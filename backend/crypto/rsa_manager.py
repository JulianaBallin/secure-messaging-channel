from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from hashlib import sha256
from cryptography.hazmat.primitives import serialization
from backend.utils.logger_config import autenticidade_logger


class RSAManager:
    
    @staticmethod
    def assinar_mensagem(data: bytes, private_key):
        assinatura = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        autenticidade_logger.info(
            f"[ASSINATURA_OK] Mensagem assinada.\n"
            f" • Hash da mensagem: {sha256(data).hexdigest().upper()}\n"
            f" • Assinatura (base64): {base64.b64encode(assinatura).decode()}\n"
            f" • PrivateKey_ID: {id(private_key)}"
        )

        return assinatura

    @staticmethod
    def verificar_assinatura(data: bytes, assinatura: bytes, public_key):
        public_key.verify(
            assinatura,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        autenticidade_logger.info(
            f"[ASSINATURA_VERIFICADA] Assinatura válida.\n"
            f" • Hash da mensagem: {sha256(data).hexdigest().upper()}\n"
            f" • Assinatura (base64): {base64.b64encode(assinatura).decode()}\n"
            f" • PublicKey fingerprint: {sha256(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest().upper()}"
        )
        
    @staticmethod
    def gerar_par_chaves():
        chave = RSA.generate(2048)
        privada = chave.export_key().decode()
        publica = chave.publickey().export_key().decode()
        # Fingerprint SHA-256 da chave pública
        fingerprint = sha256(publica.encode()).hexdigest().upper()

        autenticidade_logger.info(
            f"[RSA_OK] Par de chaves RSA gerado.\n"
            f" • Fingerprint: {fingerprint}\n"
            f" • PublicKey PEM: {publica}\n"
            f" • PrivateKey PEM: {privada}\n"
            f" • PrivateKey_ID: {id(privada)}"
        )

        return privada, publica
    
    @staticmethod
    def cifrar_chave_sessao(cek_bytes, chave_publica_pem):
        cek_hex = cek_bytes.hex().upper()

        # Carregar chave
        pub = RSA.import_key(chave_publica_pem.encode())
        cipher = PKCS1_OAEP.new(pub)

        # Cifrar
        cek_cifrado = cipher.encrypt(cek_bytes)
        cek_b64 = base64.b64encode(cek_cifrado).decode()

        autenticidade_logger.info(
            f"[CEK_CIFRADA] Chave de sessão cifrada.\n"
            f" • CEK (hex original): {cek_hex}\n"
            f" • CEK cifrada (base64): {cek_b64}\n"
            f" • PublicKey fingerprint destino: {sha256(chave_publica_pem.encode()).hexdigest().upper()}"
        )

        return cek_b64

    @staticmethod
    def decifrar_chave_sessao(cek_b64, chave_privada):
        try:          
            # Aceita tanto objeto de chave quanto string PEM
            if hasattr(chave_privada, 'private_bytes'):
                # Se for objeto cryptography, converte para string PEM
                chave_privada_pem = chave_privada.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode()
                priv = RSA.import_key(chave_privada_pem)
            else:
                # Se já for string PEM
                priv = RSA.import_key(chave_privada.encode())
                
            cipher = PKCS1_OAEP.new(priv)
            cek_cifrado_bytes = base64.b64decode(cek_b64)
            cek_bytes = cipher.decrypt(cek_cifrado_bytes)
            
            if len(cek_bytes) != 16:
                raise ValueError(f"Chave de sessão deve ter 16 bytes, tem {len(cek_bytes)}")
            
            cek_hex = cek_bytes.hex().upper()
                
            return cek_bytes
            
        except Exception as e:
            raise ValueError(f"Erro ao decifrar chave de sessão: {e}")
        
    @staticmethod
    def carregar_chave_publica(caminho):
        with open(caminho, "rb") as f:
            chave_pem = f.read()
        chave = serialization.load_pem_public_key(chave_pem)
        return chave
    
    @staticmethod
    def carregar_chave_privada(caminho):
        with open(caminho, "rb") as f:
            chave_pem = f.read()
        chave = serialization.load_pem_private_key(chave_pem, password=None)
        return chave
        
    @staticmethod
    def registrar_fingerprint(public_key, owner: str):
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        fingerprint = sha256(pem).hexdigest()