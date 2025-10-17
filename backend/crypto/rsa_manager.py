from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
from backend.utils.logger_config import crypto_logger
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from hashlib import sha256
from backend.utils.logger_config import crypto_logger as clog
from cryptography.hazmat.primitives import serialization


class RSAManager:
    
    @staticmethod
    def assinar_mensagem(data: bytes, private_key):
        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

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
        
    @staticmethod
    def gerar_par_chaves():
        chave = RSA.generate(2048)
        privada = chave.export_key().decode()
        publica = chave.publickey().export_key().decode()
        
        # LOG: Chaves RSA geradas
        crypto_logger.logger.info("=== GERAÇÃO DE CHAVES RSA ===")
        crypto_logger.logger.info(f"Chave Pública Gerada:\n{publica}")
        crypto_logger.logger.info(f"Chave Privada Gerada:\n{privada}")
        crypto_logger.logger.info("=" * 50)
        
        return privada, publica
    
    @staticmethod
    def cifrar_chave_sessao(cek_bytes, chave_publica_pem):
        pub = RSA.import_key(chave_publica_pem.encode())
        cipher = PKCS1_OAEP.new(pub)
        cek_cifrado = cipher.encrypt(cek_bytes)
        cek_b64 = base64.b64encode(cek_cifrado).decode()
        
        # LOG: Criptografia RSA da chave de sessão
        crypto_logger.logger.info("=== CRIPTOGRAFIA RSA (CHAVE DE SESSÃO) ===")
        crypto_logger.logger.info(f"Chave de Sessão Original (16 bytes): {cek_bytes.hex().upper()}")
        crypto_logger.logger.info(f"Chave de Sessão Criptografada (Base64): {cek_b64}")
        crypto_logger.logger.info("=" * 50)
        
        return cek_b64

    @staticmethod
    def decifrar_chave_sessao(cek_b64, chave_privada):
        try:
            # LOG: Início da decifração RSA
            crypto_logger.logger.info("=== INÍCIO DECRIPTOGRAFIA RSA ===")
            crypto_logger.logger.info(f"Chave de Sessão Criptografada Recebida: {cek_b64}")
            
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
            
            # LOG: Decifração RSA bem-sucedida
            crypto_logger.logger.info("=== DECRIPTOGRAFIA RSA CONCLUÍDA ===")
            crypto_logger.logger.info(f"Chave de Sessão Decifrada: {cek_bytes.hex().upper()}")
            crypto_logger.logger.info("=" * 50)
                
            return cek_bytes
            
        except Exception as e:
            crypto_logger.logger.error(f"ERRO na decifração RSA: {e}")
            raise ValueError(f"Erro ao decifrar chave de sessão: {e}")
        
    @staticmethod
    def carregar_chave_publica(caminho):
        with open(caminho, "rb") as f:
            chave_pem = f.read()
        chave = serialization.load_pem_public_key(chave_pem)
        clog.info(f"[LOAD_PUBLIC_KEY] {caminho}")
        return chave
    
    def carregar_chave_privada(caminho):
        with open(caminho, "rb") as f:
            chave_pem = f.read()
        chave = serialization.load_pem_private_key(chave_pem, password=None)
        clog.info(f"[LOAD_PRIVATE_KEY] {caminho}")
        return chave
        
    @staticmethod
    def registrar_fingerprint(public_key, owner: str):
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        fingerprint = sha256(pem).hexdigest()
        clog.info(f"[KEY_FINGERPRINT] Owner={owner} | SHA256={fingerprint}")