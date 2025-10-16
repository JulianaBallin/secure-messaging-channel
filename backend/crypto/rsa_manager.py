from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
from backend.utils.crypto_logger import crypto_logger


class RSAManager:
    
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
    def decifrar_chave_sessao(cek_b64, chave_privada_pem):
        try:
            # LOG: Início da decifração RSA
            crypto_logger.logger.info("=== INÍCIO DECRIPTOGRAFIA RSA ===")
            crypto_logger.logger.info(f"Chave de Sessão Criptografada Recebida: {cek_b64}")
            
            priv = RSA.import_key(chave_privada_pem.encode())
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
        with open(caminho, 'r') as f:
            chave = f.read()
            crypto_logger.logger.info(f"Chave pública carregada de: {caminho}")
            return chave
    
    @staticmethod
    def carregar_chave_privada(caminho):
        with open(caminho, 'r') as f:
            chave = f.read()
            crypto_logger.logger.info(f"Chave privada carregada de: {caminho}")
            return chave