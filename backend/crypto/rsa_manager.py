<<<<<<< Updated upstream
"""
rsa_manager.py
---------------

Gerencia criptografia assimétrica RSA:
- Geração de par de chaves (privada/local + pública/servidor)
- Criptografia/Descriptografia seguras com OAEP (SHA-256)
"""

from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA256
from backend.utils.logger_config import crypto_logger as log


# ======================================================
# GERAÇÃO DE PAR DE CHAVES
# ======================================================
def generate_rsa_keypair(bits: int = 2048):
    """
    Gera um par de chaves RSA no formato PEM.

    Returns:
        (bytes, bytes): (public_key_pem, private_key_pem)
    """
    key = RSA.generate(bits)
    private_pem = key.export_key(format="PEM")
    public_pem = key.publickey().export_key(format="PEM")

    log.info(f"[RSA][KEYGEN] Par de chaves RSA {bits}-bit gerado com sucesso.")
    return public_pem, private_pem


# ======================================================
# CRIPTOGRAFAR COM CHAVE PÚBLICA
# ======================================================
def encrypt_with_rsa(data: bytes, public_key_pem: bytes) -> bytes:
    """
    Criptografa dados usando RSA OAEP com SHA-256.
    """
    try:
        rsa_key = RSA.import_key(public_key_pem)
        cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
        encrypted = cipher.encrypt(data)
        log.info("[RSA][ENCRYPT] Dados criptografados com sucesso (OAEP).")
        return encrypted
    except Exception as e:
        log.error(f"[RSA][ENCRYPT_FAIL] {e}")
        raise


# ======================================================
# DESCRIPTOGRAFAR COM CHAVE PRIVADA
# ======================================================
def decrypt_with_rsa(cipher_data: bytes, private_key_pem: bytes) -> bytes:
    """
    Descriptografa dados usando RSA OAEP com SHA-256.
    """
    try:
        rsa_key = RSA.import_key(private_key_pem)
        cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
        decrypted = cipher.decrypt(cipher_data)
        log.info("[RSA][DECRYPT] Dados descriptografados com sucesso (OAEP).")
        return decrypted
    except Exception as e:
        log.error(f"[RSA][DECRYPT_FAIL] {e}")
        raise
=======
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

class RSAManager:
    
    @staticmethod
    def gerar_par_chaves():
        #Gera par de chaves RSA
        chave = RSA.generate(2048)
        privada = chave.export_key().decode()
        publica = chave.publickey().export_key().decode()
        return privada, publica
    
    @staticmethod
    def cifrar_chave_sessao(cek_bytes, chave_publica_pem):
        #Cifra CEK/Chave de Sessao com RSA
        pub = RSA.import_key(chave_publica_pem.encode())
        cipher = PKCS1_OAEP.new(pub)
        cek_cifrado = cipher.encrypt(cek_bytes)
        return base64.b64encode(cek_cifrado).decode()
    
    @staticmethod
    def decifrar_chave_sessao(cek_b64, chave_privada_pem):
        #Decifra CEK com RSA e verifica se tem 16 bytes/128 bits
        try:
            priv = RSA.import_key(chave_privada_pem.encode())
            cipher = PKCS1_OAEP.new(priv)
            cek_bytes = cipher.decrypt(base64.b64decode(cek_b64))
            
            if len(cek_bytes) != 16:
                raise ValueError(f"Chave de sessão deve ter 16 bytes, tem {len(cek_bytes)}")
                
            return cek_bytes
            
        except Exception as e:
            raise ValueError(f"Erro ao decifrar chave de sessão: {e}")
    
    @staticmethod
    def carregar_chave_publica(caminho):
        with open(caminho, 'r') as f:
            return f.read()
    
    @staticmethod
    def carregar_chave_privada(caminho):
        with open(caminho, 'r') as f:
            return f.read()
>>>>>>> Stashed changes
