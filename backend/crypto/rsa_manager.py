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
