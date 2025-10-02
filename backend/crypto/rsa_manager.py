"""
rsa_manager.py
--------------

Handles RSA key generation, encryption, and decryption for secure key exchange.
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode

def generate_rsa_keypair() -> tuple[bytes, bytes]:
    """Generate a new RSA public/private key pair."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

def encrypt_with_rsa(public_key: bytes, data: bytes) -> str:
    """Encrypts data with the given RSA public key."""
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    encrypted = cipher.encrypt(data)
    return b64encode(encrypted).decode()

def decrypt_with_rsa(private_key: bytes, encrypted_data: str) -> bytes:
    """Decrypts data with the given RSA private key."""
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(b64decode(encrypted_data))
