"""
rsa_manager.py (revisado)
-------------------------

Handles RSA key generation, encryption, and decryption for secure key exchange.
Uses OAEP padding and allows configurable key size (2048–4096 bits).
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

RSA_KEY_SIZE = 2048  # Use 4096 for very high security environments

def generate_rsa_keypair() -> tuple[bytes, bytes]:
    """Generate a new RSA key pair (public, private) in PEM format."""
    key = RSA.generate(RSA_KEY_SIZE)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

def encrypt_with_rsa(public_key: bytes, data: bytes) -> str:
    """Encrypt data with a given RSA public key (OAEP)."""
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    encrypted = cipher.encrypt(data)
    return b64encode(encrypted).decode("utf-8")

def decrypt_with_rsa(private_key: bytes, encrypted_b64: str) -> bytes:
    """Decrypt base64-encoded data using a given RSA private key (OAEP)."""
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(b64decode(encrypted_b64))
