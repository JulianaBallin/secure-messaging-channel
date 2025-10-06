"""
idea_manager.py (revisado)
--------------------------

Secure symmetric encryption using IDEA in CBC mode with PKCS7 padding.
Each ciphertext includes a random IV prepended to the encrypted data.
"""

from Crypto.Cipher import IDEA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

BLOCK_SIZE = 8  # IDEA block size in bytes
KEY_SIZE = 16   # 128-bit key (16 bytes)

def generate_idea_key() -> bytes:
    """Generate a secure 128-bit IDEA key."""
    return get_random_bytes(KEY_SIZE)

def encrypt_message(message: str, key: bytes) -> str:
    """Encrypt message using IDEA-CBC with PKCS7 padding. Returns base64 string with IV."""
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = IDEA.new(key, IDEA.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message.encode("utf-8"), BLOCK_SIZE))
    return b64encode(iv + ciphertext).decode("utf-8")

def decrypt_message(encrypted_b64: str, key: bytes) -> str:
    """Decrypt IDEA-CBC encrypted base64 string (expects IV prepended)."""
    data = b64decode(encrypted_b64)
    iv, ciphertext = data[:BLOCK_SIZE], data[BLOCK_SIZE:]
    cipher = IDEA.new(key, IDEA.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
    return plaintext.decode("utf-8")
