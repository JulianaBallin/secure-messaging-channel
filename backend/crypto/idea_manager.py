"""
idea_manager.py
---------------

Handles symmetric encryption and decryption using the IDEA algorithm.  
This module is used to encrypt and decrypt chat messages within CipherTalk.

Functions:
    - encrypt_message(message, key): Encrypts a plaintext message using IDEA.
    - decrypt_message(ciphertext, key): Decrypts a ciphertext message back to plaintext.
"""

from Crypto.Cipher import IDEA
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

# IDEA exige chave de 16 bytes
SECRET_KEY = b"1234567890ABCDEF" 

def pad(data: bytes) -> bytes:
    """Preenche o bloco de dados para múltiplos de 8 bytes (necessário no IDEA)."""
    while len(data) % 8 != 0:
        data += b" "
    return data

def encrypt_message(message: str) -> str:
    """Encrypts a message using IDEA symmetric encryption."""
    cipher = IDEA.new(SECRET_KEY, IDEA.MODE_ECB)
    padded_message = pad(message.encode())
    encrypted = cipher.encrypt(padded_message)
    return b64encode(encrypted).decode()

def decrypt_message(ciphertext: str) -> str:
    """Decrypts a ciphertext message back into plaintext."""
    cipher = IDEA.new(SECRET_KEY, IDEA.MODE_ECB)
    decrypted = cipher.decrypt(b64decode(ciphertext))
    return decrypted.decode().rstrip(" ")
