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

def generate_idea_key() -> bytes:
    """Generate a secure 16-byte IDEA key."""
    return get_random_bytes(16)

def pad(data: bytes) -> bytes:
    while len(data) % 8 != 0:
        data += b" "
    return data

def encrypt_message(message: str, key: bytes) -> str:
    cipher = IDEA.new(key, IDEA.MODE_ECB)
    return b64encode(cipher.encrypt(pad(message.encode()))).decode()

def decrypt_message(encrypted: str, key: bytes) -> str:
    cipher = IDEA.new(key, IDEA.MODE_ECB)
    return cipher.decrypt(b64decode(encrypted)).decode().rstrip(" ")
