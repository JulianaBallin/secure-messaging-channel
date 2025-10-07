"""
idea_manager.py (revisado)
--------------------------

Secure symmetric encryption using IDEA in CBC mode with PKCS7 padding.
Each ciphertext includes a random IV prepended to the encrypted data.
"""

try:
    from Cryptodome.Cipher import IDEA  # tentativa nativa
    from Cryptodome.Random import get_random_bytes
    from Cryptodome.Util.Padding import pad, unpad
except ImportError:
    from backend.crypto.idea_fallback import (
        generate_idea_key,
        encrypt_message,
        decrypt_message,
    )
else:
    from base64 import b64encode, b64decode
    BLOCK_SIZE = 8
    KEY_SIZE = 16

    def generate_idea_key() -> bytes:
        return get_random_bytes(KEY_SIZE)

    def encrypt_message(message: str, key: bytes) -> str:
        iv = get_random_bytes(BLOCK_SIZE)
        cipher = IDEA.new(key, IDEA.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(message.encode("utf-8"), BLOCK_SIZE))
        return b64encode(iv + ciphertext).decode("utf-8")

    def decrypt_message(encrypted_b64: str, key: bytes) -> str:
        data = b64decode(encrypted_b64)
        iv, ciphertext = data[:BLOCK_SIZE], data[BLOCK_SIZE:]
        cipher = IDEA.new(key, IDEA.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
        return plaintext.decode("utf-8")
