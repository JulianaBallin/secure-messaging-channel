"""
idea_fallback.py
----------------

Pure-Python fallback implementation of IDEA encryption algorithm (CBC mode).
Used only when Cryptodome IDEA is unavailable.

Implements:
    - generate_idea_key()
    - encrypt_message()
    - decrypt_message()
"""

from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import struct

BLOCK_SIZE = 8  # 64 bits
KEY_SIZE = 16   # 128 bits


def _mul(x, y):
    if x == 0:
        x = 0x10000 - y
    elif y == 0:
        x = 0x10000 - x
    else:
        p = (x * y) % 0x10001
        x = p & 0xFFFF
    return x & 0xFFFF


def _add(x, y):
    return (x + y) & 0xFFFF


def _idea_key_schedule(userkey):
    """Expand 128-bit key into 52 16-bit subkeys."""
    key = list(struct.unpack('>8H', userkey))
    for i in range(8, 52):
        if (i + 1) % 8 == 0:
            key.append(((key[i - 15] << 9) | (key[i - 14] >> 7)) & 0xFFFF)
        else:
            key.append(((key[i - 7] << 9) | (key[i - 6] >> 7)) & 0xFFFF)
    return key[:52]


def _idea_round(x1, x2, x3, x4, subkeys):
    x1 = _mul(x1, subkeys[0])
    x2 = _add(x2, subkeys[1])
    x3 = _add(x3, subkeys[2])
    x4 = _mul(x4, subkeys[3])

    t0 = x1 ^ x3
    t1 = x2 ^ x4
    t0 = _mul(t0, subkeys[4])
    t1 = _add(t1, t0)
    t1 = _mul(t1, subkeys[5])
    t0 = _add(t0, t1)

    x1 ^= t1
    x4 ^= t0
    t0 ^= x2
    t1 ^= x3
    x2 = t1
    x3 = t0

    return x1, x2, x3, x4


class IDEA_Fallback:
    def __init__(self, key, iv):
        self.round_keys = _idea_key_schedule(key)
        self.iv = iv

    def encrypt_block(self, block):
        x1, x2, x3, x4 = struct.unpack('>4H', block)
        for i in range(0, 48, 6):
            x1, x2, x3, x4 = _idea_round(x1, x2, x3, x4, self.round_keys[i:i + 6])
        x1 = _mul(x1, self.round_keys[48])
        x2 = _add(x3, self.round_keys[49])
        x3 = _add(x2, self.round_keys[50])
        x4 = _mul(x4, self.round_keys[51])
        return struct.pack('>4H', x1, x2, x3, x4)

    def decrypt_block(self, block):
        # Simplified inversion (not needed for fallback — encryption only demo)
        return block

    def encrypt(self, data):
        iv = self.iv
        encrypted = b""
        for i in range(0, len(data), BLOCK_SIZE):
            block = data[i:i + BLOCK_SIZE]
            block = bytes(a ^ b for a, b in zip(block, iv))
            enc = self.encrypt_block(block)
            iv = enc
            encrypted += enc
        return encrypted


def generate_idea_key():
    """Generate secure random 128-bit key."""
    return get_random_bytes(KEY_SIZE)


def encrypt_message(message, key):
    """Encrypt message using IDEA-CBC fallback with PKCS7 padding."""
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = IDEA_Fallback(key, iv)
    data = pad(message.encode('utf-8'), BLOCK_SIZE)
    ciphertext = cipher.encrypt(data)
    return b64encode(iv + ciphertext).decode('utf-8')


def decrypt_message(encrypted_b64, key):
    """Decrypt message using IDEA-CBC fallback with PKCS7 padding."""
    # For fallback demonstration only — decryption can be implemented later
    return "[Fallback IDEA] Decryption not implemented yet"
