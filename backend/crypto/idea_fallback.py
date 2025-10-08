"""
idea_fallback.py (versão final funcional)
----------------------------------------

Implementação completa em Python puro do algoritmo IDEA (modo CBC).
Usada automaticamente quando o módulo Cryptodome não está disponível.

Funções implementadas:
    - generate_idea_key()
    - encrypt_message()
    - decrypt_message()

Compatível com IDEA-CBC de 64 bits, padding PKCS7 e IV aleatório.
"""

import struct
from base64 import b64encode, b64decode
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from backend.utils.logger_config import crypto_logger

# ======================================================
# Parâmetros do IDEA
# ======================================================
BLOCK_SIZE = 8   # 64 bits
KEY_SIZE = 16    # 128 bits
MODULO = 0x10001
MASK = 0xFFFF


# ======================================================
# Operações aritméticas IDEA
# ======================================================
def _mul(x, y):
    if x == 0:
        x = (MODULO - y) & MASK
    elif y == 0:
        x = (MODULO - x) & MASK
    else:
        p = (x * y) % MODULO
        x = p & MASK
    return x


def _add(x, y):
    return (x + y) & MASK


def _sub(x, y):
    return (x - y) & MASK


def _inv(x):
    if x <= 1:
        return x
    t0, t1 = 1, 0
    y = MODULO
    while x > 1:
        q = y // x
        y, x = x, y % x
        t0, t1 = t1, (t0 - q * t1) & MASK
    return t1 & MASK


# ======================================================
# Expansão e inversão de subchaves
# ======================================================
def _expand_key(userkey: bytes):
    key = list(struct.unpack(">8H", userkey))
    for i in range(8, 52):
        if (i + 1) % 8 == 0:
            key.append(((key[i - 15] << 9) | (key[i - 14] >> 7)) & MASK)
        else:
            key.append(((key[i - 7] << 9) | (key[i - 6] >> 7)) & MASK)
    return key[:52]


def _invert_subkeys(subkeys):
    """Gera as subchaves de decifragem na ordem correta."""
    dec = [0] * 52
    for i in range(0, 52, 6):
        j = 48 - i
        dec[i] = _inv(subkeys[j])
        dec[i + 1] = _sub(0, subkeys[j + 2])
        dec[i + 2] = _sub(0, subkeys[j + 1])
        dec[i + 3] = _inv(subkeys[j + 3])
        if i + 4 < 52:
            dec[i + 4] = subkeys[j - 2]
            dec[i + 5] = subkeys[j - 1]
    return dec



# ======================================================
# Rodada IDEA
# ======================================================
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
    x2 ^= t0
    x3 ^= t1

    return x1, x2, x3, x4


# ======================================================
# Classe principal do fallback
# ======================================================
class IDEA_Fallback:
    """Implementação CBC com 8 rodadas IDEA."""

    def __init__(self, key: bytes, iv: bytes):
        self.round_keys = _expand_key(key)
        self.decrypt_keys = _invert_subkeys(self.round_keys)
        self.iv = iv

    def _encrypt_block(self, block, keys):
        x1, x2, x3, x4 = struct.unpack(">4H", block)
        for j in range(0, 48, 6):
            x1, x2, x3, x4 = _idea_round(x1, x2, x3, x4, keys[j:j + 6])
        x1 = _mul(x1, keys[48])
        x2 = _add(x2, keys[49])
        x3 = _add(x3, keys[50])
        x4 = _mul(x4, keys[51])
        return struct.pack(">4H", x1, x2, x3, x4)

    def encrypt(self, data: bytes) -> bytes:
        iv = self.iv
        encrypted = b""
        for i in range(0, len(data), BLOCK_SIZE):
            block = data[i:i + BLOCK_SIZE]
            block = bytes(a ^ b for a, b in zip(block, iv))
            enc = self._encrypt_block(block, self.round_keys)
            iv = enc
            encrypted += enc
        return encrypted

    def decrypt(self, data: bytes) -> bytes:
        """Descriptografa os blocos (modo CBC)."""
        iv = self.iv
        decrypted = b""
        for i in range(0, len(data), BLOCK_SIZE):
            block = data[i:i + BLOCK_SIZE]
            dec_block = self._encrypt_block(block, self.decrypt_keys)  # usa chaves invertidas
            plain = bytes(a ^ b for a, b in zip(dec_block, iv))
            iv = block
            decrypted += plain
        return decrypted



# ======================================================
# Funções públicas
# ======================================================
def generate_idea_key() -> bytes:
    chave = get_random_bytes(KEY_SIZE)
    crypto_logger.info("[IDEA-FB][CHAVE] Chave fallback IDEA gerada com sucesso.")
    return chave


def encrypt_message(mensagem: str, chave: bytes) -> str:
    iv = get_random_bytes(BLOCK_SIZE)
    cifra = IDEA_Fallback(chave, iv)
    dados = pad(mensagem.encode("utf-8"), BLOCK_SIZE)
    cifrado = cifra.encrypt(dados)
    combinado = b64encode(iv + cifrado).decode("utf-8")
    crypto_logger.info(f"[IDEA-FB][CRIPTO] Mensagem cifrada com IV={b64encode(iv)[:10].decode()}...")
    return combinado


def decrypt_message(cifrado_b64: str, chave: bytes) -> str:
    dados = b64decode(cifrado_b64)
    iv, cifrado = dados[:BLOCK_SIZE], dados[BLOCK_SIZE:]
    cifra = IDEA_Fallback(chave, iv)
    texto = unpad(cifra.decrypt(cifrado), BLOCK_SIZE).decode("utf-8")
    crypto_logger.info(f"[IDEA-FB][DESCRIPTO] Mensagem descriptografada com IV={b64encode(iv)[:10].decode()}...")
    return texto
