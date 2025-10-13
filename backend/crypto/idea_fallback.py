def padding_pkcs7(data: bytes) -> bytes:
    #Aplica padding PKCS#7 aos dados (bloco de 8 bytes)
    bloco = 8
    faltam = bloco - (len(data) % bloco) if (len(data) % bloco) != 0 else bloco
    return data + bytes([faltam]) * faltam

def remove_pkcs7(data: bytes) -> bytes:
    #Remove padding PKCS#7 dos dados (bloco de 8 bytes)
    if not data:
        return data
    bloco = 8
    pad = data[-1]
    if pad < 1 or pad > bloco:
        raise ValueError("Padding PKCS7 inválido")
    if data[-pad:] != bytes([pad]) * pad:
        raise ValueError("Padding PKCS7 inconsistente")
    return data[:-pad]

def validar_chave_hex(chave_hex: str) -> int:
    #Valida se a chave hexadecimal representa 16 bytes (<=128 bits)."""
    try:
        chave_int = int(chave_hex, 16)
    except ValueError:
        raise ValueError("Chave hexadecimal inválida")
    if chave_int.bit_length() > 128:
        raise ValueError("Chave muito longa (esperado 16 bytes)")
    return chave_int

def formatar_resultado(cifrado_hex: str, iv_hex: str) -> str:
    return f"{cifrado_hex}:{iv_hex}"

def parse_resultado(resultado: str) -> tuple[str, str]:
    if ":" not in resultado:
        raise ValueError("Formato inválido. Use: cifrado_hex:iv_hex")
    a, b = resultado.split(":", 1)
    return a, b
