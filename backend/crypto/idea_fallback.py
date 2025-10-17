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
    try:
        chave_hex = chave_hex.strip().upper()
        if len(chave_hex) != 32:
            raise ValueError(f"Chave deve ter 32 caracteres hex, tem {len(chave_hex)}")
        
        if not all(c in "0123456789ABCDEF" for c in chave_hex):
            raise ValueError("Chave contém caracteres hex inválidos")
        
        chave_int = int(chave_hex, 16)
        
        if chave_int.bit_length() > 128:
            raise ValueError("Chave muito longa")
            
        return chave_int
        
    except ValueError as e:
        raise ValueError(f"Chave hexadecimal inválida: {e}")

def formatar_resultado(cifrado_hex: str, iv_hex: str) -> str:
    return f"{cifrado_hex}:{iv_hex}"

def parse_resultado(resultado: str) -> tuple[str, str]:
    if ":" not in resultado:
        raise ValueError("Formato inválido. Use: cifrado_hex:iv_hex")
    a, b = resultado.split(":", 1)
    return a, b
