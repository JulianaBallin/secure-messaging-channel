"""
idea_manager.py 
----------------

Gerencia a criptografia simétrica usando o algoritmo IDEA no modo CBC
com preenchimento PKCS7, aplicável ao sistema CipherTalk.

Recursos:
- Criptografia híbrida IDEA + RSA (E2EE).
- Fallback automático em Python puro caso o backend nativo não esteja disponível.
- Geração segura de chaves e IVs.
- Registro detalhado de logs (chaves, IV, tamanho e backend).
- Compatível com múltiplos usuários e execuções simultâneas.
"""

import base64
import traceback
from backend.utils.logger_config import crypto_logger

# ======================================================
# Tentativa de uso do backend nativo
# ======================================================
try:
    from Cryptodome.Cipher import IDEA
    from Cryptodome.Random import get_random_bytes
    from Cryptodome.Util.Padding import pad, unpad

    BACKEND_CRIPTO = "Cryptodome (nativo)"
    USA_NATIVO = True
    crypto_logger.info("🔒 Backend de criptografia IDEA nativo detectado (Cryptodome).")

except Exception as e:
    crypto_logger.warning(f"⚠️ IDEA nativo indisponível ({e}); ativando fallback Python puro.")
    from backend.crypto.idea_fallback import (
        generate_idea_key as fallback_generate_idea_key,
        encrypt_message as fallback_encrypt_message,
        decrypt_message as fallback_decrypt_message,
    )
    BACKEND_CRIPTO = "Fallback (Python puro)"
    USA_NATIVO = False


# ======================================================
# Constantes
# ======================================================
TAMANHO_BLOCO = 8      # IDEA opera em blocos de 64 bits
TAMANHO_CHAVE = 16     # Chave de 128 bits


# ======================================================
# Geração de chave IDEA
# ======================================================
def generate_idea_key() -> bytes:
    """
    Gera uma chave IDEA de 128 bits para criptografia simétrica.

    Returns:
        bytes: Chave aleatória de 16 bytes.
    """
    try:
        if USA_NATIVO:
            chave = get_random_bytes(TAMANHO_CHAVE)
        else:
            chave = fallback_generate_idea_key()

        crypto_logger.info(f"[IDEA][CHAVE] Chave IDEA gerada com sucesso | backend={BACKEND_CRIPTO}")
        return chave

    except Exception as e:
        crypto_logger.error(f"[IDEA][ERRO_CHAVE] Falha ao gerar chave: {e}")
        crypto_logger.debug(traceback.format_exc())
        return fallback_generate_idea_key()


# ======================================================
# Criptografia
# ======================================================
def encrypt_message(mensagem: str, chave: bytes) -> str:
    """
    Criptografa uma mensagem usando IDEA-CBC (com PKCS7).

    Args:
        mensagem (str): Texto em claro.
        chave (bytes): Chave IDEA de 128 bits.

    Returns:
        str: Texto cifrado em Base64 contendo IV + dados.
    """
    try:
        if USA_NATIVO:
            iv = get_random_bytes(TAMANHO_BLOCO)
            cifra = IDEA.new(chave, IDEA.MODE_CBC, iv)
            cifrado = cifra.encrypt(pad(mensagem.encode("utf-8"), TAMANHO_BLOCO))
            combinado = base64.b64encode(iv + cifrado).decode("utf-8")

            crypto_logger.info(
                f"[IDEA][CRIPTO] Mensagem cifrada com IV={base64.b64encode(iv)[:10].decode()}... "
                f"(tamanho={len(cifrado)}B) | backend={BACKEND_CRIPTO}"
            )
            return combinado

        else:
            cifrado = fallback_encrypt_message(mensagem, chave)
            crypto_logger.info("[IDEA][CRIPTO] Fallback Python puro utilizado com sucesso.")
            return cifrado

    except Exception as e:
        crypto_logger.error(f"[IDEA][ERRO_CRIPTO] Falha na criptografia: {e}")
        crypto_logger.debug(traceback.format_exc())
        return fallback_encrypt_message(mensagem, chave)


# ======================================================
# Descriptografia
# ======================================================
def decrypt_message(cifrado_b64: str, chave: bytes) -> str:
    """
    Descriptografa uma mensagem cifrada com IDEA-CBC (com PKCS7).

    Args:
        cifrado_b64 (str): Texto cifrado em Base64 (IV + dados).
        chave (bytes): Mesma chave usada na criptografia.

    Returns:
        str: Texto original decifrado.
    """
    try:
        if USA_NATIVO:
            dados = base64.b64decode(cifrado_b64)
            iv, cifrado = dados[:TAMANHO_BLOCO], dados[TAMANHO_BLOCO:]
            cifra = IDEA.new(chave, IDEA.MODE_CBC, iv)
            texto = unpad(cifra.decrypt(cifrado), TAMANHO_BLOCO).decode("utf-8")

            crypto_logger.info(
                f"[IDEA][DESCRIPTO] Mensagem decifrada com IV={base64.b64encode(iv)[:10].decode()}... "
                f"(tamanho={len(cifrado)}B) | backend={BACKEND_CRIPTO}"
            )
            return texto

        else:
            texto = fallback_decrypt_message(cifrado_b64, chave)
            crypto_logger.info("[IDEA][DESCRIPTO] Descriptografia via fallback executada com sucesso.")
            return texto

    except Exception as e:
        crypto_logger.error(f"[IDEA][ERRO_DESCRIPTO] Falha na descriptografia: {e}")
        crypto_logger.debug(traceback.format_exc())
        return fallback_decrypt_message(cifrado_b64, chave)


# ======================================================
# Teste de integridade da criptografia
# ======================================================
def verify_encryption_cycle() -> bool:
    """
    Executa um autoteste para verificar a integridade IDEA (E2EE local).

    Returns:
        bool: True se o processo de cifra e decifra for íntegro.
    """
    try:
        mensagem_teste = "Teste de integridade IDEA - CipherTalk"
        chave = generate_idea_key()
        cifrado = encrypt_message(mensagem_teste, chave)
        decifrado = decrypt_message(cifrado, chave)

        if decifrado == mensagem_teste:
            print("✅ Teste IDEA bem-sucedido: criptografia e descriptografia íntegras.")
            crypto_logger.info("[IDEA][AUTOTESTE] ✅ Sucesso no ciclo de criptografia.")
            return True
        else:
            print("❌ Falha no autoteste IDEA: os textos não coincidem.")
            crypto_logger.warning("[IDEA][AUTOTESTE] ❌ Falha de integridade detectada.")
            return False

    except Exception as e:
        print(f"⚠️ Erro inesperado no autoteste IDEA: {e}")
        crypto_logger.error(f"[IDEA][AUTOTESTE_ERRO] {e}")
        crypto_logger.debug(traceback.format_exc())
        return False
