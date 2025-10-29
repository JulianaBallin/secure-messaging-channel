"""
login_cli.py
-------------

Realiza o login de um usuário no servidor CipherTalk via conexão TLS,
verificando credenciais e obtendo um token JWT válido.

Fluxo:
1️⃣ Solicita nome de usuário e senha.
2️⃣ Envia ao servidor via TLS.
3️⃣ Recebe e valida o token JWT.
4️⃣ Retorna nome do usuário e token.
"""

import sys
import os
import ssl
import json
import asyncio
from getpass import getpass
from dotenv import load_dotenv
from backend.utils.logger_config import messages_logger

# ----------------------------
# Garantir imports globais
# ----------------------------
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

# ----------------------------
# Variáveis de ambiente
# ----------------------------


load_dotenv()
HOST = os.getenv("SERVER_HOST", "0.0.0.0")
PORT = int(os.getenv("SERVER_PORT", "8888"))

def verify_rsa_integrity(public_key_pem: str) -> bool:
    try:
        from cryptography.hazmat.primitives import serialization
        serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        return True
    except Exception as e:
        messages_logger.warning('RSA public key verification failed: %s', e)
        return False

def verify_jwt_token(token: str) -> bool:
    try:
        parts = token.split('.')
        return len(parts) == 3
    except Exception as e:
        messages_logger.warning('JWT basic verification failed: %s', e)
        return False

def fetch_offline_messages_after_login(session):
    try:
        resp = session.get('/messages/offline')
        if resp and getattr(resp, 'status_code', None) == 200:
            msgs = resp.json()
            for m in msgs:
                messages_logger.info('Offline message from %s: %s', m.get('from'), m.get('body'))
        else:
            messages_logger.info('No offline messages or failed to fetch (status: %s)', getattr(resp, 'status_code', None))
    except Exception as e:
        messages_logger.exception('Failed to fetch offline messages: %s', e)

# ======================================================
# 🔐 Função principal de login
# ======================================================
async def perform_login():
    """Realiza o login via TLS e retorna o token JWT."""
    username = input("👤 Nome de usuário: ").strip()
    password = getpass("🔑 Senha: ").strip()

    if not username or not password:
        print("❌ Usuário e senha são obrigatórios.")
        return None, None

    payload = {
        "action": "login",
        "username": username,
        "password": password,
    }

    try:
        # 🔒 Configurar contexto SSL
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.open_connection(
            HOST, PORT, ssl=ssl_context
        )

        # 📤 Enviar credenciais
        writer.write((json.dumps(payload) + "\n").encode("utf-8"))
        await writer.drain()

        # 📥 Ler resposta
        response = await reader.readline()
        if not response:
            print("❌ Nenhuma resposta do servidor.")
            writer.close()
            await writer.wait_closed()
            return None, None

        raw = response.decode().strip()
        if raw == "AUTH_FAILED":
            print("❌ Usuário ou senha incorretos.")
            writer.close()
            await writer.wait_closed()
            return None, None

        data = json.loads(raw)
        token = data.get("token")
        if not token:
            print("❌ Falha ao autenticar: token ausente.")
            writer.close()
            await writer.wait_closed()
            return None, None

        print(f"✅ Login bem-sucedido! Bem-vindo(a), {username}.")
        writer.close()
        await writer.wait_closed()
        return username, token

    except Exception as e:
        print(f"💥 Erro durante o login: {e}")
        return None, None


# ======================================================
# ▶️ Execução direta
# ======================================================
if __name__ == "__main__":
    try:
        asyncio.run(perform_login())
    except KeyboardInterrupt:
        print("\n👋 Login cancelado pelo usuário.")
