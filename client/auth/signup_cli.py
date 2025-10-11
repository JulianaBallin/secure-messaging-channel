"""
signup_cli.py
-------------

Secure user registration for CipherTalk over TLS.

- Generates RSA key pair locally.
- Sends public key + credentials via encrypted TLS channel.
- Saves private key safely to ./keys/<username>_private.pem.
"""

import sys
import os
import re
import ssl
import json
import asyncio
from base64 import b64encode
from getpass import getpass
from dotenv import load_dotenv


# ----------------------------
# Garantir import global
# ----------------------------
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from backend.crypto.rsa_manager import generate_rsa_keypair

# -----------------------------
# ⚙️ Configuração
# -----------------------------
load_dotenv()
HOST = os.getenv("SERVER_HOST", "127.0.0.1")
PORT = int(os.getenv("SERVER_PORT", "8888"))

# Criar pastas necessárias
os.makedirs("keys", exist_ok=True)

# -----------------------------
# 🔍 Funções auxiliares
# -----------------------------
def is_valid_username(username: str) -> bool:
    """Check username validity."""
    return bool(re.fullmatch(r"^[A-Za-z0-9_]{3,20}$", username))


def is_strong_password(password: str) -> bool:
    """Validate password strength."""
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=]", password):
        return False
    return True


# -----------------------------
# 🔐 Registro seguro via TLS
# -----------------------------
async def register_user_tls():
    """Perform a secure user registration over TLS."""
    print("\n=== 📝 Cadastro de Novo Usuário (TLS) ===")
    username = input("👤 Nome de usuário: ").strip()

    if not is_valid_username(username):
        print("❌ Nome de usuário inválido. Use apenas letras, números e '_'.")
        return

    password = input("🔑 Crie uma senha: ")
    confirm = input("🔁 Confirme a senha: ")

    if password != confirm:
        print("❌ As senhas não coincidem.")
        return

    if not is_strong_password(password):
        print("❌ A senha deve ter pelo menos 8 caracteres, 1 maiúscula, 1 número e 1 caractere especial.")
        return

    # --------------------------
    # 🔑 Geração das chaves RSA
    # --------------------------
    public_key, private_key = generate_rsa_keypair()
    private_path = f"keys/{username}_private.pem"

    # Salvar chave privada localmente (modo seguro)
    with open(private_path, "wb") as f:
        f.write(private_key)
    os.chmod(private_path, 0o600)
    print(f"🔒 Chave privada salva com segurança em {private_path}")

    public_key_b64 = b64encode(public_key).decode()

    # --------------------------
    # 🌐 Conexão TLS com servidor
    # --------------------------
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE  # opcional: não verificar hostname (auto-signed)

    try:
        reader, writer = await asyncio.open_connection(
            HOST, PORT, ssl=ssl_context
        )
    except ssl.SSLError as e:
        print(f"💥 Erro SSL: {e}")
        return
    except ConnectionRefusedError:
        print("🚫 Servidor indisponível. Verifique se está em execução.")
        return

    # --------------------------
    # 📦 Enviar credenciais
    # --------------------------
    payload = {
        "action": "register",
        "username": username,
        "password": password,
        "public_key": public_key_b64,
    }

    writer.write((json.dumps(payload) + "\n").encode("utf-8"))
    await writer.drain()

    # --------------------------
    # 📬 Resposta do servidor
    # --------------------------
    response = await reader.readline()
    if not response:
        print("⚠️ Nenhuma resposta recebida do servidor.")
        writer.close()
        await writer.wait_closed()
        return

    decoded = response.decode("utf-8").strip()
    print(f"\n📨 Resposta do servidor: {decoded}")

    writer.close()
    await writer.wait_closed()


# -----------------------------
# ▶️ Execução direta
# -----------------------------
if __name__ == "__main__":
    try:
        asyncio.run(register_user_tls())
    except KeyboardInterrupt:
        print("\n👋 Cadastro cancelado pelo usuário.")
