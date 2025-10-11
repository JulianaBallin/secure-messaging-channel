"""
cli.py (mensagens)
------------------

Gerencia o envio e leitura de mensagens com criptografia ponta-a-ponta para CipherTalk.

Funcionalidades:
- IDEA (modo CBC) para criptografia simétrica
- RSA (OAEP) para troca assimétrica de chaves
- Canal seguro TLS para transporte na rede
- Armazenamento local de mensagens recebidas (em JSON)
"""

import asyncio
import json
import os
import ssl
import datetime
from base64 import b64encode, b64decode
from backend.utils.logger_config import messages_logger


from backend.crypto.idea_manager import generate_idea_key, encrypt_message, decrypt_message
from backend.crypto.rsa_manager import encrypt_with_rsa, decrypt_with_rsa


# Diretórios obrigatórios
os.makedirs("messages", exist_ok=True)
os.makedirs("keys", exist_ok=True)


# ======================================================
# ENVIO DE MENSAGEM (E2EE)
# ======================================================
async def send_encrypted_message(username: str, token: str, host: str, port: int):
    """Envia uma mensagem segura para outro usuário (E2EE)."""
    receiver = input("📨 Destinatário: ").strip()
    message = input("💬 Mensagem: ").strip()
    if not receiver or not message:
        print("❌ Campos obrigatórios ausentes.")
        return

    # Gerar chave simétrica IDEA
    idea_key = generate_idea_key()

    # Criptografar mensagem
    encrypted_message = encrypt_message(message, idea_key)

    # Conexão segura
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    # ==============================
    # Obter chave pública do destinatário
    # ==============================
    try:
        reader, writer = await asyncio.open_connection(host, port, ssl=ssl_context)
        init_payload = {"action": "resume_session", "token": token}
        writer.write((json.dumps(init_payload) + "\n").encode("utf-8"))
        await writer.drain()

        await asyncio.sleep(0.2)  # aguarda autenticação da sessão

        list_payload = {"action": "list_users", "token": token}
        writer.write((json.dumps(list_payload) + "\n").encode("utf-8"))
        await writer.drain()

        data = await reader.readline()
        if not data:
            print("❌ Nenhuma resposta do servidor (list_users).")
            return

        response_text = data.decode().strip()

        # Ignorar respostas não-JSON (como "✅ Sessão restaurada...")
        if not response_text.startswith("{"):
            print(f"ℹ️ Resposta informativa do servidor: {response_text}")
            data = await reader.readline()
            if not data:
                print("❌ Falha ao obter lista de usuários após handshake.")
                return
            response_text = data.decode().strip()

        users_info = json.loads(response_text).get("users", [])
        await asyncio.sleep(0.3)  # 🕓 evita fechamento precoce
        writer.close()
        await writer.wait_closed()

    except Exception as e:
        print(f"⚠️ Erro ao obter lista de usuários: {e}")
        return

    # ==============================
    # Selecionar destinatário
    # ==============================
    receiver_data = next((u for u in users_info if u["username"] == receiver), None)
    if not receiver_data or not receiver_data.get("public_key"):
        print("❌ Chave pública do destinatário não encontrada.")
        return

    receiver_pub_key = b64decode(receiver_data["public_key"])

    # Criptografar chave IDEA com RSA do destinatário
    encrypted_key = encrypt_with_rsa(receiver_pub_key, idea_key)

    # Montar payload final
    msg_payload = {
        "action": "send_message",
        "token": token,
        "to": receiver,
        "content_encrypted": encrypted_message,
        "key_encrypted": encrypted_key,
        "timestamp": datetime.datetime.utcnow().isoformat(),
    }

    # ==============================
    # Enviar mensagem criptografada
    # ==============================
    try:
        reader, writer = await asyncio.open_connection(host, port, ssl=ssl_context)

        # 🔑 Reautenticar sessão antes de enviar
        init_payload = {"action": "resume_session", "token": token}
        writer.write((json.dumps(init_payload) + "\n").encode("utf-8"))
        await writer.drain()
        await asyncio.sleep(0.3)

        writer.write((json.dumps(msg_payload) + "\n").encode("utf-8"))
        await writer.drain()

        print(f"✅ Mensagem enviada com sucesso para {receiver} (E2EE ativa).")

        writer.close()
        await writer.wait_closed()

    except Exception as e:
        print(f"⚠️ Falha ao enviar mensagem: {e}")


# ======================================================
# LEITURA / DESCRIPTOGRAFIA DE MENSAGENS
# ======================================================
def read_and_decrypt_messages(username: str):
    """
    Lê e descriptografa mensagens armazenadas localmente.
    Espera arquivos JSON no diretório 'messages/'.
    """
    private_key_path = f"keys/{username}_private.pem"
    if not os.path.exists(private_key_path):
        print("❌ Chave privada não encontrada.")
        return

    with open(private_key_path, "rb") as f:
        private_key = f.read()

    messages_dir = "messages"
    user_messages = [
        f for f in os.listdir(messages_dir)
        if f.startswith(f"{username}_") and f.endswith(".json")
    ]

    if not user_messages:
        print("📭 Nenhuma mensagem recebida.")
        return

    print(f"\n=== 📩 Mensagens recebidas para {username} ===")
    for file in user_messages:
        try:
            with open(os.path.join(messages_dir, file), "r", encoding="utf-8") as f:
                data = json.load(f)

            encrypted_content = data.get("content_encrypted")
            encrypted_key = data.get("key_encrypted")

            # Descriptografar chave IDEA
            idea_key = decrypt_with_rsa(private_key, encrypted_key)

            # Descriptografar mensagem
            plaintext = decrypt_message(encrypted_content, idea_key)

            print(f"\n🗓️ {data['timestamp']}")
            print(f"👤 De: {data['from']}")
            print(f"💬 {plaintext}")
            print("─" * 40)
        except Exception as e:
            print(f"⚠️ Erro ao ler {file}: {e}")

def safe_json_loads(data: bytes):
    try:
        text = data.decode('utf-8')
        return json.loads(text)
    except Exception as e:
        messages_logger.warning('Failed to parse JSON response: %s', e)
        return None
