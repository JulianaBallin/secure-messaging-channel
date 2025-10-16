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
from base64 import b64decode

from backend.crypto.idea_manager import IDEAManager
from backend.crypto.rsa_manager import RSAManager

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

    # Conexão segura
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    # ==============================
    # Obter chave pública do destinatário
    # ==============================
    try:
        reader, writer = await asyncio.open_connection(host, port, ssl=ssl_context)

        # restaura sessão para poder consultar usuários
        init_payload = {"action": "resume_session", "token": token}
        writer.write((json.dumps(init_payload) + "\n").encode("utf-8"))
        await writer.drain()

        await asyncio.sleep(0.2)  # aguarda handshake

        list_payload = {"action": "list_users", "token": token}
        writer.write((json.dumps(list_payload) + "\n").encode("utf-8"))
        await writer.drain()

        data = await reader.readline()
        if not data:
            print("❌ Nenhuma resposta do servidor (list_users).")
            writer.close()
            await writer.wait_closed()
            return

        response_text = data.decode().strip()

        # o servidor pode enviar uma mensagem informativa antes do JSON
        if not response_text.startswith("{"):
            data = await reader.readline()
            if not data:
                print("❌ Falha ao obter lista de usuários após handshake.")
                writer.close()
                await writer.wait_closed()
                return
            response_text = data.decode().strip()

        users_info = json.loads(response_text).get("users", [])
        writer.close()
        await writer.wait_closed()

    except Exception as e:
        print(f"⚠️ Erro ao obter lista de usuários: {e}")
        return

    # ==============================
    # Selecionar destinatário
    # ==============================
    receiver_data = next((u for u in users_info if u.get("username") == receiver), None)
    if not receiver_data or not receiver_data.get("public_key"):
        print("❌ Chave pública do destinatário não encontrada.")
        return

    # No banco/servidor a pública está Base64; convertemos para PEM (texto)
    receiver_pub_key_pem = b64decode(receiver_data["public_key"]).decode("utf-8")

    # ==============================
    # Criptografar com sua IDEAManager
    #   - packet: "CIFRADO_HEX:IV_HEX"
    #   - cek_b64: chave de sessão (16 bytes) cifrada com RSA do destinatário, em Base64
    # ==============================
    idea_mgr = IDEAManager()
    packet, cek_b64 = idea_mgr.cifrar_para_chat(
        texto_plano=message,
        chave_publica_pem=receiver_pub_key_pem,
        remetente=username,
        destinatario=receiver,
    )

    # Montar payload final
    msg_payload = {
        "action": "send_message",
        "token": token,
        "to": receiver,
        "content_encrypted": packet,   # "CIFRADO_HEX:IV_HEX"
        "key_encrypted": cek_b64,      # CEK (16 bytes) cifrada via RSA (Base64)
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "from": username,
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
    Espera arquivos JSON no diretório 'messages/' com os campos:
      - content_encrypted: "CIFRADO_HEX:IV_HEX"
      - key_encrypted: CEK criptografada em Base64 (RSA)
      - timestamp, from
    """
    private_key_path = f"keys/{username}_private.pem"
    if not os.path.exists(private_key_path):
        print("❌ Chave privada não encontrada.")
        return

    # sua RSAManager usa PEM em texto
    with open(private_key_path, "r", encoding="utf-8") as f:
        private_key_pem = f.read()

    messages_dir = "messages"
    user_messages = [
        f for f in os.listdir(messages_dir)
        if f.startswith(f"{username}_") and f.endswith(".json")
    ]

    if not user_messages:
        print("📭 Nenhuma mensagem recebida.")
        return

    print(f"\n=== 📩 Mensagens recebidas para {username} ===")
    for file in sorted(user_messages):
        try:
            with open(os.path.join(messages_dir, file), "r", encoding="utf-8") as f:
                data = json.load(f)

            packet = data.get("content_encrypted")   # "CIFRADO_HEX:IV_HEX"
            cek_b64 = data.get("key_encrypted")      # CEK cifrada (Base64)
            sender = data.get("from", "Desconhecido")

            if not packet or not cek_b64:
                print(f"⚠️ Arquivo inválido: {file}")
                continue

            # Decifra com a sua IDEAManager
            idea_mgr = IDEAManager()
            plaintext = idea_mgr.decifrar_do_chat(
                packet=packet,
                cek_b64=cek_b64,
                chave_privada_pem=private_key_pem,
                destinatario=username,
                remetente=sender,
            )

            print(f"\n🗓️ {data.get('timestamp','—')}")
            print(f"👤 De: {sender}")
            print(f"💬 {plaintext}")
            print("─" * 40)

        except Exception as e:
            print(f"⚠️ Erro ao ler {file}: {e}")
