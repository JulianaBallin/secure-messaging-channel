"""
client.py – versão interativa com cadastro, login e logout
"""

import asyncio
import json
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

HOST = os.getenv("SERVER_HOST", "127.0.0.1")
PORT = int(os.getenv("SERVER_PORT", 8888))


async def register_user():
    """Cria um novo usuário no servidor."""
    username = input("👤 Novo nome de usuário: ").strip()
    password = input("🔑 Crie uma senha: ").strip()

    reader, writer = await asyncio.open_connection(HOST, PORT)
    payload = {"action": "register", "username": username, "password": password}
    writer.write((json.dumps(payload) + "\n").encode())
    await writer.drain()

    response = await reader.readline()
    print(response.decode().strip())

    writer.close()
    await writer.wait_closed()


async def login_user():
    """Faz login e retorna token JWT se for bem-sucedido."""
    username = input("👤 Usuário: ").strip()
    password = input("🔑 Senha: ").strip()

    reader, writer = await asyncio.open_connection(HOST, PORT)

    payload = {"action": "login", "username": username, "password": password}
    writer.write((json.dumps(payload) + "\n").encode())
    await writer.drain()

    response = await reader.readline()
    raw = response.decode().strip()

    if raw == "AUTH_FAILED":
        print("❌ Falha na autenticação. Verifique usuário e senha.")
        writer.close()
        await writer.wait_closed()
        return None, None

    data = json.loads(raw)
    token = data.get("token")

    if not token:
        print("❌ Resposta inválida do servidor.")
        return None, None

    print("✅ Login bem-sucedido!")
    return username, token


async def send_message(writer, token):
    """Envia mensagens já autenticadas ao servidor."""
    while True:
        receiver = input("📨 Enviar para (ou 'sair' para voltar): ").strip()
        if receiver.lower() == "sair":
            break
        content = input("💬 Mensagem (já criptografada): ").strip()

        payload = {
            "token": token,
            "to": receiver,
            "content_encrypted": content,
            "timestamp": str(datetime.utcnow()),
        }
        writer.write((json.dumps(payload) + "\n").encode())
        await writer.drain()


async def receive_messages(reader):
    """Recebe mensagens do servidor."""
    while True:
        data = await reader.readline()
        if not data:
            break
        msg = json.loads(data.decode().strip())
        print(
            f"\n📩 Nova mensagem de {msg['from']}:\n🔐 Conteúdo criptografado: {msg['content_encrypted']}\n⏱️ {msg['timestamp']}"
        )


async def messaging_session(username, token):
    """Sessão principal de mensagens após login."""
    reader, writer = await asyncio.open_connection(HOST, PORT)

    # informar token e usuário na conexão
    auth_info = {"action": "auth", "username": username, "token": token}
    writer.write((json.dumps(auth_info) + "\n").encode())
    await writer.drain()

    print(f"📡 Sessão iniciada como {username}")

    await asyncio.gather(
        send_message(writer, token),
        receive_messages(reader)
    )


async def main():
    while True:
        print("\n=== 🔐 CipherTalk CLI ===")
        print("1️⃣  - Cadastrar novo usuário")
        print("2️⃣  - Fazer login")
        print("0️⃣  - Sair")

        choice = input("Escolha uma opção: ").strip()

        if choice == "1":
            await register_user()
        elif choice == "2":
            username, token = await login_user()
            if username and token:
                await messaging_session(username, token)
        elif choice == "0":
            print("👋 Encerrando cliente...")
            break
        else:
            print("❌ Opção inválida.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[CLIENT] Encerrado pelo usuário.")
