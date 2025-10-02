"""
server.py
----------

AsyncIO-based secure messaging server for CipherTalk.
- Accepts multiple client connections.
- Handles user registration and login with password hash.
- Issues JWT tokens with expiration (default: 30 min).
- Routes encrypted messages between online users.
- Stores undelivered messages for offline users.
- Does NOT decrypt messages (security boundary).
"""

import asyncio
import json
import os
from typing import Dict

from sqlalchemy.orm import Session
from dotenv import load_dotenv

from backend.database.connection import SessionLocal
from backend.auth.models import User, Message
from backend.auth.security import hash_password, verify_password
from backend.auth.auth_jwt import create_access_token, verify_access_token

load_dotenv()

# ✅ Configurações carregadas do .env
HOST = os.getenv("SERVER_HOST")
PORT = os.getenv("SERVER_PORT")

if HOST is None or PORT is None:
    raise EnvironmentError("❌ SERVER_HOST e SERVER_PORT devem estar definidos no .env")

PORT = int(PORT)

# Dicionário global de conexões de usuários online
ONLINE_USERS: Dict[str, asyncio.StreamWriter] = {}


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Handle client connection: register, login, route messages."""
    db: Session = SessionLocal()
    username = None
    addr = writer.get_extra_info("peername")
    print(f"[INFO] Conexão recebida de {addr}")

    try:
        # 📥 Recebe dados iniciais (registro ou login)
        data = await reader.readline()
        creds = json.loads(data.decode().strip())
        action = creds.get("action")

        # 🧑‍💻 Registro de novo usuário
        if action == "register":
            username = creds.get("username")
            password = creds.get("password")

            if db.query(User).filter(User.username == username).first():
                writer.write("❌ Usuário já existe.\n".encode("utf-8"))

            else:
                new_user = User(username=username, password_hash=hash_password(password))
                db.add(new_user)
                db.commit()
                writer.write("✅ Usuário criado com sucesso!\n".encode("utf-8"))


            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        # 🔐 Login de usuário existente
        if action == "login":
            username = creds.get("username")
            password = creds.get("password")

            user = db.query(User).filter(User.username == username).first()
            if not user or not verify_password(password, user.password_hash):
                writer.write(b"AUTH_FAILED\n")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                print(f"[DENIED] Conexão recusada para {username}")
                return

            # ✅ Gera token JWT
            token = create_access_token(username)
            writer.write((json.dumps({"token": token}) + "\n").encode())
            await writer.drain()

            ONLINE_USERS[username] = writer
            print(f"[LOGIN] {username} autenticado com sucesso.")

            # 📤 Entregar mensagens offline, se houver
            offline_messages = (
                db.query(Message)
                .join(User, User.id == Message.receiver_id)
                .filter(User.username == username)
                .all()
            )
            if offline_messages:
                for msg in offline_messages:
                    payload = {
                        "from": db.query(User).get(msg.sender_id).username,
                        "content_encrypted": msg.content_encrypted,
                        "timestamp": str(msg.timestamp),
                    }
                    writer.write((json.dumps(payload) + "\n").encode())
                    await writer.drain()

                print(f"[INFO] {len(offline_messages)} mensagens offline entregues a {username}.")
                for m in offline_messages:
                    db.delete(m)
                db.commit()

        # 📡 Loop principal para roteamento de mensagens
        while True:
            data = await reader.readline()
            if not data:
                break

            try:
                message = json.loads(data.decode().strip())
                token = message.get("token")

                # ✅ Verifica token JWT
                sender = verify_access_token(token)
                receiver = message["to"]
                encrypted_content = message["content_encrypted"]

                print(f"[MSG] {sender} → {receiver}")

                receiver_user = db.query(User).filter(User.username == receiver).first()
                sender_user = db.query(User).filter(User.username == sender).first()

                if not receiver_user:
                    print(f"[ERROR] Usuário destino '{receiver}' não encontrado.")
                    continue

                if receiver in ONLINE_USERS:
                    # ✅ Usuário online → entrega imediata
                    dest_writer = ONLINE_USERS[receiver]
                    payload = {
                        "from": sender,
                        "content_encrypted": encrypted_content,
                        "timestamp": str(message.get("timestamp", "")),
                    }
                    dest_writer.write((json.dumps(payload) + "\n").encode())
                    await dest_writer.drain()
                    print(f"[DELIVERED] Mensagem entregue a {receiver}")
                else:
                    # 📥 Usuário offline → salva no banco
                    msg_obj = Message(
                        sender_id=sender_user.id,
                        receiver_id=receiver_user.id,
                        content_encrypted=encrypted_content,
                    )
                    db.add(msg_obj)
                    db.commit()
                    print(f"[STORED] {receiver} offline. Mensagem salva.")

            except ValueError as e:
                print(f"[AUTH ERROR] {e}")
                writer.write(b"INVALID_TOKEN\n")
                await writer.drain()
            except Exception as e:
                print(f"[ERROR] Erro ao processar mensagem: {e}")

    except Exception as e:
        print(f"[ERROR] Conexão encerrada inesperadamente: {e}")

    finally:
        if username and username in ONLINE_USERS:
            del ONLINE_USERS[username]
            print(f"[LOGOUT] {username} saiu.")
        writer.close()
        await writer.wait_closed()


async def main():
    """Start the secure messaging server."""
    server = await asyncio.start_server(handle_client, HOST, PORT)
    addr = server.sockets[0].getsockname()
    print(f"[SERVER] Servidor rodando em {addr}")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[SERVER] Encerrado pelo usuário.")
