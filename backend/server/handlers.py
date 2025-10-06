"""
handlers.py
------------

Contains all secure, isolated async handlers for client actions:
- register
- login
- list_users
- send_message
Handles persistence, JWT, and message routing in a safe way.
"""

import asyncio
import json
import logging
from typing import Dict

from sqlalchemy.orm import Session
from backend.auth.models import User, Message
from backend.auth.security import hash_password, verify_password
from backend.auth.auth_jwt import create_access_token, verify_access_token

# 🔐 Lock global para evitar race conditions de multiusuários
USERS_LOCK = asyncio.Lock()


# -------------------------------
# 📝 Registro de usuário
# -------------------------------
async def handle_register(db: Session, writer, creds: dict) -> None:
    """Registers a new user securely."""
    username = creds.get("username")
    password = creds.get("password")
    public_key_b64 = creds.get("public_key")

    if not username or not password or not public_key_b64:
        writer.write("❌ Dados incompletos para registro.\n".encode("utf-8"))
        await writer.drain()
        return

    async with USERS_LOCK:
        existing = db.query(User).filter(User.username == username).first()
        if existing:
            writer.write("❌ Usuário já existe.\n".encode("utf-8"))
            await writer.drain()
            logging.warning(f"[REGISTER_FAIL] Usuario duplicado: {username}")
            return

        new_user = User(
            username=username,
            password_hash=hash_password(password),
            public_key=public_key_b64.encode(),
        )
        db.add(new_user)
        db.commit()

    writer.write("✅ Usuário criado com sucesso!\n".encode("utf-8"))
    await writer.drain()
    logging.info(f"[REGISTER] Usuario '{username}' cadastrado com chave publica salva.")


# -------------------------------
# 🔑 Login de usuário
# -------------------------------
async def handle_login(db: Session, writer, creds: dict, online_users: Dict[str, asyncio.StreamWriter]):
    """Handles secure login and JWT issuance."""
    username = creds.get("username")
    password = creds.get("password")

    if not username or not password:
        writer.write("❌ Dados de login incompletos.\n".encode("utf-8"))
        await writer.drain()
        return None, None

    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        writer.write("AUTH_FAILED\n".encode("utf-8"))
        await writer.drain()
        logging.warning(f"[DENIED] Tentativa de login falhou para '{username}'")
        return None, None

    token = create_access_token(username)
    async with USERS_LOCK:
        online_users[username] = writer

    logging.info(f"[LOGIN] {username} autenticado e online.")
    writer.write((json.dumps({"token": token}) + "\n").encode("utf-8"))
    await writer.drain()

    # Entregar mensagens off-line
    offline_msgs = (
        db.query(Message)
        .join(User, User.id == Message.receiver_id)
        .filter(User.username == username)
        .all()
    )
    for msg in offline_msgs:
        payload = {
            "from": db.query(User).get(msg.sender_id).username,
            "content_encrypted": msg.content_encrypted,
            "timestamp": str(msg.timestamp),
        }
        writer.write((json.dumps(payload) + "\n").encode("utf-8"))
        await writer.drain()

    if offline_msgs:
        for m in offline_msgs:
            db.delete(m)
        db.commit()
        logging.info(f"[OFFLINE] {len(offline_msgs)} mensagens entregues a '{username}'.")

    return username, token


# -------------------------------
# 👥 Listagem de usuários
# -------------------------------
async def handle_list_users(db: Session, writer, message: dict, online_users: Dict[str, asyncio.StreamWriter]):
    """Sends a list of users and their online status."""
    try:
        token = message.get("token")
        _ = verify_access_token(token)  # valida token

        users = db.query(User).all()
        users_info = [
            {
                "username": u.username,
                "online": u.username in online_users,
                "public_key": u.public_key.decode() if u.public_key else None,
            }
            for u in users
        ]
        writer.write((json.dumps({"users": users_info}) + "\n").encode("utf-8"))
        await writer.drain()
        logging.info("[LIST_USERS] Lista enviada com sucesso.")
    except Exception as e:
        logging.error(f"[LIST_USERS_ERROR] {e}")
        writer.write("❌ Falha ao listar usuários.\n".encode("utf-8"))
        await writer.drain()


# -------------------------------
# 💬 Envio de mensagem
# -------------------------------
async def handle_send_message(db: Session, message: dict, online_users: Dict[str, asyncio.StreamWriter]):
    """Routes or stores encrypted messages between users."""
    try:
        token = message.get("token")
        sender = verify_access_token(token)
        receiver = message.get("to")
        encrypted_content = message.get("content_encrypted")
        timestamp = message.get("timestamp", "")

        if not receiver or not encrypted_content:
            logging.warning(f"[SEND_FAIL] Dados incompletos de mensagem de {sender}")
            return

        receiver_user = db.query(User).filter(User.username == receiver).first()
        sender_user = db.query(User).filter(User.username == sender).first()

        if not receiver_user:
            logging.error(f"[ERROR] Destinatário '{receiver}' não encontrado.")
            return

        payload = {
            "from": sender,
            "content_encrypted": encrypted_content,
            "timestamp": timestamp,
        }

        async with USERS_LOCK:
            if receiver in online_users:
                dest_writer = online_users[receiver]
                dest_writer.write((json.dumps(payload) + "\n").encode("utf-8"))
                await dest_writer.drain()
                logging.info(f"[DELIVERED] Mensagem de {sender} para {receiver}")
            else:
                msg_obj = Message(
                    sender_id=sender_user.id,
                    receiver_id=receiver_user.id,
                    content_encrypted=encrypted_content,
                )
                db.add(msg_obj)
                db.commit()
                logging.info(f"[STORED] {receiver} offline. Mensagem armazenada.")
    except Exception as e:
        logging.error(f"[SEND_ERROR] {e}")
