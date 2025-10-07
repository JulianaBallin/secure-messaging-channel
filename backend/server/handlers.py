"""
handlers.py (E2EE + Logging)
----------------------------

Contains all secure, isolated async handlers for client actions:
- register
- login
- list_users
- send_message

Implements:
- End-to-end encryption routing (RSA + IDEA)
- Full event logging for auditability
- Race-condition protection via asyncio.Lock
"""

import asyncio
import json
import logging
from typing import Dict
from sqlalchemy.orm import Session

from backend.auth.models import User, Message
from backend.auth.security import hash_password, verify_password
from backend.auth.auth_jwt import create_access_token, verify_access_token

# 🔐 Global user lock — prevents concurrent write race conditions
USERS_LOCK = asyncio.Lock()


# ======================================================
# 📝 USER REGISTRATION
# ======================================================
async def handle_register(db: Session, writer, creds: dict) -> None:
    """Registers a new user securely with RSA public key."""
    username = creds.get("username")
    password = creds.get("password")
    public_key_b64 = creds.get("public_key")

    logging.info(f"[REGISTER_ATTEMPT] Tentativa de cadastro: {username}")

    if not username or not password or not public_key_b64:
        msg = "❌ Dados incompletos para registro."
        writer.write(f"{msg}\n".encode("utf-8"))
        await writer.drain()
        logging.warning(f"[REGISTER_FAIL] Campos ausentes para {username}")
        return

    async with USERS_LOCK:
        if db.query(User).filter(User.username == username).first():
            writer.write("❌ Usuário já existe.\n".encode("utf-8"))
            await writer.drain()
            logging.warning(f"[REGISTER_FAIL] Usuário duplicado: {username}")
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
    logging.info(f"[REGISTER_OK] Usuário '{username}' cadastrado e chave pública armazenada.")


# ======================================================
# 🔑 USER LOGIN
# ======================================================
async def handle_login(db: Session, writer, creds: dict, online_users: Dict[str, asyncio.StreamWriter]):
    """Handles user authentication and token issuance."""
    username = creds.get("username")
    password = creds.get("password")

    logging.info(f"[LOGIN_ATTEMPT] {username} tentando autenticar...")

    if not username or not password:
        writer.write("❌ Dados de login incompletos.\n".encode("utf-8"))
        await writer.drain()
        logging.warning(f"[LOGIN_FAIL] Campos ausentes: {username}")
        return None, None

    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        writer.write("AUTH_FAILED\n".encode("utf-8"))
        await writer.drain()
        logging.warning(f"[LOGIN_FAIL] Senha inválida ou usuário inexistente: {username}")
        return None, None

    token = create_access_token(username)
    async with USERS_LOCK:
        online_users[username] = writer

    writer.write((json.dumps({"token": token}) + "\n").encode("utf-8"))
    await writer.drain()
    logging.info(f"[LOGIN_OK] {username} autenticado e marcado como online.")

    # --------------------------------------------------
    # Entregar mensagens pendentes (armazenadas)
    # --------------------------------------------------
    offline_msgs = (
        db.query(Message)
        .join(User, User.id == Message.receiver_id)
        .filter(User.username == username)
        .all()
    )

    if offline_msgs:
        logging.info(f"[OFFLINE_DELIVERY] {len(offline_msgs)} mensagens pendentes para {username}")
        for msg in offline_msgs:
            payload = {
                "from": db.query(User).get(msg.sender_id).username,
                "content_encrypted": msg.content_encrypted,
                "key_encrypted": msg.key_encrypted,
                "timestamp": str(msg.timestamp),
            }
            writer.write((json.dumps(payload) + "\n").encode("utf-8"))
            await writer.drain()
            db.delete(msg)
        db.commit()
        logging.info(f"[OFFLINE_OK] Mensagens entregues e removidas do banco para {username}")

    return username, token


# ======================================================
# 👥 USER LISTING
# ======================================================
async def handle_list_users(db: Session, writer, message: dict, online_users: Dict[str, asyncio.StreamWriter]):
    """Returns list of all users with status and public key availability."""
    try:
        token = message.get("token")
        requester = verify_access_token(token)
        logging.info(f"[LIST_REQUEST] {requester} solicitou lista de usuários.")

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
        logging.info(f"[LIST_OK] Lista enviada a {requester} ({len(users)} usuários).")

    except Exception as e:
        logging.error(f"[LIST_ERROR] {e}")
        writer.write("❌ Falha ao listar usuários.\n".encode("utf-8"))
        await writer.drain()


# ======================================================
# 💬 ENCRYPTED MESSAGE ROUTING
# ======================================================
async def handle_send_message(db: Session, message: dict, online_users: Dict[str, asyncio.StreamWriter]):
    """
    Routes or stores encrypted messages between users.
    Supports IDEA (CBC) + RSA (OAEP) hybrid encryption.
    """
    try:
        token = message.get("token")
        sender = verify_access_token(token)
        receiver = message.get("to")
        encrypted_content = message.get("content_encrypted")
        encrypted_key = message.get("key_encrypted")
        timestamp = message.get("timestamp", "")

        # Validate fields
        if not all([receiver, encrypted_content, encrypted_key]):
            logging.warning(f"[SEND_FAIL] Campos ausentes em mensagem de {sender}.")
            return

        receiver_user = db.query(User).filter(User.username == receiver).first()
        sender_user = db.query(User).filter(User.username == sender).first()
        if not receiver_user:
            logging.error(f"[SEND_ERROR] Destinatário '{receiver}' não encontrado.")
            return

        payload = {
            "from": sender,
            "content_encrypted": encrypted_content,
            "key_encrypted": encrypted_key,
            "timestamp": timestamp,
        }

        async with USERS_LOCK:
            if receiver in online_users:
                dest_writer = online_users[receiver]
                dest_writer.write((json.dumps(payload) + "\n").encode("utf-8"))
                await dest_writer.drain()
                logging.info(f"[DELIVERED] E2EE mensagem de {sender} para {receiver}")
            else:
                msg_obj = Message(
                    sender_id=sender_user.id,
                    receiver_id=receiver_user.id,
                    content_encrypted=encrypted_content,
                    key_encrypted=encrypted_key,
                )
                db.add(msg_obj)
                db.commit()
                logging.info(f"[STORED] {receiver} offline. Mensagem E2EE armazenada.")

    except Exception as e:
        logging.error(f"[SEND_ERROR] {e}")
