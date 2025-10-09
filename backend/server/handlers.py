"""
handlers.py
------------

Contém todos os handlers assíncronos seguros e isolados para ações do cliente:
- register
- login
- list_users
- send_message
- send_group_message

Implementa:
- Criptografia ponta a ponta (RSA + IDEA)
- Controle completo de grupos (criação, envio, chaves, transferência)
- Logs de auditoria em tempo real
- Proteção contra race conditions via asyncio.Lock
"""

import asyncio
import json
import datetime
from typing import Dict
from sqlalchemy.orm import Session
from backend.auth.models import User, Message, Group, GroupMember
from backend.auth.security import hash_password, verify_password
from backend.auth.auth_jwt import create_access_token, verify_access_token
from backend.utils.logger_config import server_logger as log


USERS_LOCK = asyncio.Lock()


# ======================================================
# CADASTRO
# ======================================================
async def handle_register(db: Session, writer, creds: dict) -> None:
    """Cadastra novo usuário com chave RSA pública."""
    username = creds.get("username")
    password = creds.get("password")
    public_key_b64 = creds.get("public_key")

    if not username or not password or not public_key_b64:
        writer.write("❌ Dados incompletos.\n".encode())
        await writer.drain()
        return

    async with USERS_LOCK:
        if db.query(User).filter(User.username == username).first():
            writer.write("❌ Usuário já existe.\n".encode())
            await writer.drain()
            return

        new_user = User(username=username, password_hash=hash_password(password), public_key=public_key_b64.encode())
        db.add(new_user)
        db.commit()

    writer.write("✅ Usuário criado!\n".encode())
    await writer.drain()
    log.info(f"[REGISTER_OK] {username} cadastrado.")


# ======================================================
# LOGIN + MENSAGENS OFFLINE
# ======================================================
async def handle_login(db: Session, writer, creds: dict, online_users: Dict[str, asyncio.StreamWriter]):
    """Autentica usuário e entrega mensagens pendentes."""
    username = creds.get("username")
    password = creds.get("password")

    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        writer.write("AUTH_FAILED\n".encode())
        await writer.drain()
        return None, None

    token = create_access_token(username)
    async with USERS_LOCK:
        online_users[username] = writer
    writer.write((json.dumps({"token": token}) + "\n").encode())
    await writer.drain()

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
            "key_encrypted": msg.key_encrypted,
            "timestamp": str(msg.timestamp),
        }
        writer.write((json.dumps(payload) + "\n").encode())
        await writer.drain()
        db.delete(msg)
    db.commit()
    return username, token


# ======================================================
# LISTAGEM
# ======================================================
async def handle_list_users(db: Session, writer, message: dict, online_users: Dict[str, asyncio.StreamWriter]):
    token = message.get("token")
    requester = verify_access_token(token)
    users = db.query(User).all()
    users_info = [
        {"username": u.username, "online": u.username in online_users, "public_key": u.public_key.decode() if u.public_key else None}
        for u in users
    ]
    writer.write((json.dumps({"users": users_info}) + "\n").encode())
    await writer.drain()
    log.info(f"[LIST_OK] Lista enviada para {requester}")


# ======================================================
# ENVIO PRIVADO
# ======================================================
async def handle_send_message(db: Session, message: dict, online_users: Dict[str, asyncio.StreamWriter]):
    token = message.get("token")
    sender = verify_access_token(token)
    receiver = message.get("to")
    encrypted_content = message.get("content_encrypted")
    encrypted_key = message.get("key_encrypted")

    sender_user = db.query(User).filter(User.username == sender).first()
    receiver_user = db.query(User).filter(User.username == receiver).first()
    payload = {
        "from": sender,
        "content_encrypted": encrypted_content,
        "key_encrypted": encrypted_key,
        "timestamp": datetime.datetime.utcnow().isoformat(),
    }

    async with USERS_LOCK:
        if receiver in online_users:
            dest_writer = online_users[receiver]
            dest_writer.write((json.dumps(payload) + "\n").encode())
            await dest_writer.drain()
            log.info(f"[DELIVERED] {sender} → {receiver}")
        else:
            msg = Message(sender_id=sender_user.id, receiver_id=receiver_user.id, content_encrypted=encrypted_content, key_encrypted=encrypted_key)
            db.add(msg)
            db.commit()
            log.info(f"[STORED] {receiver} offline.")


# ======================================================
# ENVIO EM GRUPO
# ======================================================
async def handle_send_group_message(db: Session, message: dict, online_users: Dict[str, asyncio.StreamWriter]):
    token = message.get("token")
    sender = verify_access_token(token)
    group_name = message.get("group")
    encrypted_content = message.get("content_encrypted")
    keys_map = message.get("keys_encrypted", {})

    group = db.query(Group).filter(Group.name == group_name).first()
    members = (
        db.query(User.username)
        .join(GroupMember, GroupMember.user_id == User.id)
        .filter(GroupMember.group_id == group.id)
        .all()
    )

    sender_user = db.query(User).filter(User.username == sender).first()
    for (username,) in members:
        if username == sender:
            continue
        payload = {
            "from": sender,
            "group": group_name,
            "content_encrypted": encrypted_content,
            "key_encrypted": keys_map.get(username),
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }
        if username in online_users:
            writer = online_users[username]
            writer.write((json.dumps(payload) + "\n").encode())
            await writer.drain()
        else:
            receiver_user = db.query(User).filter(User.username == username).first()
            msg = Message(sender_id=sender_user.id, receiver_id=receiver_user.id, group_id=group.id, content_encrypted=encrypted_content, key_encrypted=keys_map.get(username))
            db.add(msg)
            db.commit()
    log.info(f"[GROUP_SEND] {sender} → grupo {group_name}")
