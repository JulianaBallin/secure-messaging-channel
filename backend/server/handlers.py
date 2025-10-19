import asyncio
import json
import datetime
import base64
from typing import Dict
from sqlalchemy.orm import Session
from backend.auth.models import User, Message, Group, GroupMember
from backend.auth.auth_jwt import create_access_token, verify_access_token
from backend.utils.logger_config import server_logger as log
from backend.auth.security import hash_senha as hash_password, verificar_senha as verify_password
from backend.crypto.rsa_manager import RSAManager

# ======================================================
# LOCK GLOBAL DE USUÁRIOS
# ======================================================
USERS_LOCK = asyncio.Lock()

# ======================================================
# CADASTRO
# ======================================================
async def handle_register(db: Session, writer, creds: dict) -> None:
    username = creds.get("username")
    password = creds.get("password")

    if not username or not password:
        writer.write("❌ Dados incompletos.\n".encode())
        await writer.drain()
        log.warning(f"[REGISTER_FAIL] Campos ausentes para cadastro de {username}")
        return

    async with USERS_LOCK:
        if db.query(User).filter(User.username == username).first():
            writer.write("❌ Usuário já existe.\n".encode())
            await writer.drain()
            log.warning(f"[REGISTER_DUPLICATE] Tentativa duplicada de {username}")
            return

        private_key_pem, public_key_pem = RSAManager.gerar_par_chaves()
        hashed_password = hash_password(password)

        new_user = User(
            username=username,
            password_hash=hashed_password,
            public_key=public_key_pem.encode(),
        )
        db.add(new_user)
        db.commit()

    writer.write(
        json.dumps(
            {
                "status": "success",
                "message": f"Usuário '{username}' criado com sucesso.",
                "private_key": private_key_pem,
            }
        ).encode()
        + b"\n"
    )
    await writer.drain()
    log.info(f"[REGISTER_OK] Novo usuário registrado: {username}")

# ======================================================
# LOGIN
# ======================================================
async def handle_login(db: Session, writer, creds: dict, online_users: Dict[str, asyncio.StreamWriter]):
    username = creds.get("username")
    password = creds.get("password")

    if not username or not password:
        writer.write("❌ Credenciais incompletas.\n".encode())
        await writer.drain()
        return None, None

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
    log.info(f"[LOGIN_OK] {username} autenticado e online.")

    return username, token

# ======================================================
# LIST USERS
# ======================================================
async def handle_list_users(db: Session, writer, message: dict, online_users: Dict[str, asyncio.StreamWriter]):
    try:
        token = message.get("token")
        requester = verify_access_token(token)
        users = db.query(User).all()

        users_info = [
            {
                "username": u.username,
                "online": u.username in online_users,
                "public_key": u.public_key.decode() if u.public_key else None,
            }
            for u in users
        ]
        writer.write((json.dumps({"users": users_info}) + "\n").encode())
        await writer.drain()
        log.info(f"[LIST_OK] {requester} requisitou a lista de usuários ({len(users)} registros).")
    except Exception as e:
        log.error(f"[LIST_FAIL] Erro ao listar usuários: {e}")
        writer.write("❌ Falha ao obter lista de usuários.\n".encode())
        await writer.drain()

# ======================================================
# ENVIO DE MENSAGEM PRIVADA (com armazenamento sempre)
# ======================================================
async def handle_send_message(db: Session, message: dict, online_users: Dict[str, asyncio.StreamWriter]):
    try:
        token = message.get("token")
        sender = verify_access_token(token)
        receiver = message.get("to")
        encrypted_content = message.get("content_encrypted")
        encrypted_key = message.get("key_encrypted")
        signature_b64 = message.get("signature")
        content_hash = message.get("content_hash")

        if not all([sender, receiver, encrypted_content, encrypted_key]):
            log.warning(f"[SEND_FAIL] Campos ausentes em mensagem de {sender}")
            return

        sender_user = db.query(User).filter(User.username == sender).first()
        receiver_user = db.query(User).filter(User.username == receiver).first()
        if not receiver_user:
            log.error(f"[SEND_FAIL] Destinatário {receiver} não encontrado.")
            return

        # 💾 Sempre salva no banco (garante histórico)
        msg = Message(
            sender_id=sender_user.id,
            receiver_id=receiver_user.id,
            content_encrypted=encrypted_content,
            key_encrypted=encrypted_key,
            content_hash=content_hash,
            signature=(base64.b64decode(signature_b64) if signature_b64 else None),
        )
        db.add(msg)
        db.commit()

        # 🔄 Tenta entregar ao destinatário online
        payload = {
            "from": sender,
            "to": receiver,
            "content_encrypted": encrypted_content,
            "key_encrypted": encrypted_key,
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }
        if signature_b64:
            payload["signature"] = signature_b64
        if content_hash:
            payload["content_hash"] = content_hash

        async with USERS_LOCK:
            dest_writer = online_users.get(receiver)
            if dest_writer and not dest_writer.is_closing():
                try:
                    dest_writer.write((json.dumps(payload) + "\n").encode())
                    await dest_writer.drain()
                    log.info(f"[DELIVERED + STORED] {sender} → {receiver}")
                except Exception as e:
                    log.error(f"[SEND_ERROR] Falha ao enviar para {receiver}: {e}")
                    online_users.pop(receiver, None)
            else:
                log.info(f"[STORED_ONLY] {receiver} offline. Mensagem armazenada.")

    except Exception as e:
        log.error(f"[SEND_ERROR] Falha ao enviar mensagem privada: {e}")

# ======================================================
# ENVIO DE MENSAGEM EM GRUPO
# ======================================================
async def handle_send_group_message(db: Session, message: dict, online_users: Dict[str, asyncio.StreamWriter]):
    try:
        token = message.get("token")
        sender = verify_access_token(token)
        group_name = message.get("group")
        encrypted_content = message.get("content_encrypted")
        keys_map = message.get("keys_encrypted", {})

        group = db.query(Group).filter(Group.name == group_name).first()
        if not group:
            log.error(f"[GROUP_SEND_FAIL] Grupo '{group_name}' não encontrado.")
            return

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
                log.info(f"[GROUP_DELIVERED] {sender} → {username} ({group_name})")
            else:
                receiver_user = db.query(User).filter(User.username == username).first()
                msg = Message(
                    sender_id=sender_user.id,
                    receiver_id=receiver_user.id,
                    group_id=group.id,
                    content_encrypted=encrypted_content,
                    key_encrypted=keys_map.get(username),
                )
                db.add(msg)
                db.commit()
                log.info(f"[GROUP_STORE] {username} offline. Mensagem salva (grupo {group_name}).")

        log.info(f"[GROUP_SEND_OK] {sender} enviou mensagem ao grupo {group_name}")

    except Exception as e:
        log.error(f"[GROUP_SEND_ERROR] Erro ao enviar mensagem em grupo: {e}") 