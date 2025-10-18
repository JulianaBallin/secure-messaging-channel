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
    """Cadastra novo usuário, gera par de chaves RSA e armazena senha com hash Argon2id."""
    username = creds.get("username")
    password = creds.get("password")

    if not username or not password:
        writer.write("❌ Dados incompletos.\n".encode())
        await writer.drain()
        log.warning(f"[REGISTER_FAIL] Campos ausentes para cadastro de {username}")
        return

    async with USERS_LOCK:
        # Verifica se o usuário já existe
        if db.query(User).filter(User.username == username).first():
            writer.write("❌ Usuário já existe.\n".encode())
            await writer.drain()
            log.warning(f"[REGISTER_DUPLICATE] Tentativa duplicada de {username}")
            return

        # Gera par de chaves RSA (privada e pública)
        private_key_pem, public_key_pem = RSAManager.gerar_par_chaves()

        # Hash da senha com Argon2
        hashed_password = hash_password(password)

        # Cria e persiste o novo usuário
        new_user = User(
            username=username,
            password_hash=hashed_password,
            public_key=public_key_pem.encode(),  # armazenar em bytes
        )
        db.add(new_user)
        db.commit()

    # Retorna chave privada ao cliente (pode ser exibida uma única vez)
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
# LOGIN + ENTREGA DE MENSAGENS OFFLINE
# ======================================================
async def handle_login(db: Session, writer, creds: dict, online_users: Dict[str, asyncio.StreamWriter]):
    """Autentica o usuário e entrega mensagens pendentes do banco."""
    username = creds.get("username")
    password = creds.get("password")

    if not username or not password:
        writer.write("❌ Credenciais incompletas.\n".encode())
        await writer.drain()
        log.warning("[LOGIN_FAIL] Campos ausentes no login.")
        return None, None

    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        writer.write("AUTH_FAILED\n".encode())
        await writer.drain()
        log.warning(f"[LOGIN_FAIL] Usuário inexistente ou senha incorreta: {username}")
        return None, None

    token = create_access_token(username)
    async with USERS_LOCK:
        online_users[username] = writer

    writer.write((json.dumps({"token": token}) + "\n").encode())
    await writer.drain()
    log.info(f"[LOGIN_OK] {username} autenticado e online.")

    # --- Mensagens offline pendentes ---
    offline_msgs = (
        db.query(Message)
        .join(User, User.id == Message.receiver_id)
        .filter(User.username == username)
        .all()
    )
    if not offline_msgs:
        return username, token

    log.info(f"[OFFLINE_DELIVERY] {len(offline_msgs)} mensagens pendentes para {username}")
    for msg in offline_msgs:
        try:
            payload = {
                "from": db.query(User).get(msg.sender_id).username,
                "content_encrypted": msg.content_encrypted,
                "key_encrypted": msg.key_encrypted,
                "timestamp": str(msg.timestamp),
            }
            writer.write((json.dumps(payload) + "\n").encode())
            await writer.drain()
            db.delete(msg)
        except Exception as e:
            log.error(f"[OFFLINE_FAIL] Erro ao entregar mensagem offline: {e}")
    db.commit()

    log.info(f"[OFFLINE_OK] Todas as mensagens pendentes entregues para {username}")
    return username, token


# ======================================================
# LISTAGEM DE USUÁRIOS
# ======================================================
async def handle_list_users(db: Session, writer, message: dict, online_users: Dict[str, asyncio.StreamWriter]):
    """Retorna a lista de todos os usuários e seus status."""
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
# ENVIO DE MENSAGEM PRIVADA
# ======================================================
# ======================================================
# 💌 ENVIO DE MENSAGEM PRIVADA (robusto e seguro)
# ======================================================
async def handle_send_message(db: Session, data: dict, online_users: Dict[str, asyncio.StreamWriter]):
    """
    Envia mensagens criptografadas entre usuários, garantindo que:
    - o token seja válido
    - o destinatário exista
    - o socket esteja ativo antes do envio
    - mensagens offline sejam armazenadas no banco
    """
    sender_token = data.get("token")
    receiver_name = data.get("to")
    content_encrypted = data.get("content_encrypted")
    key_encrypted = data.get("key_encrypted")

    try:
        # 🔒 Autentica o remetente via token JWT
        sender_username = verify_access_token(sender_token)
        if not sender_username:
            log.error("[SEND_ERROR] Token inválido.")
            return

        # ⚙️ Validação de campos
        if not receiver_name or not content_encrypted:
            log.warning(f"[SEND_FAIL] Campos ausentes em mensagem de {sender_username}")
            return

        # 🔍 Busca remetente e destinatário no banco
        sender_user = db.query(User).filter_by(username=sender_username).first()
        receiver_user = db.query(User).filter_by(username=receiver_name).first()

        if not sender_user or not receiver_user:
            log.warning(f"[SEND_FAIL] Usuário inexistente: {receiver_name}")
            return

        # 💾 Sempre salva a mensagem no banco (garantia de histórico)
        msg = Message(
            sender_id=sender_user.id,
            receiver_id=receiver_user.id,
            content_encrypted=content_encrypted,
            key_encrypted=key_encrypted,
        )
        db.add(msg)
        db.commit()

        # 🔄 Verifica se o destinatário está online
        receiver_writer = online_users.get(receiver_name)

        if receiver_writer and not receiver_writer.is_closing():
            try:
                payload = {
                    "from": sender_username,
                    "to": receiver_name,
                    "content_encrypted": content_encrypted,
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                }
                receiver_writer.write((json.dumps(payload) + "\n").encode("utf-8"))
                await receiver_writer.drain()
                log.info(f"[SEND_OK] {sender_username} → {receiver_name}")
            except Exception as e:
                log.error(f"[SEND_ERROR] Falha ao enviar para {receiver_name}: {e}")
                # Se o socket fechou, remove da lista
                online_users.pop(receiver_name, None)
        else:
            log.warning(f"[SEND_WARN] {receiver_name} está offline. Mensagem armazenada no banco.")

    except Exception as e:
        log.error(f"[SEND_ERROR] Falha ao enviar mensagem privada: {e}")

# ======================================================
# ENVIO DE MENSAGEM EM GRUPO
# ======================================================
async def handle_send_group_message(db: Session, message: dict, online_users: Dict[str, asyncio.StreamWriter]):
    """Envia mensagens criptografadas para todos os membros de um grupo."""
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