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

import datetime
from sqlalchemy.orm import Session
from backend.auth.models import User, Message
from backend.auth.auth_jwt import create_access_token, verify_access_token
from backend.auth.security import hash_senha as hash_password, verificar_senha as verify_password
from backend.crypto.rsa_manager import RSAManager

# ----------------------------
# REGISTER (REST)
# ----------------------------
async def handle_register_rest(db: Session, creds: dict):
    username = creds.get("username")
    password = creds.get("password")

    if not username or not password:
        return {"error": "Campos incompletos"}, 400

    # Verifica se usuário já existe
    if db.query(User).filter(User.username == username).first():
        return {"error": "Usuário já existe"}, 400

    # Gera par de chaves RSA
    private_key_pem, public_key_pem = RSAManager.gerar_par_chaves()

    # Hash da senha
    hashed_password = hash_password(password)

    # Cria usuário
    new_user = User(
        username=username,
        password_hash=hashed_password,
        public_key=public_key_pem.encode(),
    )
    db.add(new_user)
    db.commit()

    return {
        "status": "success",
        "message": f"Usuário '{username}' criado com sucesso.",
        "private_key": private_key_pem,
    }


# ----------------------------
# LOGIN (REST)
# ----------------------------
async def handle_login_rest(db: Session, creds: dict):
    username = creds.get("username")
    password = creds.get("password")

    if not username or not password:
        return None, "Credenciais incompletas"

    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        return None, "Usuário ou senha incorretos"

    token = create_access_token(username)

    # --- Mensagens offline ---
    offline_msgs = (
        db.query(Message)
        .join(User, User.id == Message.receiver_id)
        .filter(User.username == username)
        .all()
    )

    messages_payload = []
    for msg in offline_msgs:
        payload = {
            "from": db.query(User).get(msg.sender_id).username,
            "content_encrypted": msg.content_encrypted,
            "key_encrypted": msg.key_encrypted,
            "timestamp": str(msg.timestamp),
        }
        messages_payload.append(payload)
        db.delete(msg)

    db.commit()
    return {"token": token, "offline_messages": messages_payload}, None


# ----------------------------
# LIST USERS (REST)
# ----------------------------
async def handle_list_users_rest(db: Session, token: str):
    try:
        requester = verify_access_token(token)
        users = db.query(User).all()
        users_info = [
            {
                "username": u.username,
                "public_key": u.public_key.decode() if u.public_key else None,
            }
            for u in users
        ]
        return {"users": users_info}, None
    except Exception as e:
        log.error(f"[LIST_FAIL] Erro ao listar usuários: {e}")
        writer.write("❌ Falha ao obter lista de usuários.\n".encode())
        await writer.drain()


# ======================================================
# ENVIO DE MENSAGEM PRIVADA
# ======================================================
async def handle_send_message(db: Session, message: dict, online_users: Dict[str, asyncio.StreamWriter]):
    """Envia ou armazena uma mensagem privada (E2EE)."""
    try:
        token = message.get("token")
        sender = verify_access_token(token)
        receiver = message.get("to")
        encrypted_content = message.get("content_encrypted")
        encrypted_key = message.get("key_encrypted")

        if not all([sender, receiver, encrypted_content, encrypted_key]):
            log.warning(f"[SEND_FAIL] Campos ausentes em mensagem de {sender}")
            return

        sender_user = db.query(User).filter(User.username == sender).first()
        receiver_user = db.query(User).filter(User.username == receiver).first()
        if not receiver_user:
            log.error(f"[SEND_FAIL] Destinatário {receiver} não encontrado.")
            return

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
                msg = Message(
                    sender_id=sender_user.id,
                    receiver_id=receiver_user.id,
                    content_encrypted=encrypted_content,
                    key_encrypted=encrypted_key,
                )
                db.add(msg)
                db.commit()
                log.info(f"[STORED] {receiver} offline. Mensagem armazenada.")

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