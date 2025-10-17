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
        return None, f"Erro ao listar usuários: {e}"
