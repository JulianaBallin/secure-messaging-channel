"""
users.py
--------

Consultas e operações relacionadas a usuários.
Inclui criação, busca, atualização de chaves públicas e status online.
"""

from sqlalchemy.orm import Session
from backend.auth.models import User
from backend.utils.logger_config import database_logger as dblog


# ======================================================
# Buscar usuário
# ======================================================
def get_user_by_username(db: Session, username: str):
    """Busca um usuário pelo nome de usuário."""
    user = db.query(User).filter(User.username == username).first()
    if user:
        dblog.info(f"[USER_GET] Usuário encontrado: {username}")
    else:
        dblog.warning(f"[USER_GET_FAIL] Usuário não encontrado: {username}")
    return user


# ======================================================
# Criar usuário
# ======================================================
def create_user(db: Session, username: str, password_hash: str, public_key: bytes | None = None):
    """Cria um novo usuário com hash de senha e chave pública opcional."""
    if db.query(User).filter(User.username == username).first():
        dblog.warning(f"[USER_CREATE_DUPLICATE] {username} já existe.")
        return None

    new_user = User(username=username, password_hash=password_hash, public_key=public_key)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    dblog.info(f"[USER_CREATE] Usuário criado: {username}")
    return new_user


# ======================================================
# Atualizar chave pública
# ======================================================
def update_public_key(db: Session, username: str, new_key: bytes):
    """Atualiza a chave pública de um usuário existente."""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        dblog.error(f"[USER_KEY_UPDATE_FAIL] Usuário não encontrado: {username}")
        return False

    user.public_key = new_key
    db.commit()
    dblog.info(f"[USER_KEY_UPDATE] Chave pública atualizada para {username}")
    return True


# ======================================================
# Atualizar status online/offline
# ======================================================
def set_user_status(db: Session, username: str, online: bool):
    """Atualiza o status (online/offline) de um usuário."""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        dblog.warning(f"[USER_STATUS_FAIL] Usuário não encontrado: {username}")
        return False

    user.is_online = online
    db.commit()
    state = "🟢 online" if online else "⚫ offline"
    dblog.info(f"[USER_STATUS] {username} está agora {state}.")
    return True


# ======================================================
# Listar todos os usuários
# ======================================================
def list_all_users(db: Session):
    """Lista todos os usuários cadastrados."""
    users = db.query(User).all()
    dblog.info(f"[USER_LIST] {len(users)} usuários retornados.")
    return [
        {
            "username": u.username,
            "online": u.is_online,
            "has_key": bool(u.public_key),
            "created_at": str(u.created_at),
        }
        for u in users
    ]
