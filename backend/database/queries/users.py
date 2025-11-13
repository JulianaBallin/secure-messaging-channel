"""
users.py — CRUD para tabela 'users'
"""

from backend.auth.models import User
from backend.auth.security import hash_senha
from backend.crypto.rsa_manager import RSAManager
from backend.utils.db_utils import safe_db_operation
from backend.utils.logger_config import autenticidade_logger

import os

# CREATE
@safe_db_operation
def create_user(db, username: str, password: str):
    """Cria um novo usuário com senha hash e chave RSA."""
    if db.query(User).filter_by(username=username).first():
        raise ValueError(f"Usuário '{username}' já existe.")

    password_hash = hash_senha(password)
    private_key_pem, public_key_pem = RSAManager.gerar_par_chaves()

    # 🔑 Salvar chaves em backend/keys/{username}/
    # users.py está em backend/database/queries/, então sobe 3 níveis para chegar em backend/
    BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    user_keys_dir = os.path.join(BACKEND_DIR, "keys", username)
    os.makedirs(user_keys_dir, exist_ok=True)
    
    private_key_path = os.path.join(user_keys_dir, f"{username}_private.pem")
    public_key_path = os.path.join(user_keys_dir, f"{username}_public.pem")

    # Salvar chave privada
    with open(private_key_path, "w", encoding="utf-8") as key_file:
        key_file.write(private_key_pem)
    os.chmod(private_key_path, 0o600)
    
    # Salvar chave pública
    with open(public_key_path, "w", encoding="utf-8") as key_file:
        key_file.write(public_key_pem)
    os.chmod(public_key_path, 0o644)

    user = User(username=username, password_hash=password_hash, public_key=public_key_pem.encode())
    db.add(user)
    db.commit()
    db.refresh(user)

    autenticidade_logger.info("USER_CREATE", username, f"Usuário criado com senha hash (hash parcial: {password_hash[:16]}...)")
    autenticidade_logger.info("RSA_KEYGEN", username, "Par de chaves RSA gerado e salvo com segurança.")
    
    return user


# READ
def get_user_by_username(db, username: str):
    return db.query(User).filter(User.username == username).first()

def list_users(db):
    return db.query(User).all()


# UPDATE
@safe_db_operation
def set_user_online_status(db, username: str, online: bool):
    user = get_user_by_username(db, username)
    if not user:
        raise ValueError("Usuário não encontrado.")
    user.is_online = online
    db.commit()
    return user

# DELETE
@safe_db_operation
def delete_user(db, username: str):
    user = get_user_by_username(db, username)
    if not user:
        raise ValueError("Usuário não encontrado.")
    db.delete(user)
    db.commit()
    return True
