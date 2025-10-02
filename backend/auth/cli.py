"""
cli.py
-------

Provides a secure terminal interface for user registration and login.
Includes username/password validation, secure hashing, and online status tracking.
"""

import re
from sqlalchemy.orm import Session
from backend.database.connection import SessionLocal
from backend.auth.models import User
from backend.auth.security import hash_password, verify_password
from backend.crypto.rsa_manager import generate_rsa_keypair

# Dicionário simples para usuários online (chave: username)
ONLINE_USERS: dict[str, bool] = {}

# -------------------------------
# 🔍 Validações de segurança
# -------------------------------

def is_valid_username(username: str) -> bool:
    """Check username validity: only letters, digits, and underscore, 3–20 chars."""
    return bool(re.fullmatch(r"^[A-Za-z0-9_]{3,20}$", username))

def is_valid_password(password: str) -> bool:
    """Check password strength: min 8 chars, 1 uppercase, 1 digit, 1 special char."""
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=]", password):
        return False
    return True

# -------------------------------
# 👤 Cadastro de usuário
# -------------------------------

def register_user() -> None:
    """Registers a new user with strong username and password validation."""
    db: Session = SessionLocal()
    public_key, private_key = generate_rsa_keypair()

    username = input("👤 Escolha um nome de usuário: ").strip()

    if not is_valid_username(username):
        print("❌ Nome de usuário inválido. Use apenas letras, números e '_' (sem acentuação).")
        return

    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        print("❌ Este nome de usuário já está em uso. Escolha outro.")
        return

    password = input("🔑 Crie uma senha: ").strip()
    confirm_password = input("🔁 Confirme a senha: ").strip()

    if password != confirm_password:
        print("❌ As senhas não coincidem.")
        return

    if not is_valid_password(password):
        print(
            "❌ Senha fraca.\n"
            "A senha deve ter pelo menos:\n"
            "- 8 caracteres\n"
            "- 1 letra maiúscula\n"
            "- 1 número\n"
            "- 1 caractere especial (!@#$%^&*...)"
        )
        return

    user = User(
        username=username,
        password_hash=hash_password(password),
        public_key=public_key,
        private_key=private_key
    )
    db.add(user)
    db.commit()
    print("✅ Usuário cadastrado com sucesso!")


# -------------------------------
# 🔑 Login de usuário + lista online
# -------------------------------

def login_user() -> str | None:
    """Authenticates a user and shows the list of all users with online status."""
    db: Session = SessionLocal()
    username = input("👤 Usuário: ").strip()
    password = input("🔑 Senha: ").strip()

    user = db.query(User).filter(User.username == username).first()
    if not user:
        print("❌ Usuário não encontrado.")
        return None

    if verify_password(password, user.password_hash):
        print(f"✅ Login bem-sucedido! Bem-vindo(a), {username}!")

        ONLINE_USERS[username] = True

        print("\n=== 👥 Lista de usuários cadastrados ===")
        all_users = db.query(User).all()
        for u in all_users:
            status = "🟢 online" if ONLINE_USERS.get(u.username) else "🔴 offline"
            print(f" - {u.username:20} | {status}")

        return username
    else:
        print("❌ Senha incorreta.")
        return None
