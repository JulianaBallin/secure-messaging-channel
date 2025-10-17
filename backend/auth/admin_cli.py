"""
admin_cli.py
------------

Ferramenta administrativa local para cadastro e login direto no banco.
Uso exclusivo do servidor (não do cliente).
"""

import re
from sqlalchemy.orm import Session
from backend.database.connection import SessionLocal
from backend.auth.models import User
from backend.auth.security import hash_password, verify_password
from backend.crypto.rsa_manager import RSAManager

# Mapa simples de usuários online (memória local do processo)
ONLINE_USERS: dict[str, bool] = {}


def is_valid_username(username: str) -> bool:
    return bool(re.fullmatch(r"^[A-Za-z0-9_]{3,20}$", username))


def is_valid_password(password: str) -> bool:
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=]", password):
        return False
    return True


def register_user() -> None:
    """Cadastro local (uso administrativo apenas)."""
    db: Session = SessionLocal()
    try:
        # RSAManager.gerar_par_chaves() retorna (privada_str, publica_str)
        _, public_key_str = RSAManager.gerar_par_chaves()

        username = input("👤 Nome de usuário: ").strip()
        if not is_valid_username(username):
            print("❌ Nome de usuário inválido.")
            return

        # Verifica duplicidade
        if db.query(User).filter(User.username == username).first():
            print("❌ Usuário já existe.")
            return

        password = input("🔑 Senha: ").strip()
        confirm = input("🔁 Confirme: ").strip()
        if password != confirm:
            print("❌ Senhas não coincidem.")
            return
        if not is_valid_password(password):
            print("❌ Senha fraca. Exige 8+ caracteres, 1 maiúscula, 1 número, 1 símbolo.")
            return

        # Se o campo public_key no modelo for TEXT, usar string mesmo.
        # Se for LargeBinary, troque para: public_key=public_key_str.encode("utf-8")
        user = User(
            username=username,
            password_hash=hash_password(password),
            public_key=public_key_str,
        )

        db.add(user)
        db.commit()
        print("✅ Usuário cadastrado com sucesso!")
    except Exception as e:
        db.rollback()
        print(f"💥 Erro ao cadastrar: {e}")
    finally:
        db.close()


def login_user() -> str | None:
    db: Session = SessionLocal()
    try:
        username = input("👤 Usuário: ").strip()
        password = input("🔑 Senha: ").strip()

        user = db.query(User).filter(User.username == username).first()
        if not user:
            print("❌ Usuário não encontrado.")
            return None

        if verify_password(password, user.password_hash):
            ONLINE_USERS[username] = True
            print(f"✅ Login bem-sucedido! {username} agora está online.")
            return username

        print("❌ Senha incorreta.")
        return None
    except Exception as e:
        print(f"💥 Erro no login: {e}")
        return None
    finally:
        db.close()


if __name__ == "__main__":
    print("⚙️ Ferramenta administrativa local")
    print("1️⃣  Cadastrar usuário")
    print("2️⃣  Fazer login")
    choice = input("Opção: ").strip()
    if choice == "1":
        register_user()
    elif choice == "2":
        login_user()
