# backend/server/handlers_rest.py
from backend.database.connection import SessionLocal
from backend.auth.models import User
from backend.auth.security import hash_senha as hash_password, verificar_senha as verify_password
from backend.auth.auth_jwt import create_access_token

async def handle_register_rest(db, creds: dict):
    username = creds.get("username")
    password = creds.get("password")
    if not username or not password:
        return {"status": "error", "message": "Campos ausentes"}

    if db.query(User).filter(User.username == username).first():
        return {"status": "error", "message": "Usuário já existe"}

    hashed_password = hash_password(password)
    new_user = User(username=username, password_hash=hashed_password)
    db.add(new_user)
    db.commit()
    return {"status": "ok", "message": f"Usuário '{username}' criado"}

async def handle_login_rest(db, creds: dict):
    username = creds.get("username")
    password = creds.get("password")
    if not username or not password:
        return {"status": "error", "message": "Campos ausentes"}, None

    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        return {"status": "error", "message": "Credenciais inválidas"}, None

    token = create_access_token(username)
    return {"status": "ok", "token": token}, token
