"""
routes.py
----------

Defines API routes for user authentication and management.  
Includes endpoints for user registration, login, and retrieving a list of online users.

Endpoints:
    - POST /auth/register: Register a new user with hashed password.
    - POST /auth/login: Authenticate a user and issue a JWT access token.
    - GET /auth/online: Return a list of users currently online (connected sessions).
"""

from datetime import datetime, timedelta
from typing import List

from fastapi import APIRouter, HTTPException, status
from jose import jwt
from pydantic import BaseModel
from backend.auth.security import hash_password, verify_password
from backend.config import SECRET_KEY, ACCESS_TOKEN_EXPIRE_MINUTES
from backend.utils.logger_config import autenticidade_logger

# JWT Config
ALGORITHM = "HS256"

router = APIRouter()

# -------------------------
# MODELOS Pydantic
# -------------------------

class UserCreate(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class OnlineUser(BaseModel):
    username: str
    last_active: datetime

# "Banco de dados" em memória (substituir por SQLAlchemy no futuro)
FAKE_DB = {}
ONLINE_USERS = {}

# -------------------------
# Registro de Usuário
# -------------------------

@router.post("/register", status_code=201)
async def register_user(user: UserCreate):
    """
    Register a new user with hashed password.
    Raises 400 if user already exists.
    """
    if user.username in FAKE_DB:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already exists."
        )
    hashed_pw = hash_password(user.password)
    FAKE_DB[user.username] = {"password": hashed_pw}
    autenticidade_logger.info(f"[REGISTRO_OK] Usuário '{user.username}' criado com hash: {hashed_pw}")
    return {"message": f"✅ User '{user.username}' registered successfully."}


# -------------------------
# Login e emissão de JWT
# -------------------------

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """Creates a JWT access token with expiration."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@router.post("/login", response_model=Token)
async def login(user: UserLogin):
    """
    Authenticate a user using username and password.
    Returns a JWT access token if credentials are valid.
    """
    stored_user = FAKE_DB.get(user.username)
    if not stored_user or not verify_password(user.password, stored_user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials."
        )

    # Atualiza status online
    ONLINE_USERS[user.username] = {"last_active": datetime.utcnow()}

    # Gera token JWT
    access_token = create_access_token(data={"sub": user.username})
    autenticidade_logger.info(f"[LOGIN_OK] Usuário '{user.username}' autenticado. Hash verificado: {stored_user['password']}")
    return {"access_token": access_token, "token_type": "bearer"}

# -------------------------
# Lista de Usuários Online
# -------------------------

@router.get("/online", response_model=List[OnlineUser])
async def list_online_users():
    """
    Return a list of users currently online.
    """
    return [
        OnlineUser(username=username, last_active=data["last_active"])
        for username, data in ONLINE_USERS.items()
    ]
