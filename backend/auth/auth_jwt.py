"""
auth_jwt.py
------------

Gerencia a geração e validação de tokens JWT para autenticação segura.
"""

import os
import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
from backend.utils.logger_config import autenticidade_logger

load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", 30))

if not SECRET_KEY:
    raise EnvironmentError("❌ JWT_SECRET_KEY não definido no .env")

def create_access_token(username: str) -> str:
    """Generate a JWT for a given username with expiration."""
    expire = datetime.utcnow() + timedelta(minutes=EXPIRE_MINUTES)
    payload = {"sub": username, "exp": expire}
    autenticidade_logger.info(
        f"[JWT_GERADO] Token criado para '{username}'.\n"
        f" • Token JWT: {jwt.encode(payload, SECRET_KEY, algorithm='HS256')}\n"
        f" • Payload: {payload}\n"
        f" • SECRET_KEY fingerprint: {SECRET_KEY[:12]}..."
    )
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_access_token(token: str) -> str:
    """Validate JWT and return the username if valid."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        autenticidade_logger.info(f"[JWT_VALIDO] Token válido para '{payload.get('sub')}'. Payload: {payload}")
        return payload.get("sub")
    except jwt.ExpiredSignatureError:
        raise ValueError("❌ Token expirado. Faça login novamente.")
    except jwt.InvalidTokenError:
        raise ValueError("❌ Token inválido.")