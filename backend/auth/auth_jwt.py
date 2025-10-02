"""
auth_jwt.py
------------

Handles JWT token generation and validation for secure authentication.
"""

import os
import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", 30))

if not SECRET_KEY:
    raise EnvironmentError("❌ JWT_SECRET_KEY não definido no .env")

def create_access_token(username: str) -> str:
    """Generate a JWT for a given username with expiration."""
    expire = datetime.utcnow() + timedelta(minutes=EXPIRE_MINUTES)
    payload = {"sub": username, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_access_token(token: str) -> str:
    """Validate JWT and return the username if valid."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload.get("sub")
    except jwt.ExpiredSignatureError:
        raise ValueError("❌ Token expirado. Faça login novamente.")
    except jwt.InvalidTokenError:
        raise ValueError("❌ Token inválido.")
