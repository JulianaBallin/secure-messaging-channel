"""
security.py
------------

Implements secure password hashing and verification using bcrypt.
"""

from passlib.context import CryptContext

# Configura o contexto de hashing seguro
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    """Generate a secure bcrypt hash for the given password."""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify if the provided password matches the stored hash."""
    return pwd_context.verify(plain_password, hashed_password)
