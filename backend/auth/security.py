"""
security.py
------------

Implements secure password handling and verification logic.  
This module uses bcrypt hashing (via Passlib) to securely store and verify user passwords.

Functions:
    - hash_password(password): Generates a bcrypt hash for a given password.
    - verify_password(plain_password, hashed_password): Verifies a password against a stored hash.
"""


from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    """Gera o hash de uma senha usando bcrypt."""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica se a senha está correta."""
    return pwd_context.verify(plain_password, hashed_password)
