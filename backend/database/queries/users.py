"""
users.py
--------

Funções de consulta relacionadas à tabela de usuários.
"""

from sqlalchemy.orm import Session
from backend.auth.models import User
from backend.server.server import ONLINE_USERS


def get_all_users(db: Session):
    """
    Return a list of all users with their online/offline status.
    """
    users = db.query(User).all()
    return [
        {
            "id": user.id,
            "username": user.username,
            "created_at": user.created_at,
            "online": user.username in ONLINE_USERS,
        }
        for user in users
    ]


def get_user_by_username(db: Session, username: str):
    """
    Return a single user object by username.
    """
    return db.query(User).filter(User.username == username).first()


def get_user_full_info(db: Session, username: str):
    """
    Return all columns for a given username (SELECT *).
    """
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return None

    return {
        "id": user.id,
        "username": user.username,
        "created_at": user.created_at,
        "public_key": user.public_key.decode() if user.public_key else None,
        "online": user.username in ONLINE_USERS
    }
