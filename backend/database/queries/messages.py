"""
messages.py
-----------

Funções de consulta para recuperar mensagens do banco de dados.
"""

from sqlalchemy.orm import Session
from backend.auth.models import Message, User


def get_user_messages(db: Session, username: str):
    """
    Retrieve all messages (sent and received) for a specific user.
    """
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return []

    sent = (
        db.query(Message)
        .filter(Message.sender_id == user.id)
        .order_by(Message.timestamp.desc())
        .all()
    )
    received = (
        db.query(Message)
        .filter(Message.receiver_id == user.id)
        .order_by(Message.timestamp.desc())
        .all()
    )

    return {"sent": sent, "received": received}


def get_offline_messages(db: Session, username: str):
    """
    Retrieve only undelivered messages for a specific user.
    """
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return []

    return (
        db.query(Message)
        .filter(Message.receiver_id == user.id)
        .order_by(Message.timestamp.desc())
        .all()
    )
