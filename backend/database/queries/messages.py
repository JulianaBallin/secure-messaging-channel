# ==========================================
# backend/database/queries/messages.py
# ==========================================
"""
messages.py
------------

Gerencia toda a lógica de persistência e recuperação de mensagens no CipherTalk.

- Armazenamento seguro (IDEA + RSA)
- Histórico entre usuários e grupos
- Entrega offline
- Descriptografia local para auditoria
- Logs de auditoria detalhados
"""

import datetime
import base64
from sqlalchemy.orm import Session
from sqlalchemy import or_
from backend.auth.models import User, Message, Group
from backend.utils.logger_config import database_logger as dblog
from backend.crypto.idea_manager import decrypt_message
from backend.crypto.rsa_manager import decrypt_with_rsa


# ======================================================
# Armazenar mensagem criptografada
# ======================================================
def save_message(db: Session, sender: str, receiver: str | None, group: str | None,
                 content_encrypted: str, key_encrypted: str):
    """Armazena mensagem criptografada (privada ou de grupo)."""
    try:
        sender_user = db.query(User).filter_by(username=sender).first()
        receiver_user = db.query(User).filter_by(username=receiver).first() if receiver else None
        group_entity = db.query(Group).filter_by(name=group).first() if group else None

        msg = Message(
            sender_id=sender_user.id,
            receiver_id=receiver_user.id if receiver_user else None,
            group_id=group_entity.id if group_entity else None,
            content_encrypted=content_encrypted,
            key_encrypted=key_encrypted,
            timestamp=datetime.datetime.utcnow(),
        )
        db.add(msg)
        db.commit()
        dblog.info(f"[MSG_SAVE] Mensagem salva: de={sender} → {receiver or 'grupo ' + group}")
    except Exception as e:
        db.rollback()
        dblog.error(f"[MSG_SAVE_FAIL] {e}")
        raise e


# ======================================================
# Histórico entre usuários
# ======================================================
def get_chat_history(db: Session, user1: str, user2: str):
    """Retorna o histórico de mensagens entre dois usuários (criptografadas)."""
    try:
        u1 = db.query(User).filter_by(username=user1).first()
        u2 = db.query(User).filter_by(username=user2).first()
        msgs = (
            db.query(Message)
            .filter(
                or_(
                    (Message.sender_id == u1.id) & (Message.receiver_id == u2.id),
                    (Message.sender_id == u2.id) & (Message.receiver_id == u1.id),
                )
            )
            .order_by(Message.timestamp.asc())
            .all()
        )
        dblog.info(f"[MSG_HISTORY] {len(msgs)} mensagens entre {user1} e {user2}")
        return msgs
    except Exception as e:
        dblog.error(f"[MSG_HISTORY_FAIL] {e}")
        return []


# ======================================================
# Mensagens pendentes (usuário offline)
# ======================================================
def get_pending_messages(db: Session, username: str):
    """Retorna todas as mensagens pendentes para o usuário informado."""
    try:
        user = db.query(User).filter_by(username=username).first()
        msgs = db.query(Message).filter(Message.receiver_id == user.id).all()
        dblog.info(f"[MSG_PENDING] {len(msgs)} mensagens pendentes para {username}")
        return msgs
    except Exception as e:
        dblog.error(f"[MSG_PENDING_FAIL] {e}")
        return []


# ======================================================
# Descriptografia local para auditoria
# ======================================================
def decrypt_stored_message(encrypted_key_b64: str, encrypted_content: str, private_key_pem: bytes):
    """Descriptografa uma mensagem armazenada localmente (IDEA + RSA)."""
    try:
        encrypted_key = base64.b64decode(encrypted_key_b64)
        idea_key = decrypt_with_rsa(private_key_pem, encrypted_key)
        mensagem = decrypt_message(encrypted_content, idea_key)
        dblog.info("[MSG_DECRYPT] Mensagem descriptografada (auditoria local).")
        return mensagem
    except Exception as e:
        dblog.error(f"[MSG_DECRYPT_FAIL] {e}")
        raise e
