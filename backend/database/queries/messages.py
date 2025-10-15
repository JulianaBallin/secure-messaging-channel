# ==========================================
# backend/database/queries/messages.py
# ==========================================
"""
messages.py 
-----------

Versão de teste para auditoria e persistência sem dependências de criptografia.

Objetivo: permitir uso de run_queries.py para verificar cadastro e leitura
de usuários, grupos e mensagens sem precisar do subsistema de criptografia.
"""

import datetime
from sqlalchemy.orm import Session
from sqlalchemy import or_
from backend.auth.models import User, Message, Group
from backend.utils.logger_config import database_logger as dblog


# ======================================================
# Armazenar mensagem (sem criptografia)
# ======================================================
def save_message(db: Session, sender: str, receiver: str | None, group: str | None,
                 content_encrypted: str, key_encrypted: str):
    """Armazena mensagem (texto puro, para fins de teste)."""
    try:
        sender_user = db.query(User).filter_by(username=sender).first()
        receiver_user = db.query(User).filter_by(username=receiver).first() if receiver else None
        group_entity = db.query(Group).filter_by(name=group).first() if group else None

        msg = Message(
            sender_id=sender_user.id,
            receiver_id=receiver_user.id if receiver_user else None,
            group_id=group_entity.id if group_entity else None,
            content_encrypted=content_encrypted or "(mensagem de teste)",
            key_encrypted=key_encrypted or "(chave nula)",
            timestamp=datetime.datetime.utcnow(),
        )
        db.add(msg)
        db.commit()
        dblog.info(f"[MSG_SAVE] Mensagem salva (teste): de={sender} → {receiver or group}")
    except Exception as e:
        db.rollback()
        dblog.error(f"[MSG_SAVE_FAIL] {e}")
        raise e


# ======================================================
# Histórico entre usuários
# ======================================================
def get_chat_history(db: Session, user1: str, user2: str):
    """Retorna o histórico de mensagens entre dois usuários."""
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
# Mensagens pendentes
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
# Descriptografia simulada
# ======================================================
def decrypt_stored_message(encrypted_key_b64: str, encrypted_content: str, private_key_pem: bytes = b""):
    """
    Simula a descriptografia apenas para auditoria de estrutura.
    Retorna o conteúdo de texto simples.
    """
    try:
        dblog.info("[MSG_DECRYPT_SIM] Modo de auditoria sem criptografia real.")
        return f"(Simulação de descriptografia) → {encrypted_content}"
    except Exception as e:
        dblog.error(f"[MSG_DECRYPT_FAIL] {e}")
        raise e
