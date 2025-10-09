"""
messages.py (versão final)
--------------------------

Gerencia toda a lógica de persistência e recuperação de mensagens no CipherTalk.

Implementa:
- Armazenamento seguro de mensagens criptografadas (IDEA + RSA).
- Consulta de histórico entre usuários e grupos.
- Descriptografia completa local (auditoria e verificação).
- Entrega de mensagens offline.
- Logs detalhados para todas as operações.

Todos os dados são armazenados criptografados no banco.
A descriptografia ocorre apenas no cliente, com chave privada local.
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
# Armazenar mensagem
# ======================================================
def save_message(
    db: Session,
    sender: str,
    receiver: str | None,
    group: str | None,
    content_encrypted: str,
    key_encrypted: str,
) -> None:
    """
    Armazena uma nova mensagem criptografada no banco.

    Args:
        db (Session): Sessão ativa do SQLAlchemy.
        sender (str): Nome do remetente.
        receiver (str | None): Nome do destinatário (para mensagens privadas).
        group (str | None): Nome do grupo (para mensagens em grupo).
        content_encrypted (str): Mensagem cifrada (IDEA).
        key_encrypted (str): Chave simétrica cifrada (RSA).
    """
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
        dblog.info(
            f"[MSG_SAVE] Mensagem armazenada | de={sender} para={'grupo '+group if group else receiver} | ts={msg.timestamp}"
        )
    except Exception as e:
        db.rollback()
        dblog.error(f"[MSG_SAVE_FAIL] Erro ao salvar mensagem: {e}")
        raise e


# ======================================================
# Consultar histórico entre dois usuários
# ======================================================
def get_chat_history(db: Session, user1: str, user2: str) -> list[dict]:
    """
    Recupera o histórico de mensagens entre dois usuários (criptografadas).

    Args:
        db (Session): Sessão ativa.
        user1 (str): Primeiro usuário.
        user2 (str): Segundo usuário.

    Returns:
        list[dict]: Lista de mensagens (criptografadas).
    """
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
        return [
            {
                "from": db.query(User).get(m.sender_id).username,
                "to": db.query(User).get(m.receiver_id).username if m.receiver_id else None,
                "content_encrypted": m.content_encrypted,
                "key_encrypted": m.key_encrypted,
                "timestamp": str(m.timestamp),
            }
            for m in msgs
        ]
    except Exception as e:
        dblog.error(f"[MSG_HISTORY_FAIL] Falha ao obter histórico: {e}")
        raise e


# ======================================================
# Entregar mensagens pendentes (usuário offline)
# ======================================================
def get_pending_messages(db: Session, username: str) -> list[Message]:
    """
    Retorna todas as mensagens pendentes para o usuário informado.

    Args:
        db (Session): Sessão SQLAlchemy.
        username (str): Nome do usuário destino.

    Returns:
        list[Message]: Mensagens pendentes.
    """
    try:
        user = db.query(User).filter_by(username=username).first()
        msgs = db.query(Message).filter(Message.receiver_id == user.id).all()
        dblog.info(f"[MSG_PENDING] {len(msgs)} mensagens pendentes para {username}")
        return msgs
    except Exception as e:
        dblog.error(f"[MSG_PENDING_FAIL] {e}")
        return []


def delete_message(db: Session, message_id: int) -> None:
    """Exclui uma mensagem específica do banco."""
    try:
        msg = db.query(Message).get(message_id)
        if msg:
            db.delete(msg)
            db.commit()
            dblog.info(f"[MSG_DELETE] Mensagem {message_id} removida.")
    except Exception as e:
        db.rollback()
        dblog.error(f"[MSG_DELETE_FAIL] {e}")


# ======================================================
# Descriptografia local (auditoria)
# ======================================================
def decrypt_stored_message(
    encrypted_key_b64: str, encrypted_content: str, private_key_pem: bytes
) -> str:
    """
    Descriptografa uma mensagem armazenada usando RSA + IDEA (modo CBC).

    Args:
        encrypted_key_b64 (str): Chave simétrica IDEA cifrada (RSA).
        encrypted_content (str): Conteúdo cifrado (IDEA).
        private_key_pem (bytes): Chave privada RSA do destinatário.

    Returns:
        str: Mensagem descriptografada (texto puro).
    """
    try:
        # Decodifica a chave simétrica
        encrypted_key = base64.b64decode(encrypted_key_b64)
        idea_key = decrypt_with_rsa(private_key_pem, encrypted_key)

        # Decifra a mensagem
        mensagem = decrypt_message(encrypted_content, idea_key)

        dblog.info("[MSG_DECRYPT] Mensagem descriptografada com sucesso (auditoria local).")
        return mensagem
    except Exception as e:
        dblog.error(f"[MSG_DECRYPT_FAIL] Falha na descriptografia: {e}")
        raise e


# ======================================================
# Limpeza e manutenção
# ======================================================
def delete_old_messages(db: Session, days: int = 30):
    """
    Remove mensagens mais antigas que o período informado.

    Args:
        db (Session): Sessão SQLAlchemy.
        days (int): Quantidade de dias para retenção.
    """
    try:
        limite = datetime.datetime.utcnow() - datetime.timedelta(days=days)
        count = db.query(Message).filter(Message.timestamp < limite).delete()
        db.commit()
        dblog.info(f"[MSG_CLEANUP] {count} mensagens antigas removidas (> {days} dias).")
    except Exception as e:
        db.rollback()
        dblog.error(f"[MSG_CLEANUP_FAIL] {e}")
