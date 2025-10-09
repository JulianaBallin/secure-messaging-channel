"""
models.py 
---------

Modelos de dados do CipherTalk — compatíveis com SQLAlchemy 2.0.

Inclui:
- Usuários com senhas hash e chaves públicas RSA.
- Mensagens privadas e de grupo (armazenadas criptografadas).
- Grupos com controle de membros e administrador.
- Integridade garantida via constraints e cascatas.
"""

from __future__ import annotations
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, DateTime, Text, ForeignKey,
    LargeBinary, CheckConstraint, UniqueConstraint, Index, Boolean
)
from sqlalchemy.orm import relationship, Mapped, mapped_column
from backend.database.connection import Base


# ======================================================
# Usuário
# ======================================================
class User(Base):
    """Representa um usuário registrado no sistema CipherTalk."""
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=True)
    is_online: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    # Relacionamentos
    sent_messages: Mapped[list["Message"]] = relationship(
        "Message",
        back_populates="sender",
        foreign_keys="Message.sender_id",
        cascade="all, delete-orphan",
    )

    received_messages: Mapped[list["Message"]] = relationship(
        "Message",
        back_populates="receiver",
        foreign_keys="Message.receiver_id",
        cascade="all, delete-orphan",
    )

    group_memberships: Mapped[list["GroupMember"]] = relationship(
        "GroupMember", back_populates="user", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<User(username='{self.username}', online={self.is_online})>"


# ======================================================
# Grupo de usuários
# ======================================================
class Group(Base):
    """Entidade que representa um grupo de conversa entre múltiplos usuários."""
    __tablename__ = "groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    admin_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    # Relacionamentos
    admin: Mapped["User"] = relationship("User")
    members: Mapped[list["GroupMember"]] = relationship(
        "GroupMember", back_populates="group", cascade="all, delete-orphan"
    )
    messages: Mapped[list["Message"]] = relationship(
        "Message", back_populates="group", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Group(name='{self.name}', admin_id={self.admin_id})>"


# ======================================================
# Associação de membros a grupos
# ======================================================
class GroupMember(Base):
    """Tabela de associação entre usuários e grupos."""
    __tablename__ = "group_members"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    group_id: Mapped[int] = mapped_column(
        ForeignKey("groups.id", ondelete="CASCADE"), nullable=False, index=True
    )
    joined_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    # Relacionamentos
    user: Mapped["User"] = relationship("User", back_populates="group_memberships")
    group: Mapped["Group"] = relationship("Group", back_populates="members")

    __table_args__ = (
        UniqueConstraint("user_id", "group_id", name="uq_group_members_user_group"),
    )

    def __repr__(self) -> str:
        return f"<GroupMember(user_id={self.user_id}, group_id={self.group_id})>"


# ======================================================
# Mensagem
# ======================================================
class Message(Base):
    """
    Entidade de mensagem — pode ser privada (entre 2 usuários)
    ou em grupo (vários usuários).

    Somente uma das colunas receiver_id ou group_id deve estar definida.
    O conteúdo e a chave simétrica são armazenados cifrados.
    """
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    sender_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    receiver_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )
    group_id: Mapped[int | None] = mapped_column(
        ForeignKey("groups.id", ondelete="CASCADE"), nullable=True, index=True
    )

    content_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    key_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True, nullable=False)

    # Relacionamentos
    sender: Mapped["User"] = relationship(
        "User", back_populates="sent_messages", foreign_keys=[sender_id]
    )
    receiver: Mapped["User"] = relationship(
        "User", back_populates="received_messages", foreign_keys=[receiver_id]
    )
    group: Mapped["Group"] = relationship("Group", back_populates="messages")

    __table_args__ = (
        CheckConstraint(
            "(receiver_id IS NOT NULL AND group_id IS NULL) OR "
            "(receiver_id IS NULL AND group_id IS NOT NULL)",
            name="ck_message_private_or_group",
        ),
        Index("ix_messages_sender_ts", "sender_id", "timestamp"),
    )

    def __repr__(self) -> str:
        destino = f"receiver_id={self.receiver_id}" if self.receiver_id else f"group_id={self.group_id}"
        return f"<Message(sender={self.sender_id}, {destino}, ts={self.timestamp})>"
