"""
models.py
----------

SQLAlchemy models for authentication and messaging.
Covers users, groups, group membership, and messages (private or group).

Rules:
- Private message: receiver_id != NULL and group_id == NULL
- Group message:   receiver_id == NULL and group_id != NULL
"""

from __future__ import annotations
from datetime import datetime
from sqlalchemy import LargeBinary

from sqlalchemy import (
    Column, Integer, String, DateTime, Text, ForeignKey,
    CheckConstraint, UniqueConstraint, Index
)
from sqlalchemy.orm import relationship, Mapped, mapped_column

from backend.database.connection import Base


class User(Base):
    """User entity with unique username and password hash."""
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    sent_messages: Mapped[list["Message"]] = relationship(
        "Message", back_populates="sender", foreign_keys="Message.sender_id"
    )
    received_messages: Mapped[list["Message"]] = relationship(
        "Message", back_populates="receiver", foreign_keys="Message.receiver_id"
    )
    groups: Mapped[list["GroupMember"]] = relationship("GroupMember", back_populates="user")

    def __repr__(self) -> str:
        return f"User(id={self.id!r}, username={self.username!r})"


class Group(Base):
    """Group entity for multi-user conversations."""
    __tablename__ = "groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    members: Mapped[list["GroupMember"]] = relationship("GroupMember", back_populates="group")
    messages: Mapped[list["Message"]] = relationship("Message", back_populates="group")

    def __repr__(self) -> str:
        return f"Group(id={self.id!r}, name={self.name!r})"


class GroupMember(Base):
    """Join table between users and groups, with uniqueness per (user_id, group_id)."""
    __tablename__ = "group_members"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id", ondelete="CASCADE"), nullable=False, index=True)
    joined_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="groups")
    group: Mapped["Group"] = relationship("Group", back_populates="members")

    __table_args__ = (
        UniqueConstraint("user_id", "group_id", name="uq_group_members_user_group"),
    )

    def __repr__(self) -> str:
        return f"GroupMember(user_id={self.user_id!r}, group_id={self.group_id!r})"


class Message(Base):
    """
    Message entity. Can be private (receiver_id set) or group (group_id set).
    Exactly one of (receiver_id, group_id) must be non-null.
    """
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    receiver_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    group_id: Mapped[int | None] = mapped_column(ForeignKey("groups.id", ondelete="CASCADE"), nullable=True, index=True)

    content_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True, nullable=False)

    sender: Mapped["User"] = relationship("User", back_populates="sent_messages", foreign_keys=[sender_id])
    receiver: Mapped["User"] = relationship("User", back_populates="received_messages", foreign_keys=[receiver_id])
    group: Mapped["Group"] = relationship("Group", back_populates="messages")

    __table_args__ = (
        # ensure XOR-like rule: exactly one target (private OR group)
        CheckConstraint(
            "(receiver_id IS NOT NULL AND group_id IS NULL) OR "
            "(receiver_id IS NULL AND group_id IS NOT NULL)",
            name="ck_message_private_or_group"
        ),
        Index("ix_messages_sender_ts", "sender_id", "timestamp"),
    )

    def __repr__(self) -> str:
        target = f"receiver_id={self.receiver_id!r}" if self.receiver_id else f"group_id={self.group_id!r}"
        return f"Message(id={self.id!r}, sender_id={self.sender_id!r}, {target}, ts={self.timestamp!r})"
