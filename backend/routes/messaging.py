"""
messaging.py
------------

Defines API routes for sending, receiving, and storing encrypted messages.  
This module uses the IDEA algorithm for message encryption/decryption and keeps 
all communication internal to the CipherTalk system (identified by usernames only).

Endpoints:
    - POST /messages/send: Send an encrypted message from one user to another.
    - GET /messages/inbox/{username}: Retrieve all messages for a given user.
"""

from datetime import datetime
from typing import List

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from backend.crypto.idea_manager import encrypt_message, decrypt_message

router = APIRouter()

# Simulated message database
MESSAGES = []

# -------------------------
# 📦 Modelos Pydantic
# -------------------------

class MessageCreate(BaseModel):
    sender: str
    receiver: str
    content: str

class MessageResponse(BaseModel):
    sender: str
    receiver: str
    content_encrypted: str
    content_decrypted: str
    timestamp: datetime

# -------------------------
# 📨 Envio de Mensagem Criptografada
# -------------------------

@router.post("/send", status_code=201)
async def send_message(msg: MessageCreate):
    """
    Encrypts and stores a message from sender to receiver.
    Both sender and receiver must exist as registered usernames.
    """
    if msg.sender == msg.receiver:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Sender and receiver cannot be the same user."
        )

    # Criptografa mensagem com IDEA
    encrypted = encrypt_message(msg.content)
    timestamp = datetime.utcnow()

    # Armazena mensagem
    MESSAGES.append({
        "sender": msg.sender,
        "receiver": msg.receiver,
        "encrypted": encrypted,
        "timestamp": timestamp
    })

    return {
        "message": "✅ Message sent successfully.",
        "sender": msg.sender,
        "receiver": msg.receiver,
        "timestamp": timestamp.isoformat()
    }

# -------------------------
# 📬 Caixa de Entrada (Inbox)
# -------------------------

@router.get("/inbox/{username}", response_model=List[MessageResponse])
async def get_inbox(username: str):
    """
    Retrieve all messages for a given username.
    Returns both the encrypted content and the decrypted version for display.
    """
    user_messages = [
        m for m in MESSAGES if m["receiver"] == username
    ]

    if not user_messages:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No messages found for user '{username}'."
        )

    return [
        MessageResponse(
            sender=m["sender"],
            receiver=m["receiver"],
            content_encrypted=m["encrypted"],
            content_decrypted=decrypt_message(m["encrypted"]),
            timestamp=m["timestamp"]
        )
        for m in user_messages
    ]
