"""
cli.py (mensagens)
------------------

Implements peer-to-peer encrypted messaging between two users using RSA + IDEA.
"""

from sqlalchemy.orm import Session
from backend.database.connection import SessionLocal
from backend.auth.models import User, Message
from backend.crypto.idea_manager import generate_idea_key, encrypt_message, decrypt_message
from backend.crypto.rsa_manager import encrypt_with_rsa, decrypt_with_rsa

def start_conversation(sender_username: str):
    """Initiate an encrypted conversation between two users."""
    db: Session = SessionLocal()

    users = db.query(User).filter(User.username != sender_username).all()
    if not users:
        print("⚠️ Nenhum outro usuário cadastrado para conversar.")
        return

    print("\n=== 👥 Usuários disponíveis ===")
    for u in users:
        print(f"- {u.username}")

    receiver_username = input("👉 Escolha o usuário com quem deseja conversar: ").strip()
    receiver = db.query(User).filter(User.username == receiver_username).first()

    if not receiver:
        print("❌ Usuário não encontrado.")
        return

    message_text = input("💬 Digite sua mensagem: ").strip()

    # ✅ 1. Gerar chave IDEA
    idea_key = generate_idea_key()

    # ✅ 2. Criptografar a mensagem com IDEA
    encrypted_message = encrypt_message(message_text, idea_key)

    # ✅ 3. Criptografar a chave IDEA com a chave pública do destinatário
    encrypted_idea_key = encrypt_with_rsa(receiver.public_key, idea_key)

    # ✅ 4. Salvar no banco
    sender = db.query(User).filter(User.username == sender_username).first()
    message = Message(
        sender_id=sender.id,
        receiver_id=receiver.id,
        content_encrypted=encrypted_message
    )
    db.add(message)
    db.commit()

    print("✅ Mensagem enviada com sucesso e armazenada de forma segura!")

def read_inbox(current_user: str):
    """Read and decrypt all messages for the current user."""
    db: Session = SessionLocal()
    user = db.query(User).filter(User.username == current_user).first()

    messages = db.query(Message).filter(Message.receiver_id == user.id).all()
    if not messages:
        print("📭 Nenhuma mensagem recebida.")
        return

    print("\n=== 📥 Caixa de Entrada ===")
    for m in messages:
        sender = db.query(User).filter(User.id == m.sender_id).first()
        # Aqui precisaríamos da chave IDEA criptografada salva junto (faremos na versão 2)
        print(f"📨 De: {sender.username}")
        print(f"🔐 Conteúdo criptografado: {m.content_encrypted}")
        print("⚠️ (Descriptografia completa será implementada junto ao armazenamento da chave IDEA)\n")
