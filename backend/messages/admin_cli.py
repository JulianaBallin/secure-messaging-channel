"""
admin_cli.py (mensagens)
------------------------

CLI administrativo para testar criptografia e armazenamento local de mensagens.
Uso apenas para depuração no ambiente do servidor.
"""

from sqlalchemy.orm import Session
from backend.database.connection import SessionLocal
from backend.auth.models import User, Message
from backend.crypto.idea_manager import generate_idea_key, encrypt_message
from backend.crypto.rsa_manager import encrypt_with_rsa

def start_conversation(sender_username: str):
    db: Session = SessionLocal()

    users = db.query(User).filter(User.username != sender_username).all()
    if not users:
        print("⚠️ Nenhum outro usuário cadastrado.")
        return

    print("\n=== 👥 Usuários disponíveis ===")
    for u in users:
        print(f"- {u.username}")

    receiver_username = input("👉 Escolha o destinatário: ").strip()
    receiver = db.query(User).filter(User.username == receiver_username).first()
    if not receiver:
        print("❌ Usuário não encontrado.")
        return

    message_text = input("💬 Digite a mensagem: ").strip()
    idea_key = generate_idea_key()
    encrypted_message = encrypt_message(message_text, idea_key)
    encrypted_idea_key = encrypt_with_rsa(receiver.public_key, idea_key)

    sender = db.query(User).filter(User.username == sender_username).first()
    message = Message(
        sender_id=sender.id,
        receiver_id=receiver.id,
        content_encrypted=encrypted_message,
        encrypted_key=encrypted_idea_key  # futura implementação
    )
    db.add(message)
    db.commit()

    print("✅ Mensagem criptografada e armazenada com sucesso!")


def read_inbox(current_user: str):
    db: Session = SessionLocal()
    user = db.query(User).filter(User.username == current_user).first()

    messages = db.query(Message).filter(Message.receiver_id == user.id).all()
    if not messages:
        print("📭 Nenhuma mensagem recebida.")
        return

    print("\n=== 📥 Caixa de Entrada ===")
    for m in messages:
        sender = db.query(User).filter(User.id == m.sender_id).first()
        print(f"📨 De: {sender.username}")
        print(f"🔐 Conteúdo criptografado: {m.content_encrypted}")
        print(f"🗝️ Chave IDEA criptografada: {getattr(m, 'encrypted_key', 'não armazenada')}")
        print()
