"""
messages.py — CRUD e operações seguras da tabela 'messages'
-----------------------------------------------------------

Inclui:
- CRUD tradicional (create, read, update, delete)
- Envio seguro de mensagens (IDEA + RSA)
- Suporte a comunicação entre pares e em grupos
"""
from hashlib import sha256
from backend.auth.models import Message, User, Group
from backend.utils.logger_config import database_logger as dblog
from backend.crypto.idea_manager import IDEAManager
from backend.crypto.rsa_manager import RSAManager
from backend.utils.db_utils import safe_db_operation
from datetime import datetime, timezone, timedelta
import os
from cryptography.hazmat.primitives import serialization

manaus_tz = timezone(timedelta(hours=-4))

# ======================================================
# 🧱 CREATE (Mensagem simples)
# ======================================================
@safe_db_operation
def create_message(db, sender: str, receiver: str | None, group: str | None,
                   content_encrypted: str, key_encrypted: str):
    """Insere mensagem já cifrada (fluxo manual)."""
    sender_user = db.query(User).filter_by(username=sender).first()
    receiver_user = db.query(User).filter_by(username=receiver).first() if receiver else None
    group_obj = db.query(Group).filter_by(name=group).first() if group else None

    msg = Message(
        sender_id=sender_user.id,
        receiver_id=receiver_user.id if receiver_user else None,
        group_id=group_obj.id if group_obj else None,
        content_encrypted=content_encrypted,
        key_encrypted=key_encrypted,
        timestamp=datetime.now(manaus_tz),
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)
    dblog.info(f"[CREATE_MESSAGE] {sender} → {receiver or group}")
    return msg


# ======================================================
# 💬 Envio seguro de mensagem privada (IDEA + RSA)
# ======================================================
@safe_db_operation
def send_secure_message(db, sender: str, receiver: str, plaintext: str):
    """Criptografa mensagem privada entre dois usuários e armazena."""
    content_hash = sha256(plaintext.encode()).hexdigest()
    
    # Carrega chave privada do remetente
    private_key_path = os.path.join("keys", f"{sender}_private.pem")
    private_key = RSAManager.carregar_chave_privada(private_key_path)

    # Gera assinatura digital (RSA-SHA256)
    assinatura = RSAManager.assinar_mensagem(plaintext.encode(), private_key)
    
    sender_user = db.query(User).filter_by(username=sender).first()
    receiver_user = db.query(User).filter_by(username=receiver).first()
    if not sender_user or not receiver_user:
        raise ValueError("Usuário remetente ou destinatário não encontrado.")

    # 🔐 Garante que a chave pública seja string PEM
    public_key_dest = (
        receiver_user.public_key.decode()
        if isinstance(receiver_user.public_key, bytes)
        else receiver_user.public_key
    )

    mgr = IDEAManager()
    conteudo_cifrado, chave_sessao_cifrada = mgr.cifrar_para_chat(
        plaintext, sender, receiver, public_key_dest
    )

    msg = Message(
        sender_id=sender_user.id,
        receiver_id=receiver_user.id,
        content_encrypted=conteudo_cifrado,
        key_encrypted=chave_sessao_cifrada,
        signature=assinatura,
        content_hash=content_hash,
        timestamp=datetime.now(manaus_tz),
    )
    db.add(msg)
    db.commit()
    dblog.info(f"[SEND_SECURE_PRIVATE] {sender} → {receiver}")
    return msg


# ======================================================
# 👥 Envio seguro de mensagem de grupo
# ======================================================
@safe_db_operation
def send_secure_group_message(db, sender: str, group_name: str, plaintext: str):
    """Criptografa mensagem para grupo (cada membro usa sua chave pública)."""
    sender_user = db.query(User).filter_by(username=sender).first()
    group = db.query(Group).filter_by(name=group_name).first()
    if not sender_user or not group:
        raise ValueError("Usuário ou grupo não encontrado.")

    # Itera sobre cada membro do grupo e gera uma cópia cifrada para cada
    membros = [m.user for m in group.members]
    if not membros:
        raise ValueError("Nenhum membro no grupo.")

    mgr = IDEAManager()
    msgs_armazenadas = []

    for membro in membros:
        if membro.id == sender_user.id:
            continue  # não envia para si mesmo

        # 🔐 Garante que a chave pública seja string PEM
        public_key_dest = (
            membro.public_key.decode()
            if isinstance(membro.public_key, bytes)
            else membro.public_key
        )

        conteudo_cifrado, chave_sessao_cifrada = mgr.cifrar_para_chat(
            plaintext, sender, membro.username, public_key_dest
        )

        # Inclui o receiver_id para cada membro
        msg = Message(
            sender_id=sender_user.id,
            group_id=group.id,
            receiver_id=membro.id,
            content_encrypted=conteudo_cifrado,
            key_encrypted=chave_sessao_cifrada,
            timestamp=datetime.now(manaus_tz),
        )
        db.add(msg)
        msgs_armazenadas.append(msg)

    db.commit()
    dblog.info(f"[SEND_SECURE_GROUP] {sender} → grupo {group_name} ({len(msgs_armazenadas)} cópias cifradas)")
    return msgs_armazenadas


# ======================================================
# 🔎 READ (Histórico e mensagens de grupo)
# ======================================================
def get_chat_history(db, user1: str, user2: str):
    u1 = db.query(User).filter_by(username=user1).first()
    u2 = db.query(User).filter_by(username=user2).first()
    if not u1 or not u2:
        return []
    msgs = (
        db.query(Message)
        .filter(
            ((Message.sender_id == u1.id) & (Message.receiver_id == u2.id))
            | ((Message.sender_id == u2.id) & (Message.receiver_id == u1.id))
        )
        .order_by(Message.timestamp.asc())
        .all()
    )
    dblog.info(f"[MSG_HISTORY] {len(msgs)} mensagens entre {user1} e {user2}")
    return msgs


def list_group_messages(db, group_name: str):
    group = db.query(Group).filter_by(name=group_name).first()
    if not group:
        return []
    return (
        db.query(Message)
        .filter_by(group_id=group.id)
        .order_by(Message.timestamp.asc())
        .all()
    )

# ======================================================
# 🔓 RECEIVE — Decifrar mensagens recebidas
# ======================================================
@safe_db_operation
def receive_secure_messages(db, username: str):
    """
    Decifra e exibe todas as mensagens criptografadas recebidas por um usuário.
    Utiliza a chave privada armazenada em 'keys/<username>_private.pem'.
    """
    user = db.query(User).filter_by(username=username).first()
    if not user:
        raise ValueError("Usuário não encontrado.")

    msgs = db.query(Message).filter(Message.receiver_id == user.id).all()
    if not msgs:
        print("📭 Nenhuma mensagem recebida.")
        return []

    private_key_path = os.path.join("keys", f"{username}_private.pem")
    if not os.path.exists(private_key_path):
        raise FileNotFoundError(f"Chave privada não encontrada em {private_key_path}")

    # Objeto de chave, não string PEM
    private_key = RSAManager.carregar_chave_privada(private_key_path)
    
    mgr = IDEAManager()
    mensagens_decifradas = []

    for msg in msgs:
        remetente = db.query(User).get(msg.sender_id).username
        try:
            # 1️⃣ Decifra o conteúdo com IDEA - passe o OBJETO
            texto = mgr.decifrar_do_chat(msg.content_encrypted, msg.key_encrypted, username, private_key)

            # 2️⃣ Verifica integridade (hash SHA256)
            content_hash_calc = sha256(texto.encode()).hexdigest()
            if msg.content_hash and msg.content_hash != content_hash_calc:
                raise ValueError("⚠️ Hash mismatch: conteúdo pode ter sido alterado!")

            # 3️⃣ Verifica assinatura digital RSA-SHA256
            sender_user = db.query(User).get(msg.sender_id)
            if msg.signature and sender_user.public_key:
                try:
                    public_key = serialization.load_pem_public_key(sender_user.public_key)
                    RSAManager.verificar_assinatura(texto.encode(), msg.signature, public_key)
                    print(f"🔏 Assinatura válida de {sender_user.username}.")
                except Exception as e:
                    print(f"⚠️ Assinatura inválida de {sender_user.username}: {e}")

            # 4️⃣ Adiciona à lista de mensagens decifradas
            mensagens_decifradas.append((remetente, texto, msg.timestamp))
            print(f"🔓 {remetente} → {username}: {texto}")
            dblog.info(f"[RECEIVE_OK] {username} decifrou mensagem de {remetente}.")
            msg.is_read = True

        except Exception as e:
            print(f"⚠️ Erro ao decifrar mensagem de {remetente}: {e}")
            dblog.error(f"[RECEIVE_FAIL] {username} erro ao decifrar mensagem de {remetente}: {e}")

    db.commit()
    return mensagens_decifradas


@safe_db_operation
def receive_secure_group_messages(db, username: str, group_name: str):
    """
    Decifra e exibe todas as mensagens criptografadas de um grupo específico
    para um usuário específico.
    """
    user = db.query(User).filter_by(username=username).first()
    group = db.query(Group).filter_by(name=group_name).first()
    
    if not user:
        raise ValueError("Usuário não encontrado.")
    if not group:
        raise ValueError("Grupo não encontrado.")

    # Busca mensagens do grupo destinadas a este usuário
    msgs = (
        db.query(Message)
        .filter(
            Message.group_id == group.id, 
            Message.receiver_id == user.id  # Busca pelo receiver_id específico
        )
        .all()
    )
    
    if not msgs:
        print(f"📭 Nenhuma mensagem recebida no grupo '{group_name}'.")
        return []

    private_key_path = os.path.join("keys", f"{username}_private.pem")
    if not os.path.exists(private_key_path):
        raise FileNotFoundError(f"Chave privada não encontrada em {private_key_path}")

    private_key = RSAManager.carregar_chave_privada(private_key_path)
    mgr = IDEAManager()
    mensagens_decifradas = []

    print(f"\n=== 🔓 MENSAGENS DECIFRADAS DO GRUPO '{group_name}' ===")
    
    for msg in msgs:
        remetente = db.query(User).get(msg.sender_id).username
        try:
            # 1️⃣ Decifra o conteúdo com IDEA
            texto = mgr.decifrar_do_chat(msg.content_encrypted, msg.key_encrypted, username, private_key)

            # 2️⃣ Verifica integridade (hash SHA256)
            content_hash_calc = sha256(texto.encode()).hexdigest()
            if msg.content_hash and msg.content_hash != content_hash_calc:
                print(f"⚠️ Hash mismatch na mensagem de {remetente}: conteúdo pode ter sido alterado!")

            # 3️⃣ Verifica assinatura digital (se existir)
            sender_user = db.query(User).get(msg.sender_id)
            if msg.signature and sender_user.public_key:
                try:
                    public_key = serialization.load_pem_public_key(sender_user.public_key)
                    RSAManager.verificar_assinatura(texto.encode(), msg.signature, public_key)
                    assinatura_status = "🔏"
                except Exception:
                    assinatura_status = "⚠️"
            else:
                assinatura_status = ""

            # 4️⃣ Adiciona à lista de mensagens decifradas
            mensagens_decifradas.append((remetente, texto, msg.timestamp))
            print(f"{assinatura_status} {remetente} → {username}: {texto} [{msg.timestamp}]")
            dblog.info(f"[RECEIVE_GROUP_OK] {username} decifrou mensagem de {remetente} no grupo {group_name}.")
            msg.is_read = True

        except Exception as e:
            print(f"⚠️ Erro ao decifrar mensagem de {remetente}: {e}")
            dblog.error(f"[RECEIVE_GROUP_FAIL] {username} erro ao decifrar mensagem de {remetente} no grupo {group_name}: {e}")

    db.commit()
    return mensagens_decifradas

# ======================================================
# ✏️ UPDATE
# ======================================================
@safe_db_operation
def mark_as_read(db, msg_id: int):
    msg = db.query(Message).get(msg_id)
    if not msg:
        return None
    msg.is_read = True
    db.commit()
    dblog.info(f"[MSG_READ] ID={msg_id}")
    return msg


# ======================================================
# 🗑️ DELETE
# ======================================================
@safe_db_operation
def delete_message(db, msg_id: int):
    msg = db.query(Message).get(msg_id)
    if msg:
        db.delete(msg)
        db.commit()
        dblog.info(f"[DELETE_MESSAGE] ID={msg_id}")
        return True
    return False
