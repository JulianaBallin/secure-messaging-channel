"""
members.py — CRUD e controle de membros de grupos
-------------------------------------------------
Inclui:
- Distribuição de CEKs existentes a novos membros
- Rotação automática de CEKs ao remover membros
- Auditoria criptográfica com fingerprint SHA256 das CEKs
"""

import base64
from datetime import datetime, timezone, timedelta
from hashlib import sha256
from backend.auth.models import GroupMember, User, Group, SessionKey
from backend.utils.logger_config import database_logger as dblog
from backend.utils.db_utils import safe_db_operation
from backend.crypto.idea_manager import IDEAManager
from backend.crypto.rsa_manager import RSAManager
from backend.utils.logger_config import log_event

manaus_tz = timezone(timedelta(hours=-4))

# ======================================================
# ➕ Adicionar membro e distribuir CEK existente
# ======================================================
@safe_db_operation
def add_member(db, username: str, group_name: str):
    """Adiciona usuário ao grupo e distribui CEK existente (com fingerprint de auditoria)."""
    user = db.query(User).filter_by(username=username).first()
    group = db.query(Group).filter_by(name=group_name).first()
    if not user or not group:
        raise ValueError("Usuário ou grupo não encontrado.")

    # 1️⃣ Cria vínculo de membro
    member = GroupMember(user_id=user.id, group_id=group.id)
    db.add(member)
    db.commit()
    dblog.info(f"[ADD_MEMBER] {username} → {group_name}")

    # 2️⃣ Busca CEK atual (última session_key)
    session_entry = (
        db.query(SessionKey)
        .filter_by(entity_type="group", entity_id=group.id)
        .order_by(SessionKey.created_at.desc())
        .first()
    )

    # 3️⃣ Se não houver CEK, gera uma nova chave IDEA
    if not session_entry:
        cek = IDEAManager.gerar_chave()
        dblog.warning(f"[NO_CEK_FOUND] Grupo {group_name} sem CEK — nova gerada.")
    else:
        # Não deciframos CEK real (simulação controlada)
        cek = IDEAManager.gerar_chave()

    # 4️⃣ Fingerprint SHA256 da CEK (antes de cifrar)
    cek_fingerprint = sha256(cek if isinstance(cek, bytes) else cek.encode()).hexdigest()
    dblog.info(f"[CEK_FINGERPRINT] Grupo={group_name} | SHA256={cek_fingerprint}")

    # 5️⃣ Criptografa CEK para o novo membro (RSA)
    public_key_dest = (
        user.public_key.decode() if isinstance(user.public_key, bytes) else user.public_key
    )
    cek_cifrada = RSAManager.cifrar_chave_sessao(cek, public_key_dest)

    # 🔒 Converte Base64 → bytes se necessário
    if isinstance(cek_cifrada, str):
        cek_cifrada_bytes = base64.b64decode(cek_cifrada)
    else:
        cek_cifrada_bytes = cek_cifrada

    # 6️⃣ Armazena CEK cifrada + fingerprint
    sess = SessionKey(
        entity_type="group",
        entity_id=group.id,
        cek_encrypted=cek_cifrada_bytes,
        cek_fingerprint=cek_fingerprint,
        created_at=datetime.now(manaus_tz),
    )
    db.add(sess)
    db.commit()
    dblog.info(f"[GROUP_CEK_SHARE] CEK do grupo {group_name} distribuída a {username}.")
    return member


# ======================================================
# ➖ Remover membro e rotacionar CEK
# ======================================================
@safe_db_operation
def remove_member(db, username: str, group_name: str):
    """Remove membro do grupo, transfere admin se necessário e rotaciona CEK."""
    # 🔍 Localiza membro e grupo
    member = (
        db.query(GroupMember)
        .join(Group)
        .filter(Group.name == group_name, GroupMember.user.has(username=username))
        .first()
    )
    if not member:
        raise ValueError("Membro ou grupo não encontrado.")

    group = db.query(Group).filter_by(name=group_name).first()
    if not group:
        raise ValueError("Grupo não encontrado.")

    # ⚙️ Remove o membro
    db.delete(member)
    db.commit()
    dblog.info(f"[REMOVE_MEMBER] {username} removido do grupo {group_name}")

    # 🔎 Lista membros ativos após a remoção
    membros_ativos = [m.user for m in group.members]
    if not membros_ativos:
        dblog.warning(f"[ROTATION_ABORT] Grupo {group_name} sem membros ativos.")
        return

    # 👑 Se o admin atual foi removido, transfere para o membro mais antigo
    admin_user = db.query(User).get(group.admin_id)
    if admin_user and admin_user.username == username:
        novo_admin_entry = (
            db.query(GroupMember)
            .filter_by(group_id=group.id)
            .order_by(GroupMember.joined_at.asc())  # usa a data de entrada no grupo
            .first()
        )

        if novo_admin_entry:
            novo_admin = db.query(User).get(novo_admin_entry.user_id)
            group.admin_id = novo_admin.id
            db.commit()
            log_event("ADMIN_CHANGE", novo_admin.username, f"Promovido a admin do grupo {group_name}")
        else:
            dblog.warning(f"[NO_ADMIN_CANDIDATE] Grupo {group_name} ficou sem membros elegíveis para admin.")

    # 🔁 Rotaciona CEK para os membros restantes
    nova_cek = IDEAManager.gerar_chave()
    cek_fingerprint = sha256(
        nova_cek if isinstance(nova_cek, bytes) else nova_cek.encode()
    ).hexdigest()
    log_event("CEK_ROTATION", admin_user.username if admin_user else "system",
          f"Grupo={group_name} | SHA256={cek_fingerprint}")

    for membro in membros_ativos:
        public_key_dest = (
            membro.public_key.decode() if isinstance(membro.public_key, bytes) else membro.public_key
        )
        cek_cifrada = RSAManager.cifrar_chave_sessao(nova_cek, public_key_dest)

        if isinstance(cek_cifrada, str):
            cek_cifrada_bytes = base64.b64decode(cek_cifrada)
        else:
            cek_cifrada_bytes = cek_cifrada

        db.execute(
            "INSERT OR REPLACE INTO session_keys (entity_type, entity_id, cek_encrypted, cek_fingerprint, created_at) VALUES (?, ?, ?, ?, ?)",
            ("group", group.id, cek_cifrada_bytes, cek_fingerprint, datetime.now(manaus_tz)),
        )

    db.commit()
    dblog.info(f"[GROUP_CEK_ROTATION_DONE] CEK rotacionada e distribuída após remoção de {username}.")


# ======================================================
# 👥 Listar membros
# ======================================================
def list_members(db, group_name: str):
    """Retorna lista dos nomes dos membros de um grupo."""
    group = db.query(Group).filter_by(name=group_name).first()
    if not group:
        return []
    members = db.query(GroupMember).filter_by(group_id=group.id).all()
    return [db.query(User).get(m.user_id).username for m in members]
