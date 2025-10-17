"""
groups.py — CRUD para tabela 'groups'
"""
from datetime import datetime, timezone, timedelta
from backend.auth.models import Group, User, GroupMember, SessionKey
from backend.utils.logger_config import database_logger as dblog
from backend.utils.db_utils import safe_db_operation
from backend.crypto.idea_manager import IDEAManager
from backend.crypto.rsa_manager import RSAManager

manaus_tz = timezone(timedelta(hours=-4))


# ======================================================
# 🆕 CREATE
# ======================================================
# backend/database/queries/groups.py

@safe_db_operation
def create_group(db, name: str, admin_username: str):
    """Cria um novo grupo, adiciona o admin como membro e gera CEK inicial."""
    admin = db.query(User).filter_by(username=admin_username).first()
    if not admin:
        raise ValueError("Administrador não encontrado.")

    # 1️⃣ Cria grupo
    group = Group(name=name, admin_id=admin.id)
    db.add(group)
    db.commit()
    db.refresh(group)
    dblog.info(f"[CREATE_GROUP] {name} (admin={admin_username})")

    # 2️⃣ Adiciona o admin como membro do grupo
    admin_member = GroupMember(user_id=admin.id, group_id=group.id)
    db.add(admin_member)
    db.commit()
    dblog.info(f"[ADD_ADMIN_MEMBER] {admin_username} adicionado automaticamente ao grupo {name}")

    # 3️⃣ Gera CEK inicial para o grupo
    cek = IDEAManager.gerar_chave()

    # Criptografa a CEK com a chave pública do admin
    public_key_admin = (
        admin.public_key.decode() if isinstance(admin.public_key, bytes) else admin.public_key
    )
    cek_cifrada_b64 = RSAManager.cifrar_chave_sessao(cek, public_key_admin)

    sess = SessionKey(
        entity_type="group",
        entity_id=group.id,
        cek_encrypted=cek_cifrada_b64, 
        created_at=datetime.now(manaus_tz),
    )
    db.add(sess)
    db.commit()
    dblog.info(f"[GROUP_CEK_INIT] CEK inicial criada e armazenada para grupo {name}")

    return group


# ======================================================
# 🔎 READ
# ======================================================
def get_group_by_name(db, name: str):
    return db.query(Group).filter_by(name=name).first()


def list_groups(db):
    return db.query(Group).all()


# ======================================================
# ✏️ UPDATE
# ======================================================
@safe_db_operation
def rename_group(db, old_name: str, new_name: str):
    group = get_group_by_name(db, old_name)
    if not group:
        raise ValueError("Grupo não encontrado.")
    group.name = new_name
    db.commit()
    dblog.info(f"[UPDATE_GROUP] {old_name} → {new_name}")
    return group


# ======================================================
# 🗑️ DELETE
# ======================================================
@safe_db_operation
def delete_group(db, name: str):
    group = get_group_by_name(db, name)
    if not group:
        raise ValueError("Grupo não encontrado.")
    db.delete(group)
    db.commit()
    dblog.info(f"[DELETE_GROUP] {name}")
    return True
