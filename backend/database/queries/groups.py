"""
groups.py
---------

Consultas relacionadas a grupos e seus membros.

Inclui:
- Criação e exclusão de grupos
- Adição e remoção de membros
- Transferência automática de administração
- Listagem de membros
- Logs de auditoria completos
"""

from sqlalchemy.orm import Session
from backend.auth.models import Group, GroupMember, User
from backend.utils.logger_config import database_logger as dblog


# ======================================================
# Criação de grupo
# ======================================================
def create_group(db: Session, name: str, admin_username: str):
    """Cria um grupo e adiciona o criador como administrador."""
    admin = db.query(User).filter(User.username == admin_username).first()
    if not admin:
        dblog.error(f"[GROUP_CREATE_FAIL] Admin {admin_username} não encontrado.")
        return None

    # Evita duplicidade
    if db.query(Group).filter(Group.name == name).first():
        dblog.warning(f"[GROUP_CREATE_DUPLICATE] Grupo '{name}' já existe.")
        return None

    group = Group(name=name, admin_id=admin.id)
    db.add(group)
    db.commit()
    db.refresh(group)

    member = GroupMember(group_id=group.id, user_id=admin.id)
    db.add(member)
    db.commit()

    dblog.info(f"[GROUP_CREATE] Grupo '{name}' criado com admin '{admin_username}'.")
    return group


# ======================================================
# Adição de membro
# ======================================================
def add_member(db: Session, group_name: str, username: str):
    """Adiciona um novo membro ao grupo (somente se ainda não existir)."""
    group = db.query(Group).filter(Group.name == group_name).first()
    user = db.query(User).filter(User.username == username).first()
    if not group or not user:
        dblog.error(f"[GROUP_ADD_FAIL] Grupo ou usuário inválido ({group_name}, {username})")
        return None

    if db.query(GroupMember).filter_by(group_id=group.id, user_id=user.id).first():
        dblog.warning(f"[GROUP_ADD_DUPLICATE] {username} já é membro de {group_name}.")
        return None

    gm = GroupMember(group_id=group.id, user_id=user.id)
    db.add(gm)
    db.commit()
    dblog.info(f"[GROUP_ADD] {username} adicionado a {group_name}.")
    return gm


# ======================================================
# Remoção de membro
# ======================================================
def remove_member(db: Session, group_name: str, username: str):
    """Remove um membro do grupo; transfere administração se necessário."""
    group = db.query(Group).filter(Group.name == group_name).first()
    user = db.query(User).filter(User.username == username).first()
    if not group or not user:
        dblog.error(f"[GROUP_REMOVE_FAIL] Grupo ou usuário inválido ({group_name}, {username})")
        return False

    membership = db.query(GroupMember).filter_by(group_id=group.id, user_id=user.id).first()
    if not membership:
        dblog.warning(f"[GROUP_REMOVE_NOTFOUND] {username} não pertence a {group_name}.")
        return False

    # Se o usuário for o admin do grupo, transferir a administração
    if group.admin_id == user.id:
        successor = (
            db.query(GroupMember)
            .filter(GroupMember.group_id == group.id, GroupMember.user_id != user.id)
            .first()
        )
        if successor:
            group.admin_id = successor.user_id
            dblog.info(f"[GROUP_ADMIN_TRANSFER] Admin de '{group_name}' transferido para user_id={successor.user_id}.")
        else:
            dblog.warning(f"[GROUP_ADMIN_WARNING] Grupo '{group_name}' sem membros restantes (será deletado).")
            db.delete(group)
            db.commit()
            return True

    db.delete(membership)
    db.commit()
    dblog.info(f"[GROUP_REMOVE] {username} removido de {group_name}.")
    return True


# ======================================================
# Listagem de membros
# ======================================================
def list_members(db: Session, group_name: str):
    """Lista todos os membros de um grupo (retorna usernames)."""
    group = db.query(Group).filter(Group.name == group_name).first()
    if not group:
        dblog.error(f"[GROUP_LIST_FAIL] Grupo não encontrado: {group_name}")
        return []

    members = (
        db.query(User.username)
        .join(GroupMember, GroupMember.user_id == User.id)
        .filter(GroupMember.group_id == group.id)
        .all()
    )
    usernames = [m[0] for m in members]
    dblog.info(f"[GROUP_LIST] {len(usernames)} membros listados em {group_name}.")
    return usernames
