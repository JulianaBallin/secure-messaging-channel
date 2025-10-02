"""
cli.py (grupos)
---------------

Provides a terminal interface for creating groups, joining groups,
and listing groups and their members.
"""

from sqlalchemy.orm import Session
from backend.database.connection import SessionLocal
from backend.auth.models import User, Group, GroupMember

def create_group(current_user: str) -> None:
    """Create a new group if the name does not already exist."""
    db: Session = SessionLocal()
    group_name = input("👥 Nome do novo grupo: ").strip()

    if len(group_name) < 3:
        print("❌ O nome do grupo deve ter pelo menos 3 caracteres.")
        return

    existing = db.query(Group).filter(Group.name == group_name).first()
    if existing:
        print("❌ Já existe um grupo com esse nome.")
        return

    # Criar grupo
    new_group = Group(name=group_name)
    db.add(new_group)
    db.commit()

    # Adicionar criador automaticamente como membro
    user = db.query(User).filter(User.username == current_user).first()
    membership = GroupMember(user_id=user.id, group_id=new_group.id)
    db.add(membership)
    db.commit()

    print(f"✅ Grupo '{group_name}' criado com sucesso e você foi adicionado(a) a ele!")


def join_group(current_user: str) -> None:
    """Join an existing group if not already a member."""
    db: Session = SessionLocal()
    groups = db.query(Group).all()

    if not groups:
        print("⚠️ Nenhum grupo existe ainda.")
        return

    print("\n=== 📜 Grupos disponíveis ===")
    for g in groups:
        print(f"- {g.name}")

    group_name = input("👉 Digite o nome do grupo que deseja entrar: ").strip()
    group = db.query(Group).filter(Group.name == group_name).first()

    if not group:
        print("❌ Grupo não encontrado.")
        return

    user = db.query(User).filter(User.username == current_user).first()

    already_member = (
        db.query(GroupMember)
        .filter(GroupMember.user_id == user.id, GroupMember.group_id == group.id)
        .first()
    )

    if already_member:
        print("⚠️ Você já é membro deste grupo.")
        return

    membership = GroupMember(user_id=user.id, group_id=group.id)
    db.add(membership)
    db.commit()
    print(f"✅ Você entrou no grupo '{group.name}' com sucesso!")


def list_groups_and_members() -> None:
    """List all groups and their members."""
    db: Session = SessionLocal()
    groups = db.query(Group).all()

    if not groups:
        print("⚠️ Nenhum grupo encontrado.")
        return

    print("\n=== 👥 Grupos e Membros ===")
    for g in groups:
        print(f"\n📦 Grupo: {g.name}")
        members = (
            db.query(User.username)
            .join(GroupMember, User.id == GroupMember.user_id)
            .filter(GroupMember.group_id == g.id)
            .all()
        )
        if members:
            for m in members:
                print(f"  - {m.username}")
        else:
            print("  (sem membros)")
