"""
groups.py
---------

Query functions related to groups and group membership.
"""

from sqlalchemy.orm import Session
from backend.auth.models import Group, GroupMember, User


def get_all_groups(db: Session):
    """
    Return a list of all groups.
    """
    return db.query(Group).all()


def get_group_members(db: Session, group_id: int):
    """
    Return a list of members for a given group.
    """
    members = (
        db.query(GroupMember)
        .filter(GroupMember.group_id == group_id)
        .join(User, User.id == GroupMember.user_id)
        .all()
    )
    return [{"id": m.user.id, "username": m.user.username} for m in members]
