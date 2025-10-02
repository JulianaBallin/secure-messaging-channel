"""
init_db.py
-----------

Initializes the SQLite database by creating all tables declared on Base.
IMPORTANT: Models must be imported BEFORE create_all() so they get registered.
"""

from sqlalchemy import inspect
from backend.database.connection import Base, engine

# ✅ Importa os modelos para registrar as tabelas no Base.metadata
from backend.auth.models import User, Group, GroupMember, Message  # noqa: F401

def main() -> None:
    print(f"🔧 Creating tables on: {engine.url}")
    Base.metadata.create_all(bind=engine)

    insp = inspect(engine)
    print("✅ Tables created:", insp.get_table_names())

if __name__ == "__main__":
    main()
