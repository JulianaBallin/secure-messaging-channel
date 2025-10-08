"""
connection.py
--------------

Cria e gerencia a conexão com o banco de dados usando SQLAlchemy.
Garante que o banco de dados SQLite seja sempre armazenado em backend/database/cipher_talk.db.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os

# ----------------------------
# Caminho fixo e seguro
# ----------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "cipher_talk.db")

SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"

# ----------------------------
# Engine e sessão
# ----------------------------
connect_args = {"check_same_thread": False}
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)
Base = declarative_base()

def get_db():
    """Yield a new database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
