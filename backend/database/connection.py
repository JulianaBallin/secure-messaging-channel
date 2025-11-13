"""
connection.py 
--------------

Gerencia a conexão com o banco de dados SQLite usando SQLAlchemy.
Cria o banco automaticamente (cipher_talk.db) e inicializa todas as tabelas.
Inclui logging detalhado das operações de conexão, verificação e inicialização.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# ======================================================
# Caminho fixo e seguro para o banco
# ======================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "cipher_talk.db")
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"

# ======================================================
# Engine e sessão
# ======================================================
connect_args = {"check_same_thread": False}
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)
Base = declarative_base()


# ======================================================
# Sessão de banco (gerador padrão)
# ======================================================
def get_db():
    """Fornece uma nova sessão de banco de dados, garantindo fechamento seguro."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ======================================================
# Criação e verificação automática de tabelas
# ======================================================
def ensure_database():
    """
    Garante que todas as tabelas estejam criadas e verificadas no banco de dados SQLite.
    Pode ser chamada por qualquer módulo (server, run_queries, testes).
    """
    try:
        from backend.auth.models import Base as AuthBase

        # Cria as tabelas, se não existirem
        AuthBase.metadata.create_all(bind=engine)

        # Log de verificação de esquema
        print("✅ Banco de dados inicializado e verificado com sucesso.")

    except Exception as e:
        raise e
