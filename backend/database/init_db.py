"""
init_db.py
-----------

Initializes or updates the CipherTalk SQLite database.

Features:
- Creates all tables declared in Base if missing.
- Verifies existing schema (safe migration-like behavior).
- Allows full reset via --reset flag.
- Logs every operation to database.log (with Manaus timezone).
"""

import os
import sys
from sqlalchemy import inspect
from datetime import datetime, timezone, timedelta

import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.database.connection import Base, engine
from backend.auth.models import User, Group, GroupMember, Message  # noqa: F401

# Fuso horário de Manaus
MANAUS_TZ = timezone(timedelta(hours=-4))
DB_PATH = os.path.join(os.path.dirname(__file__), "cipher_talk.db")


def recreate_database() -> None:
    """Remove o banco antigo e recria do zero."""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print(f"🧹 Banco antigo removido ({DB_PATH}) em {datetime.now(MANAUS_TZ)}")
    Base.metadata.create_all(bind=engine)
    print(f"✅ Novo banco criado em {datetime.now(MANAUS_TZ)}")


def update_schema() -> None:
    """
    Atualiza o schema existente:
    - Cria tabelas ausentes, sem apagar dados.
    - Loga resultado e tabelas existentes.
    """
    Base.metadata.create_all(bind=engine)  # safe update
    insp = inspect(engine)
    tables = insp.get_table_names()
    print(f"🔧 Schema verificado — tabelas existentes: {tables}")
    print("✅ Banco atualizado. Tabelas:", ", ".join(tables))


def main() -> None:
    """Gerencia inicialização ou recriação do banco."""
    reset_flag = "--reset" in sys.argv

    print(f"📦 Banco de dados alvo: {engine.url}")
    if not os.path.exists(DB_PATH):
        print("🆕 Nenhum banco encontrado. Criando novo...")
        recreate_database()
    elif reset_flag:
        print("♻️  Reset completo solicitado. Recriando banco...")
        recreate_database()
    else:
        print("🔍 Banco existente encontrado. Atualizando schema...")
        update_schema()

    insp = inspect(engine)
    print("📋 Estrutura final:", insp.get_table_names())
    print(f"🏁 Processo de inicialização concluído às {datetime.now(MANAUS_TZ)}")


if __name__ == "__main__":
    main()
