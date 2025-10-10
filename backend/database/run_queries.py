"""
run_queries.py
---------------

Painel interativo de auditoria e validação de persistência do banco CipherTalk.

Recursos:
- Todas as consultas são somente leitura (SELECT).
- Exibe usuários, grupos, membros e mensagens (pares e grupos).
- Registra logs de auditoria no arquivo logs/database.log.
"""
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.database.connection import SessionLocal
from backend.database.queries.users import get_user_by_username
from backend.database.queries.groups import list_members
from backend.database.queries.messages import get_chat_history
from backend.auth.models import Group, GroupMember, User, Message
from backend.utils.logger_config import database_logger as dblog

db = SessionLocal()


# ======================================================
# 1️⃣  Listar todos os usuários
# ======================================================
def listar_usuarios():
    print("\n=== 👥 Usuários cadastrados ===")
    users = db.query(User).all()
    if not users:
        print("⚠️ Nenhum usuário cadastrado.")
        return
    for u in users:
        print(f"- ID: {u.id:<3} | Nome: {u.username:<20} | Criado em: {u.created_at}")
    dblog.info("[AUDIT] Consulta: listar_usuarios executada.")


# ======================================================
# 2️⃣  Buscar usuário (todas as informações)
# ======================================================
def buscar_usuario():
    username = input("🔍 Nome do usuário: ").strip()
    user = get_user_by_username(db, username)
    if not user:
        print("❌ Usuário não encontrado.")
        return

    print(f"\n=== 📋 Detalhes de {user.username} ===")
    print(f"ID: {user.id}")
    print(f"Nome de usuário: {user.username}")
    print(f"Senha hash: {user.password_hash}")
    print(f"Chave pública armazenada: {'✅ Sim' if user.public_key else '❌ Não'}")
    print(f"Data de criação: {user.created_at}")

    memberships = db.query(GroupMember).filter(GroupMember.user_id == user.id).all()
    if memberships:
        print("\n👥 Grupos que participa:")
        for m in memberships:
            grupo = db.query(Group).get(m.group_id)
            print(f"- {grupo.name}")
    else:
        print("\n👥 Não pertence a nenhum grupo.")
    dblog.info(f"[AUDIT] Consulta: buscar_usuario({username}) executada.")


# ======================================================
# 3️⃣  Listar todos os grupos
# ======================================================
def listar_grupos():
    print("\n=== 🧱 Grupos cadastrados ===")
    grupos = db.query(Group).all()
    if not grupos:
        print("⚠️ Nenhum grupo cadastrado.")
        return
    for g in grupos:
        print(f"- ID: {g.id:<3} | Nome: {g.name:<20} | Criado em: {g.created_at}")
    dblog.info("[AUDIT] Consulta: listar_grupos executada.")


# ======================================================
# 4️⃣  Buscar grupo (informações + membros)
# ======================================================
def buscar_grupo():
    nome = input("🔍 Nome do grupo: ").strip()
    grupo = db.query(Group).filter(Group.name == nome).first()
    if not grupo:
        print("❌ Grupo não encontrado.")
        return

    print(f"\n=== 📋 Detalhes do Grupo '{grupo.name}' ===")
    print(f"ID: {grupo.id}")
    print(f"Administrador ID: {grupo.admin_id}")
    print(f"Criado em: {grupo.created_at}")

    membros = list_members(db, grupo.name)
    if not membros:
        print("⚠️ Nenhum membro encontrado.")
    else:
        print("\n👥 Membros do grupo:")
        for nome_membro in membros:
            print(f"- {nome_membro}")
    dblog.info(f"[AUDIT] Consulta: buscar_grupo({nome}) executada.")


# ======================================================
# 5️⃣  Listar usuários que pertencem a algum grupo
# ======================================================
def usuarios_em_grupos():
    print("\n=== 👥 Usuários com participação em grupos ===")
    membros = db.query(User.username, Group.name).join(GroupMember).join(Group).all()
    if not membros:
        print("⚠️ Nenhum vínculo entre usuários e grupos encontrado.")
        return
    for username, groupname in membros:
        print(f"- {username:<20} → {groupname}")
    dblog.info("[AUDIT] Consulta: usuarios_em_grupos executada.")


# ======================================================
# 6️⃣  Ver mensagens entre dois usuários (pares)
# ======================================================
def mensagens_pares():
    user1 = input("👤 Primeiro usuário: ").strip()
    user2 = input("👤 Segundo usuário: ").strip()

    messages = get_chat_history(db, user1, user2)
    if not messages:
        print("⚠️ Nenhuma mensagem privada entre esses usuários.")
        return

    print(f"\n=== 💬 Histórico entre {user1} e {user2} ===")
    for m in messages:
        remetente = db.query(User).get(m.sender_id).username
        destinatario = db.query(User).get(m.receiver_id).username if m.receiver_id else "-"
        print(f"{remetente:<15} → {destinatario:<15} | {m.timestamp} | {m.content_encrypted[:60]}...")
    dblog.info(f"[AUDIT] Consulta: mensagens_pares({user1}, {user2}) executada.")


# ======================================================
# 7️⃣  Ver mensagens de grupo
# ======================================================
def mensagens_grupos():
    nome_grupo = input("👥 Nome do grupo: ").strip()
    grupo = db.query(Group).filter(Group.name == nome_grupo).first()
    if not grupo:
        print("❌ Grupo não encontrado.")
        return

    mensagens = db.query(Message).filter(Message.group_id == grupo.id).order_by(Message.timestamp.asc()).all()
    if not mensagens:
        print("⚠️ Nenhuma mensagem registrada nesse grupo.")
        return

    print(f"\n=== 📨 Mensagens no grupo '{grupo.name}' ===")
    for m in mensagens:
        remetente = db.query(User).get(m.sender_id).username
        print(f"• {remetente:<15} | {m.timestamp} | {m.content_encrypted[:60]}...")
    dblog.info(f"[AUDIT] Consulta: mensagens_grupos({nome_grupo}) executada.")


# ======================================================
# Menu principal
# ======================================================
def menu():
    while True:
        print("\n=== 🧾 Painel de Auditoria — CipherTalk ===")
        print("1️⃣  - Listar todos os usuários")
        print("2️⃣  - Buscar usuário (todas as informações)")
        print("3️⃣  - Listar todos os grupos")
        print("4️⃣  - Buscar grupo (informações + membros)")
        print("5️⃣  - Listar usuários que pertencem a algum grupo")
        print("6️⃣  - Ver mensagens entre dois usuários (pares)")
        print("7️⃣  - Ver mensagens de grupo")
        print("0️⃣  - Sair")

        opcao = input("Escolha uma opção: ").strip()
        if opcao == "1":
            listar_usuarios()
        elif opcao == "2":
            buscar_usuario()
        elif opcao == "3":
            listar_grupos()
        elif opcao == "4":
            buscar_grupo()
        elif opcao == "5":
            usuarios_em_grupos()
        elif opcao == "6":
            mensagens_pares()
        elif opcao == "7":
            mensagens_grupos()
        elif opcao == "0":
            print("👋 Encerrando painel de auditoria.")
            break
        else:
            print("❌ Opção inválida.")


# ======================================================
# Execução direta
# ======================================================
if __name__ == "__main__":
    dblog.info("🔍 Painel de auditoria do banco iniciado (modo leitura).")
    try:
        menu()
    finally:
        db.close()
        dblog.info("🧹 Sessão SQLAlchemy encerrada (modo leitura).")
