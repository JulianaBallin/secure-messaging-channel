"""
run_queries.py 
----------------

Painel interativo de auditoria e validação de persistência do banco CipherTalk.

Recursos:
- Todas as consultas são somente leitura (SELECT).
- Exibe usuários, grupos, membros e mensagens (pares e grupos).
- Registra logs de auditoria no arquivo logs/database.log.
"""

from backend.database.connection import SessionLocal
from backend.database.queries.users import list_all_users, get_user_by_username
from backend.database.queries.groups import list_members
from backend.database.queries.messages import get_user_messages, get_group_messages
from backend.auth.models import Group, GroupMember, User
from backend.utils.logger_config import database_logger as dblog

db = SessionLocal()


# ======================================================
# 1 - Listar todos os usuários
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
# 2 - Buscar usuário (todas as informações)
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

    # Exibir grupos pertencentes
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
# 3 - Listar todos os grupos
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
# 4 - Buscar grupo (informações + membros)
# ======================================================
def buscar_grupo():
    nome = input("🔍 Nome do grupo: ").strip()
    grupo = db.query(Group).filter(Group.name == nome).first()
    if not grupo:
        print("❌ Grupo não encontrado.")
        return

    print(f"\n=== 📋 Detalhes do Grupo '{grupo.name}' ===")
    print(f"ID: {grupo.id}")
    print(f"Criado em: {grupo.created_at}")

    membros = list_members(db, grupo.name)
    if not membros:
        print("⚠️ Nenhum membro encontrado.")
    else:
        print("\n👥 Membros do grupo:")
        for m in membros:
            print(f"- {m.user.username}")

    dblog.info(f"[AUDIT] Consulta: buscar_grupo({nome}) executada.")


# ======================================================
# 5 - Listar usuários que pertencem a algum grupo
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
# 6 - Ver mensagens de usuário (comunicação em pares)
# ======================================================
def mensagens_pares():
    username = input("💬 Nome do usuário: ").strip()
    messages = get_user_messages(db, username)
    sent = messages.get("sent", [])
    received = messages.get("received", [])

    if not sent and not received:
        print("⚠️ Nenhuma mensagem privada encontrada.")
        return

    print("\n=== ✉️ Mensagens Enviadas ===")
    for m in sent:
        if m.receiver:
            print(f"→ Para: {m.receiver.username:<15} | {m.timestamp} | Cifrada: {m.content_encrypted[:50]}...")

    print("\n=== 📩 Mensagens Recebidas ===")
    for m in received:
        if m.sender:
            print(f"← De: {m.sender.username:<15} | {m.timestamp} | Cifrada: {m.content_encrypted[:50]}...")
    dblog.info(f"[AUDIT] Consulta: mensagens_pares({username}) executada.")


# ======================================================
# 7 - Ver mensagens de usuário (grupos)
# ======================================================
def mensagens_grupos():
    username = input("👥 Nome do usuário: ").strip()
    grupos = (
        db.query(Group)
        .join(GroupMember, GroupMember.group_id == Group.id)
        .join(User, User.id == GroupMember.user_id)
        .filter(User.username == username)
        .all()
    )

    if not grupos:
        print("⚠️ Esse usuário não pertence a nenhum grupo.")
        return

    print(f"\n=== 💬 Mensagens em grupos de {username} ===")
    for g in grupos:
        msgs = get_group_messages(db, g.name)
        if not msgs:
            print(f"\n📭 Grupo {g.name}: sem mensagens registradas.")
            continue
        print(f"\n📨 Grupo {g.name}:")
        for m in msgs:
            remetente = m.sender.username if m.sender else "Desconhecido"
            print(f"   • {remetente:<15} → {m.timestamp} | {m.content_encrypted[:50]}...")
    dblog.info(f"[AUDIT] Consulta: mensagens_grupos({username}) executada.")


# ======================================================
# Menu principal (somente leitura)
# ======================================================
def menu():
    while True:
        print("\n=== 🧾 Painel de Auditoria — CipherTalk ===")
        print("1️⃣  - Listar todos os usuários")
        print("2️⃣  - Buscar usuário (todas as informações)")
        print("3️⃣  - Listar todos os grupos")
        print("4️⃣  - Buscar grupo (informações + membros)")
        print("5️⃣  - Listar usuários que pertencem a algum grupo")
        print("6️⃣  - Ver mensagens de usuário (pares)")
        print("7️⃣  - Ver mensagens de usuário (grupos)")
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
