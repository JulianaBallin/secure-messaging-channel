"""
run_queries.py
--------------

Script interativo de consulta ao banco de dados CipherTalk.
Permite visualizar usuários cadastrados, status online/offline,
mensagens, grupos e membros diretamente no terminal.
"""

from backend.database.connection import SessionLocal
from backend.database.queries.users import get_all_users, get_user_by_username
from backend.database.queries.messages import get_user_messages, get_offline_messages
from backend.database.queries.groups import get_all_groups, get_group_members

# Cria sessão com o banco
db = SessionLocal()


def listar_usuarios():
    """Lista todos os usuários com status online/offline."""
    print("\n=== 👤 Usuários cadastrados ===")
    users = get_all_users(db)
    if not users:
        print("⚠️ Nenhum usuário cadastrado.")
        return
    for u in users:
        status = "🟢 Online" if u["online"] else "⚫ Offline"
        print(f"- ID: {u['id']} | {u['username']} | Criado em: {u['created_at']} | {status}")


def buscar_usuario():
    """Busca um usuário pelo nome de usuário."""
    username = input("Digite o nome de usuário: ").strip()
    user = get_user_by_username(db, username)
    if user:
        print(f"\n✅ Usuário encontrado:")
        print(f"ID: {user.id}")
        print(f"Username: {user.username}")
        print(f"Criado em: {user.created_at}")
    else:
        print("❌ Usuário não encontrado.")


def mensagens_usuario():
    """Exibe mensagens enviadas e recebidas de um usuário."""
    username = input("Digite o nome de usuário: ").strip()
    messages = get_user_messages(db, username)
    if not messages["sent"] and not messages["received"]:
        print("⚠️ Nenhuma mensagem encontrada.")
        return

    print("\n=== ✉️ Mensagens enviadas ===")
    for m in messages["sent"]:
        print(f"→ ID: {m.id} | Para: {m.receiver.username} | Conteúdo: {m.content_encrypted} | {m.timestamp}")

    print("\n=== 📩 Mensagens recebidas ===")
    for m in messages["received"]:
        print(f"← ID: {m.id} | De: {m.sender.username} | Conteúdo: {m.content_encrypted} | {m.timestamp}")


def mensagens_offline():
    """Mostra mensagens não entregues a um usuário."""
    username = input("Digite o nome de usuário: ").strip()
    messages = get_offline_messages(db, username)
    if not messages:
        print("⚠️ Nenhuma mensagem offline encontrada.")
        return

    print("\n=== 📬 Mensagens não entregues ===")
    for m in messages:
        print(f"De: {m.sender.username} | Conteúdo: {m.content_encrypted} | {m.timestamp}")


def listar_grupos():
    """Lista todos os grupos existentes."""
    print("\n=== 👥 Grupos ===")
    groups = get_all_groups(db)
    if not groups:
        print("⚠️ Nenhum grupo cadastrado.")
        return

    for g in groups:
        print(f"- ID: {g.id} | Nome: {g.name} | Criado em: {g.created_at}")


def membros_grupo():
    """Lista membros de um grupo pelo ID."""
    group_id = input("Digite o ID do grupo: ").strip()
    try:
        group_id = int(group_id)
    except ValueError:
        print("❌ ID inválido.")
        return

    members = get_group_members(db, group_id)
    if not members:
        print("⚠️ Nenhum membro encontrado para esse grupo.")
        return

    print("\n=== 👤 Membros do grupo ===")
    for m in members:
        print(f"- ID: {m['id']} | {m['username']}")


def menu():
    """Menu interativo de consultas."""
    while True:
        print("\n=== 🛠️ Consultas ao Banco CipherTalk ===")
        print("1️⃣  - Listar todos os usuários")
        print("2️⃣  - Buscar usuário por nome")
        print("3️⃣  - Ver mensagens de um usuário")
        print("4️⃣  - Ver mensagens offline de um usuário")
        print("5️⃣  - Listar grupos")
        print("6️⃣  - Ver membros de um grupo")
        print("0️⃣  - Sair")

        choice = input("Escolha uma opção: ").strip()

        if choice == "1":
            listar_usuarios()
        elif choice == "2":
            buscar_usuario()
        elif choice == "3":
            mensagens_usuario()
        elif choice == "4":
            mensagens_offline()
        elif choice == "5":
            listar_grupos()
        elif choice == "6":
            membros_grupo()
        elif choice == "0":
            print("👋 Encerrando consultas...")
            break
        else:
            print("❌ Opção inválida.")


if __name__ == "__main__":
    menu()
