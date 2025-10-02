"""
run_cli.py
-----------

Main entry point for the CipherTalk terminal interface.
"""

from backend.auth.cli import register_user, login_user
from backend.groups.cli import create_group, join_group, list_groups_and_members
from backend.messages.cli import start_conversation, read_inbox

def group_menu(current_user: str) -> None:
    """Show group actions for a logged-in user."""
    while True:
        print("\n=== 👥 Menu de Grupos ===")
        print("1️⃣  - Criar grupo")
        print("2️⃣  - Entrar em grupo")
        print("3️⃣  - Listar grupos e membros")
        print("0️⃣  - Voltar ao menu principal")

        choice = input("\nEscolha uma opção: ").strip()

        if choice == "1":
            create_group(current_user)
        elif choice == "2":
            join_group(current_user)
        elif choice == "3":
            list_groups_and_members()
        elif choice == "0":
            break
        else:
            print("❌ Opção inválida.")
            
def user_menu(current_user: str):
    """Menu de ações disponíveis após login."""
    while True:
        print("\n=== 📡 Menu Principal ===")
        print("1️⃣ - Grupos")
        print("2️⃣ - Iniciar conversa com usuário")
        print("3️⃣ - Ler mensagens recebidas")
        print("0️⃣ - Logout")

        choice = input("\nEscolha uma opção: ").strip()

        if choice == "1":
            group_menu(current_user)
        elif choice == "2":
            start_conversation(current_user)
        elif choice == "3":
            read_inbox(current_user)
        elif choice == "0":
            break
        else:
            print("❌ Opção inválida.")

def main():
    while True:
        print("\n=== 🔐 CipherTalk CLI ===")
        print("1️⃣  - Cadastrar novo usuário")
        print("2️⃣  - Fazer login")
        print("0️⃣  - Sair")

        choice = input("\nEscolha uma opção: ").strip()

        if choice == "1":
            register_user()
        elif choice == "2":
            user = login_user()
            if user: 
                group_menu(user)
        elif choice == "0":
            print("👋 Encerrando...")
            break
        else:
            print("❌ Opção inválida.")

if __name__ == "__main__":
    main()
