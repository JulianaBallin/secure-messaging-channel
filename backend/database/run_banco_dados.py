"""
run_banco_dados.py
------------------

Painel central do banco CipherTalk.
Controla todos os CRUDs (Create, Read, Update, Delete) de forma modular.

Menus:
1️⃣ Inserir dados (Usuário, Grupo, Membro, Mensagem)
2️⃣ Consultar registros
3️⃣ Editar informações
4️⃣ Deletar registros
0️⃣ Sair

⚙️ Todas as operações utilizam as funções centralizadas
em backend/database/queries/
"""

import sys, os
from getpass import getpass
from datetime import datetime, timezone, timedelta

# Corrige o caminho do projeto
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.database.connection import SessionLocal, Base, engine
from backend.database.queries import users, groups, members, messages
from backend.utils.logger_config import database_logger as dblog
print(type(dblog))

manaus_tz = timezone(timedelta(hours=-4))
db = SessionLocal()

# ======================================================
# 🔧 Funções auxiliares
# ======================================================
def limpar_tela():
    os.system("clear" if os.name == "posix" else "cls")

def pausa():
    input("\nPressione ENTER para continuar...")


# ======================================================
# 1️⃣  INSERIR
# ======================================================
def menu_inserir():
    while True:
        limpar_tela()
        print("\n=== 🧩 INSERIR REGISTROS ===")
        print("1️⃣ - Novo usuário")
        print("2️⃣ - Novo grupo")
        print("3️⃣ - Novo membro de grupo")
        print("4️⃣ - Nova mensagem (privada ou grupo, criptografada)")
        print("0️⃣ - Voltar")

        op = input("\nEscolha: ").strip()
        try:
            # -----------------------------------------------
            # 1️⃣ Novo usuário
            # -----------------------------------------------
            if op == "1":
                username = input("👤 Nome do usuário: ").strip()
                password = getpass("🔑 Senha: ").strip()
                users.create_user(db, username, password)

            # -----------------------------------------------
            # 2️⃣ Novo grupo
            # -----------------------------------------------
            elif op == "2":
                nome = input("🏷️ Nome do grupo: ").strip()
                admin = input("👑 Nome do administrador: ").strip()
                groups.create_group(db, nome, admin)

            # -----------------------------------------------
            # 3️⃣ Novo membro de grupo
            # -----------------------------------------------
            elif op == "3":
                username = input("👥 Usuário: ").strip()
                grupo = input("🏷️ Grupo: ").strip()
                # Valida se usuário e grupo existem
                user_obj = users.get_user_by_username(db, username)
                group_obj = groups.get_group_by_name(db, grupo)
                if not user_obj or not group_obj:
                    print("❌ Usuário ou grupo não encontrado.")
                else:
                    members.add_member(db, username, grupo)
                    print(f"✅ {username} adicionado ao grupo '{grupo}'.")

            # -----------------------------------------------
            # 4️⃣ Nova mensagem segura (privada ou grupo)
            # -----------------------------------------------
            elif op == "4":
                sender = input("✉️ Remetente: ").strip()
                tipo = input("Enviar para (U)suário ou (G)rupo? ").lower()

                if tipo == "u":
                    receiver = input("📩 Destinatário: ").strip()
                    texto = input("💬 Conteúdo da mensagem: ").strip()
                    messages.send_secure_message(db, sender, receiver, texto)
                elif tipo == "g":
                    grupo = input("👥 Nome do grupo: ").strip()
                    texto = input("💬 Conteúdo da mensagem: ").strip()
                    messages.send_secure_group_message(db, sender, grupo, texto)
                else:
                    print("❌ Tipo inválido. Use 'U' para usuário ou 'G' para grupo.")

            elif op == "0":
                break
            else:
                print("❌ Opção inválida.")

        except Exception as e:
            print(f"⚠️ Erro: {e}")
            dblog.error(f"[INSERT_ERROR] {e}")
        pausa()


# ======================================================
# 2️⃣  CONSULTAR
# ======================================================

def menu_consultar():
    while True:
        limpar_tela()
        print("\n=== 🔍 CONSULTAR REGISTROS ===")
        print("1️⃣ - Listar usuários")
        print("2️⃣ - Detalhar usuário")
        print("3️⃣ - Listar grupos")
        print("4️⃣ - Detalhar grupo e membros")
        print("5️⃣ - Mensagens privadas entre dois usuários")
        print("6️⃣ - Mensagens de grupo (criptografadas)")
        print("7️⃣ - Receber e decifrar mensagens privadas")
        print("8️⃣ - Decifrar mensagens de grupo")
        print("0️⃣ - Voltar")

        op = input("\nEscolha: ").strip()
        try:
            # -----------------------------------------------
            # 1️⃣ Listar usuários
            # -----------------------------------------------
            if op == "1":
                for u in users.list_users(db):
                    print(f"- ID={u.id:<3} | Nome={u.username:<15} | Criado em {u.created_at}")

            # -----------------------------------------------
            # 2️⃣ Detalhar usuário
            # -----------------------------------------------
            elif op == "2":
                nome = input("Usuário: ").strip()
                u = users.get_user_by_username(db, nome)
                if u:
                    print(f"\n📋 ID={u.id}\nNome={u.username}\nCriado em={u.created_at}")
                    print(f"Chave pública armazenada: {'✅ Sim' if u.public_key else '❌ Não'}")
                else:
                    print("❌ Usuário não encontrado.")

            # -----------------------------------------------
            # 3️⃣ Listar grupos
            # -----------------------------------------------
            elif op == "3":
                for g in groups.list_groups(db):
                    print(f"- ID={g.id:<3} | Nome={g.name:<20} | Admin={g.admin_id}")

            # -----------------------------------------------
            # 4️⃣ Detalhar grupo e membros
            # -----------------------------------------------
            elif op == "4":
                nome = input("Grupo: ").strip()
                membros = members.list_members(db, nome)
                if membros:
                    print(f"\n👥 Membros do grupo '{nome}':")
                    for m in membros:
                        print(f"- {m}")
                else:
                    print("⚠️ Grupo vazio ou inexistente.")

            # -----------------------------------------------
            # 5️⃣ Histórico entre usuários
            # -----------------------------------------------
            elif op == "5":
                u1 = input("Usuário 1: ").strip()
                u2 = input("Usuário 2: ").strip()
                msgs = messages.get_chat_history(db, u1, u2)
                if not msgs:
                    print("📭 Nenhuma mensagem encontrada.")
                else:
                    for m in msgs:
                        remetente = db.query(users.User).get(m.sender_id).username
                        destinatario = db.query(users.User).get(m.receiver_id).username
                        status = "✅ Lida" if m.is_read else "📨 Não lida"
                        print(f"{remetente:<12} → {destinatario:<12} | {m.timestamp} | {status}")

            # -----------------------------------------------
            # 6️⃣ Mensagens de grupo
            # -----------------------------------------------
            elif op == "6":
                nome = input("Grupo: ").strip()
                msgs = messages.list_group_messages(db, nome)
                if not msgs:
                    print("📭 Nenhuma mensagem encontrada.")
                else:
                    for m in msgs:
                        sender = db.query(users.User).get(m.sender_id).username
                        print(f"{sender:<12} | {m.timestamp} | {m.content_encrypted[:60]}...")

            # -----------------------------------------------
            # 7️⃣ Receber e decifrar mensagens
            # -----------------------------------------------
            elif op == "7":
                nome = input("👤 Usuário (para decifrar suas mensagens): ").strip()
                messages.receive_secure_messages(db, nome)

            # -----------------------------------------------
            # 8️⃣ Decifrar mensagens de grupo
            # -----------------------------------------------
            elif op == "8":
                username = input("👤 Usuário (para decifrar): ").strip()
                group_name = input("👥 Grupo: ").strip()
                messages.receive_secure_group_messages(db, username, group_name)

            elif op == "0":
                break
            else:
                print("❌ Opção inválida.")

        except Exception as e:
            print(f"⚠️ Erro: {e}")
            dblog.error(f"[SELECT_ERROR] {e}")
        pausa()
        
       


# ======================================================
# 3️⃣  EDITAR
# ======================================================
def menu_editar():
    while True:
        limpar_tela()
        print("\n=== ✏️ EDITAR REGISTROS ===")
        print("1️⃣ - Atualizar status online de usuário")
        print("2️⃣ - Renomear grupo")
        print("3️⃣ - Marcar mensagem como lida")
        print("0️⃣ - Voltar")

        op = input("\nEscolha: ").strip()
        try:
            if op == "1":
                nome = input("Usuário: ").strip()
                status = input("Online? (s/n): ").lower() == "s"
                users.set_user_online_status(db, nome, status)
            elif op == "2":
                old = input("Nome atual do grupo: ").strip()
                new = input("Novo nome: ").strip()
                groups.rename_group(db, old, new)
            elif op == "3":
                msg_id = int(input("ID da mensagem: "))
                messages.mark_as_read(db, msg_id)
            elif op == "0":
                break
            else:
                print("❌ Opção inválida.")
        except Exception as e:
            print(f"⚠️ Erro: {e}")
            dblog.error(f"[UPDATE_ERROR] {e}")
        pausa()


# ======================================================
# 4️⃣  DELETAR
# ======================================================
def menu_deletar():
    while True:
        limpar_tela()
        print("\n=== 🗑️ DELETAR REGISTROS ===")
        print("1️⃣ - Usuário")
        print("2️⃣ - Grupo")
        print("3️⃣ - Membro de grupo")
        print("4️⃣ - Mensagem")
        print("0️⃣ - Voltar")

        op = input("\nEscolha: ").strip()
        try:
            if op == "1":
                nome = input("Usuário: ").strip()
                users.delete_user(db, nome)
            elif op == "2":
                nome = input("Grupo: ").strip()
                groups.delete_group(db, nome)
            elif op == "3":
                nome = input("Usuário: ").strip()
                grupo = input("Grupo: ").strip()
                members.remove_member(db, nome, grupo)
            elif op == "4":
                msg_id = int(input("ID da mensagem: "))
                messages.delete_message(db, msg_id)
            elif op == "0":
                break
            else:
                print("❌ Opção inválida.")
        except Exception as e:
            print(f"⚠️ Erro: {e}")
            dblog.error(f"[DELETE_ERROR] {e}")
        pausa()


# ======================================================
# MENU PRINCIPAL
# ======================================================
def menu_principal():
    Base.metadata.create_all(bind=engine)
    while True:
        limpar_tela()
        print("\n=== 🧭 PAINEL CENTRAL — CIPHERTALK ===")
        print("1️⃣  - Inserir")
        print("2️⃣  - Consultar")
        print("3️⃣  - Editar")
        print("4️⃣  - Deletar")
        print("0️⃣  - Sair")

        op = input("\nEscolha: ").strip()
        if op == "1":
            menu_inserir()
        elif op == "2":
            menu_consultar()
        elif op == "3":
            menu_editar()
        elif op == "4":
            menu_deletar()
        elif op == "0":
            print("👋 Encerrando painel do banco.")
            break
        else:
            print("❌ Opção inválida.")
            pausa()


# ======================================================
# Execução direta
# ======================================================
if __name__ == "__main__":
    dblog.info("🧭 Painel de banco iniciado (modo CRUD completo).")
    try:
        menu_principal()
    finally:
        db.close()
        dblog.info("🧹 Sessão SQLAlchemy encerrada.")
