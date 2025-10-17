"""
run_inserts.py
---------------

Painel interativo de inserção e testes de persistência no banco CipherTalk.

Recursos:
- Inserção de usuários, grupos e mensagens.
- Associação de membros a grupos.
- Logs de inserção no arquivo logs/database.log.
"""

import os
import sys

# 🔧 Corrige sys.path quando o script é rodado diretamente
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))
sys.path.insert(0, PROJECT_ROOT)


import datetime
from getpass import getpass
from backend.database.connection import SessionLocal
from backend.auth.models import User, Group, GroupMember, Message
from backend.database.connection import engine, Base
from backend.utils.logger_config import database_logger as dblog
from backend.auth.security import hash_senha
from backend.crypto.rsa_manager import RSAManager


# ======================================================
# 🏗️ Garante que o banco e as tabelas existam
# ======================================================
print("🧱 Verificando estrutura do banco...")
Base.metadata.create_all(bind=engine)
print("✅ Tabelas verificadas e prontas.\n")

db = SessionLocal()


# ======================================================
# 1️⃣ Criar novo usuário
# ======================================================
def criar_usuario():
    """
    Cria um novo usuário:
    - Gera hash Argon2id da senha;
    - Gera par RSA (privada e pública);
    - Salva a chave privada em 'keys/<username>_private.pem';
    - Armazena a senha hash e a chave pública no banco.
    """
    username = input("👤 Nome do usuário: ").strip()
    password = getpass("🔑 Senha: ").strip()

    if not username or not password:
        print("❌ Usuário e senha são obrigatórios.")
        return

    # Verifica duplicidade
    if db.query(User).filter_by(username=username).first():
        print("⚠️ Usuário já existe no banco.")
        return

    # Gera hash Argon2id da senha
    password_hash = hash_senha(password)

    # Gera par RSA
    private_key_pem, public_key_pem = RSAManager.gerar_par_chaves()

    # Garante a existência da pasta 'keys' na raiz do projeto
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    keys_dir = os.path.join(project_root, "keys")
    os.makedirs(keys_dir, exist_ok=True)

    # Caminho seguro do arquivo da chave privada
    private_key_path = os.path.join(keys_dir, f"{username}_private.pem")

    # Salva a chave privada em arquivo local (somente leitura)
    with open(private_key_path, "w", encoding="utf-8") as key_file:
        key_file.write(private_key_pem)
    os.chmod(private_key_path, 0o600)  # restrição de permissão

    # Cria o usuário com a chave pública e o hash da senha
    new_user = User(
        username=username,
        password_hash=password_hash,
        public_key=public_key_pem.encode(),  # armazenar em bytes
    )

    db.add(new_user)
    db.commit()

    print(f"\n✅ Usuário '{username}' criado com sucesso (ID={new_user.id}).")
    print(f"🔒 Chave privada salva em: {private_key_path}")
    print(f"🗝️  A chave pública foi armazenada no banco de dados.")
    print("\n" + "=" * 70)
    dblog.info(f"[INSERT_USER_RSA] Usuário criado: {username} | Chave privada: {private_key_path}")



# ======================================================
# 2️⃣ Criar grupo
# ======================================================
def criar_grupo():
    """Cria um novo grupo com um administrador existente."""
    nome = input("🏷️ Nome do grupo: ").strip()
    admin_username = input("👑 Nome do administrador: ").strip()

    admin = db.query(User).filter_by(username=admin_username).first()
    if not admin:
        print("❌ Administrador não encontrado.")
        return

    grupo = Group(name=nome, admin_id=admin.id)
    db.add(grupo)
    db.commit()
    print(f"✅ Grupo '{nome}' criado com sucesso (Admin: {admin_username}).")
    dblog.info(f"[INSERT_GROUP] Grupo criado: {nome} (admin={admin_username})")


# ======================================================
# 3️⃣ Adicionar membro a grupo
# ======================================================
def adicionar_membro():
    """Adiciona um usuário existente a um grupo."""
    username = input("👤 Nome do usuário: ").strip()
    group_name = input("🏷️ Nome do grupo: ").strip()

    user = db.query(User).filter_by(username=username).first()
    group = db.query(Group).filter_by(name=group_name).first()

    if not user or not group:
        print("❌ Usuário ou grupo não encontrado.")
        return

    membro = GroupMember(user_id=user.id, group_id=group.id)
    db.add(membro)
    db.commit()
    print(f"✅ {username} adicionado ao grupo '{group_name}'.")
    dblog.info(f"[INSERT_MEMBER] {username} → {group_name}")


# ======================================================
# 4️⃣ Enviar mensagem privada
# ======================================================
def enviar_mensagem_privada():
    """Cria uma mensagem privada entre dois usuários."""
    sender = input("✉️ Remetente: ").strip()
    receiver = input("📩 Destinatário: ").strip()
    content = input("💬 Conteúdo da mensagem: ").strip()

    u1 = db.query(User).filter_by(username=sender).first()
    u2 = db.query(User).filter_by(username=receiver).first()
    if not u1 or not u2:
        print("❌ Usuário(s) não encontrado(s).")
        return

    msg = Message(
        sender_id=u1.id,
        receiver_id=u2.id,
        content_encrypted=content,
        key_encrypted="(chave_simulada)",
        timestamp=datetime.datetime.utcnow(),
    )
    db.add(msg)
    db.commit()
    print(f"✅ Mensagem de {sender} → {receiver} salva.")
    dblog.info(f"[INSERT_MSG_PRIVATE] {sender} → {receiver}")


# ======================================================
# 5️⃣ Enviar mensagem de grupo
# ======================================================
def enviar_mensagem_grupo():
    """Cria uma mensagem associada a um grupo."""
    sender = input("✉️ Remetente: ").strip()
    group_name = input("👥 Nome do grupo: ").strip()
    content = input("💬 Conteúdo da mensagem: ").strip()

    u = db.query(User).filter_by(username=sender).first()
    g = db.query(Group).filter_by(name=group_name).first()
    if not u or not g:
        print("❌ Usuário ou grupo não encontrado.")
        return

    msg = Message(
        sender_id=u.id,
        group_id=g.id,
        content_encrypted=content,
        key_encrypted="(chave_simulada)",
        timestamp=datetime.datetime.utcnow(),
    )
    db.add(msg)
    db.commit()
    print(f"✅ Mensagem no grupo '{group_name}' salva com sucesso.")
    dblog.info(f"[INSERT_MSG_GROUP] {sender} → grupo {group_name}")


# ======================================================
# 6️⃣ Mostrar resumo do banco
# ======================================================
def resumo_geral():
    """Mostra quantos registros existem em cada tabela."""
    n_users = db.query(User).count()
    n_groups = db.query(Group).count()
    n_members = db.query(GroupMember).count()
    n_msgs = db.query(Message).count()

    print("\n📊 Resumo de registros:")
    print(f"- Usuários: {n_users}")
    print(f"- Grupos: {n_groups}")
    print(f"- Membros: {n_members}")
    print(f"- Mensagens: {n_msgs}")

    dblog.info("[DB_SUMMARY] Consulta de contagem executada.")


# ======================================================
# Menu principal
# ======================================================
def menu():
    while True:
        print("\n=== 🧩 Painel de Inserção — CipherTalk ===")
        print("1️⃣  - Criar novo usuário")
        print("2️⃣  - Criar novo grupo")
        print("3️⃣  - Adicionar membro a grupo")
        print("4️⃣  - Enviar mensagem privada")
        print("5️⃣  - Enviar mensagem de grupo")
        print("6️⃣  - Mostrar resumo do banco")
        print("0️⃣  - Sair")

        opcao = input("Escolha uma opção: ").strip()
        if opcao == "1":
            criar_usuario()
        elif opcao == "2":
            criar_grupo()
        elif opcao == "3":
            adicionar_membro()
        elif opcao == "4":
            enviar_mensagem_privada()
        elif opcao == "5":
            enviar_mensagem_grupo()
        elif opcao == "6":
            resumo_geral()
        elif opcao == "0":
            print("👋 Encerrando painel de inserção.")
            break
        else:
            print("❌ Opção inválida.")


# ======================================================
# Execução direta
# ======================================================
if __name__ == "__main__":
    dblog.info("🧱 Painel de inserção iniciado (modo escrita).")
    try:
        menu()
    finally:
        db.close()
        dblog.info("🧹 Sessão SQLAlchemy encerrada (modo escrita).")
