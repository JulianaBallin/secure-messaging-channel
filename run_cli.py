"""
run_cli.py
-----------

CipherTalk CLI - Parte 2
- Cadastro de usuário com geração de par RSA.
- Login com JWT.
- Listagem de usuários com status online/offline e presença de chave pública.
"""

import asyncio
import json
import os
import re
import sys
from getpass import getpass
from base64 import b64encode
from dotenv import load_dotenv

from backend.crypto.rsa_manager import generate_rsa_keypair

# 🌱 Carregar variáveis de ambiente
load_dotenv()
HOST = os.getenv("SERVER_HOST", "127.0.0.1")
PORT = int(os.getenv("SERVER_PORT", "8888"))

# 📁 Criar diretórios obrigatórios
os.makedirs("keys", exist_ok=True)
os.makedirs("logs", exist_ok=True)

USERNAME_REGEX = r"^[A-Za-z0-9_]+$"


def validar_senha(password: str) -> bool:
    """Política de senha segura."""
    return (
        len(password) >= 8
        and re.search(r"[A-Z]", password)
        and re.search(r"[0-9]", password)
        and re.search(r"[^A-Za-z0-9]", password)
    )


async def cadastrar_usuario():
    """Fluxo de cadastro com geração de par RSA."""
    print("\n=== 📝 Cadastro de Novo Usuário ===")
    username = input("👤 Nome de usuário: ").strip()

    if not re.match(USERNAME_REGEX, username):
        print("❌ Nome de usuário inválido. Use apenas letras, números e _.")
        return

    password = getpass("🔑 Crie uma senha: ")
    confirmar = getpass("🔁 Confirme a senha: ")

    if password != confirmar:
        print("❌ As senhas não coincidem.")
        return

    if not validar_senha(password):
        print("❌ A senha deve ter pelo menos 8 caracteres, 1 maiúscula, 1 número e 1 caractere especial.")
        return

    # 🔐 Geração do par RSA
    public_key, private_key = generate_rsa_keypair()

    # 💾 Salvar chave privada localmente
    private_path = f"keys/{username}_private.pem"
    with open(private_path, "wb") as f:
        f.write(private_key)
    print(f"🔑 Chave privada salva em: {private_path}")

    # 📤 Converter chave pública em Base64 para enviar ao servidor
    public_key_b64 = b64encode(public_key).decode()

    # 📡 Enviar cadastro ao servidor
    reader, writer = await asyncio.open_connection(HOST, PORT)
    payload = {
        "action": "register",
        "username": username,
        "password": password,
        "public_key": public_key_b64
    }
    writer.write((json.dumps(payload) + "\n").encode("utf-8"))
    await writer.drain()

    response = await reader.readline()
    print(response.decode().strip())

    writer.close()
    await writer.wait_closed()


async def listar_usuarios(token: str):
    """Solicita ao servidor a lista de usuários e exibe status."""
    reader, writer = await asyncio.open_connection(HOST, PORT)

    payload = {
        "action": "list_users",
        "token": token
    }
    writer.write((json.dumps(payload) + "\n").encode("utf-8"))
    await writer.drain()

    response = await reader.readline()
    if not response:
        print("❌ Falha ao receber a lista de usuários.")
        return

    data = json.loads(response.decode().strip())
    print("\n=== 👥 Usuários cadastrados ===")
    for u in data["users"]:
        status = "🟢 Online" if u["online"] else "⚫ Offline"
        key_status = "✅ Pública OK" if u["public_key"] else "❌ Sem chave pública"
        print(f"- {u['username']} | {status} | {key_status}")

    writer.close()
    await writer.wait_closed()


async def fazer_login():
    """Fluxo de login com token JWT e listagem de usuários."""
    print("\n=== 🔐 Login ===")
    username = input("👤 Nome de usuário: ").strip()
    password = getpass("🔑 Senha: ")

    reader, writer = await asyncio.open_connection(HOST, PORT)
    payload = {
        "action": "login",
        "username": username,
        "password": password
    }
    writer.write((json.dumps(payload) + "\n").encode("utf-8"))
    await writer.drain()

    response = await reader.readline()
    if not response:
        print("❌ Falha de conexão com o servidor.")
        return

    data = json.loads(response.decode().strip())
    if "token" not in data:
        print("❌ Usuário ou senha inválidos.")
        return

    token = data["token"]
    print(f"✅ Login bem-sucedido! Bem-vindo(a), {username}\n")

    # 📋 Mostrar lista de usuários
    await listar_usuarios(token)

    print("\n📬 Em breve: chat individual e grupos...")
    input("\nPressione ENTER para voltar ao menu inicial.")


async def menu_principal():
    """Menu inicial do cliente."""
    while True:
        os.system("clear" if os.name != "nt" else "cls")
        print("=== 🔐 CipherTalk CLI ===")
        print("1️⃣  - Cadastrar novo usuário")
        print("2️⃣  - Fazer login")
        print("0️⃣  - Sair")

        opcao = input("Escolha uma opção: ").strip()
        if opcao == "1":
            await cadastrar_usuario()
            input("\nPressione ENTER para continuar...")
        elif opcao == "2":
            await fazer_login()
        elif opcao == "0":
            print("👋 Encerrando cliente...")
            sys.exit(0)
        else:
            print("❌ Opção inválida.")
            input("\nPressione ENTER para continuar...")


if __name__ == "__main__":
    try:
        asyncio.run(menu_principal())
    except KeyboardInterrupt:
        print("\n👋 Cliente encerrado pelo usuário.")
