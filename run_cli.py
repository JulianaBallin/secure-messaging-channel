"""
run_cli.py 

CipherTalk CLI Unificado
- Cadastro de usuário com RSA.
- Login com JWT.
- Envio e leitura de mensagens E2EE.
- Listagem de usuários com status online/offline.
"""

import asyncio
import json
import os
import re
import sys
from getpass import getpass
from base64 import b64encode
from dotenv import load_dotenv
from backend.utils.logger_config import messages_logger

# Importar módulos internos
sys.path.append(os.path.dirname(__file__))

from backend.crypto.rsa_manager import RSAManager
from backend.messages.cli import send_encrypted_message, read_and_decrypt_messages
from backend.messages.listener import start_listener


# -----------------------------
# Login centralizado (TLS)
# -----------------------------
async def perform_login():
    """Executa login seguro com o servidor (TLS) e retorna (username, token)."""
    import ssl

    try:
        username = input("👤 Nome de usuário: ").strip()
        password = getpass("🔑 Senha: ")

        # Contexto TLS
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        # Conectar ao servidor seguro
        reader, writer = await asyncio.open_connection(HOST, PORT, ssl=ssl_context)

        # Enviar payload de login
        payload = {"action": "login", "username": username, "password": password}
        writer.write((json.dumps(payload) + "\n").encode("utf-8"))
        await writer.drain()

        # Receber resposta
        response = await reader.readline()
        writer.close()
        await writer.wait_closed()

        if not response:
            print("❌ Falha ao conectar ao servidor.")
            return None, None

        # Processar resposta
        data = json.loads(response.decode().strip())
        if "token" not in data:
            messages_logger.info("❌ Usuário ou senha inválidos.")
            return None, None

        messages_logger.info(f"✅ Login bem-sucedido! Bem-vindo(a), {username}.")
        return username, data["token"]

    except ConnectionRefusedError:
        messages_logger.info("❌ Servidor indisponível. Verifique se está em execução.")
        return None, None
    except Exception as e:
        messages_logger.info(f"⚠️ Erro inesperado no login: {e}")
        return None, None


# -----------------------------
# Configurações e pastas
# -----------------------------
load_dotenv()
HOST = os.getenv("SERVER_HOST", "127.0.0.1")
PORT = int(os.getenv("SERVER_PORT", "8888"))

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


# ======================================================
# Cadastro de usuário
# ======================================================
async def cadastrar_usuario():
    """Cadastra um novo usuário com par RSA."""
    print("\n=== 📝 Cadastro de Novo Usuário ===")
    username = input("👤 Nome de usuário: ").strip()

    if not re.match(USERNAME_REGEX, username):
        messages_logger.info("❌ Nome de usuário inválido. Use apenas letras, números e _.")
        return

    password = getpass("🔑 Crie uma senha: ")
    confirmar = getpass("🔁 Confirme a senha: ")

    if password != confirmar:
        messages_logger.info("❌ As senhas não coincidem.")
        return

    if not validar_senha(password):
        messages_logger.info("❌ A senha deve ter pelo menos 8 caracteres, 1 maiúscula, 1 número e 1 caractere especial.")
        return

    # ATENÇÃO: seu RSAManager.gerar_par_chaves() retorna (privada_str, publica_str)
    privada_pem_str, publica_pem_str = RSAManager.gerar_par_chaves()

    # Salva a chave privada como texto (matching com o retorno em string)
    private_path = f"keys/{username}_private.pem"
    with open(private_path, "w", encoding="utf-8") as f:
        f.write(privada_pem_str)
    print(f"🔑 Chave privada salva em: {private_path}")

    # Envia a pública em base64 para o servidor (esperado pelo backend)
    public_key_b64 = b64encode(publica_pem_str.encode("utf-8")).decode("utf-8")

    # Conexão (sem TLS aqui; mantenha como estava no seu servidor)
    reader, writer = await asyncio.open_connection(HOST, PORT)
    payload = {
        "action": "register",
        "username": username,
        "password": password,
        "public_key": public_key_b64,
    }
    writer.write((json.dumps(payload) + "\n").encode("utf-8"))
    await writer.drain()

    response = await reader.readline()
    if response:
        print(response.decode().strip())
    else:
        print("⚠️ Nenhuma resposta recebida do servidor durante o cadastro.")

    writer.close()
    await writer.wait_closed()


# ======================================================
# Listar usuários
# ======================================================
async def listar_usuarios(token: str):
    """Lista usuários online/offline."""
    reader, writer = await asyncio.open_connection(HOST, PORT)
    payload = {"action": "list_users", "token": token}
    writer.write((json.dumps(payload) + "\n").encode("utf-8"))
    await writer.drain()

    response = await reader.readline()
    if not response:
        messages_logger.info("❌ Falha ao receber a lista de usuários.")
        return

    data = json.loads(response.decode().strip())
    print("\n=== 👥 Usuários cadastrados ===")
    for u in data.get("users", []):
        status = "🟢 Online" if u.get("online") else "⚫ Offline"
        key_status = "✅ Pública OK" if u.get("public_key") else "❌ Sem chave pública"
        print(f"- {u.get('username','?')} | {status} | {key_status}")

    writer.close()
    await writer.wait_closed()


# ======================================================
# Login e menu interno
# ======================================================
async def fazer_login():
    """Login + menu interno pós-autenticação."""
    messages_logger.info("\n=== 🔐 Login ===")
    username, token = await perform_login()
    if not token:
        input("\nPressione ENTER para voltar ao menu inicial...")
        return

    # Listener assíncrono para receber mensagens em tempo real
    asyncio.create_task(start_listener(username, token, HOST, PORT))

    while True:
        os.system("cls" if os.name == "nt" else "clear")
        print(f"=== 💬 CipherTalk - Usuário: {username} ===")
        print("1️⃣  - Listar usuários")
        print("2️⃣  - Enviar mensagem segura (E2EE)")
        print("3️⃣  - Ler mensagens recebidas")
        print("0️⃣  - Logout")

        opcao = input("Escolha uma opção: ").strip()
        if opcao == "1":
            await listar_usuarios(token)
            input("\nPressione ENTER para continuar...")
        elif opcao == "2":
            # Mantém a função do módulo backend.messages.cli
            await send_encrypted_message(username, token, HOST, PORT)
            input("\nPressione ENTER para continuar...")
        elif opcao == "3":
            # Lê do armazenamento local (como seu fluxo original)
            read_and_decrypt_messages(username)
            input("\nPressione ENTER para continuar...")
        elif opcao == "0":
            print("👋 Logout efetuado.")
            break
        else:
            messages_logger.info("❌ Opção inválida.")
            input("\nPressione ENTER para continuar...")


# ======================================================
# Menu principal
# ======================================================
async def menu_principal():
    """Menu inicial do cliente."""
    while True:
        os.system("cls" if os.name == "nt" else "clear")
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
            messages_logger.info("👋 Encerrando cliente...")
            sys.exit(0)
        else:
            messages_logger.info("❌ Opção inválida.")
            input("\nPressione ENTER para continuar...")


# ======================================================
# ▶ Execução direta
# ======================================================
if __name__ == "__main__":
    try:
        asyncio.run(menu_principal())
    except KeyboardInterrupt:
        messages_logger.info("\n👋 Cliente encerrado pelo usuário.")
