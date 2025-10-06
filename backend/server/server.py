"""
server.py
----------

AsyncIO-based secure messaging server for CipherTalk.
- Uses TLS (SSL) for encrypted transport layer.
- Automatically releases occupied ports.
- Delegates all logic to backend/server/handlers.py.
"""

import sys
import os
import asyncio
import json
import ssl
import socket
import logging
import subprocess
from typing import Dict

# ----------------------------
# Garantir import global
# ----------------------------
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from dotenv import load_dotenv
from sqlalchemy.orm import Session

from backend.database.connection import engine, Base
from backend.database.connection import SessionLocal
from backend.server.handlers import (
    handle_register,
    handle_login,
    handle_list_users,
    handle_send_message,
)

# ----------------------------
# ⚙️ Configurações gerais
# ----------------------------
load_dotenv()
HOST = os.getenv("SERVER_HOST", "127.0.0.1")
PORT = int(os.getenv("SERVER_PORT", "8888"))

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    filename="logs/server.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

ONLINE_USERS: Dict[str, asyncio.StreamWriter] = {}

# ----------------------------
# 🔒 SSL/TLS Configuration
# ----------------------------
def ensure_certificates():
    """Generate self-signed TLS certificate if not exist."""
    if not (os.path.exists("cert.pem") and os.path.exists("key.pem")):
        print("🔐 Gerando certificado TLS autoassinado...")
        subprocess.run(
            [
                "openssl", "req", "-new", "-x509", "-days", "365",
                "-nodes", "-out", "cert.pem", "-keyout", "key.pem",
                "-subj", "/CN=CipherTalk-Server"
            ],
            check=True
        )
        print("✅ Certificados TLS gerados com sucesso.")

def create_ssl_context() -> ssl.SSLContext:
    """Create an SSL context for the secure server."""
    ensure_certificates()
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
    return context

# ----------------------------
# 🔧 Liberação automática da porta
# ----------------------------
def free_port(port: int):
    """Forcefully free the port if occupied."""
    try:
        # Linux/macOS
        output = subprocess.getoutput(f"lsof -ti:{port}")
        if output:
            for pid in output.splitlines():
                subprocess.run(["kill", "-9", pid], check=False)
            print(f"⚙️ Porta {port} liberada de processos antigos.")
    except Exception as e:
        print(f"⚠️ Não foi possível liberar a porta {port}: {e}")


# ----------------------------
# 🔁 Manipulação de conexões
# ----------------------------
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Handles new client connections and delegates to handlers."""
    db: Session = SessionLocal()
    username = None
    addr = writer.get_extra_info("peername")
    logging.info(f"[CONNECT] Nova conexão recebida de {addr}")
    print(f"📡 Nova conexão recebida de {addr}")

    try:
        data = await reader.readline()
        if not data:
            return

        message = json.loads(data.decode().strip())
        action = message.get("action")

        if action == "register":
            await handle_register(db, writer, message)
            writer.close()
            await writer.wait_closed()
            return

        elif action == "login":
            username, token = await handle_login(db, writer, message, ONLINE_USERS)
            if not username:
                writer.close()
                await writer.wait_closed()
                return

        else:
            writer.write("❌ Ação inicial inválida.\n".encode("utf-8"))
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        # ----------------------------------------------------
        # Loop principal: processa ações pós-login
        # ----------------------------------------------------
        while True:
            data = await reader.readline()
            if not data:
                break

            try:
                payload = json.loads(data.decode().strip())
                action = payload.get("action")

                if action == "list_users":
                    await handle_list_users(db, writer, payload, ONLINE_USERS)
                elif action == "send_message":
                    await handle_send_message(db, payload, ONLINE_USERS)
                else:
                    logging.warning(f"[WARN] Ação desconhecida recebida: {action}")
                    writer.write(f"❌ Ação desconhecida: {action}\n".encode("utf-8"))
                    await writer.drain()

            except json.JSONDecodeError:
                logging.warning("[WARN] JSON inválido recebido.")
                writer.write("❌ Erro: mensagem inválida (JSON incorreto).\n".encode("utf-8"))
                await writer.drain()
            except Exception as e:
                logging.error(f"[ERROR] Falha ao processar ação: {e}")
                print(f"⚠️ Erro ao processar ação: {e}")

    except Exception as e:
        logging.error(f"[ERROR] Conexão encerrada com erro: {e}")
        print(f"💥 Erro de conexão: {e}")

    finally:
        if username and username in ONLINE_USERS:
            del ONLINE_USERS[username]
            logging.info(f"[LOGOUT] {username} desconectado.")
        writer.close()
        await writer.wait_closed()


# ----------------------------
# 🗄️ Inicialização automática do banco
# ----------------------------

# 🎨 Cores ANSI para saída no terminal
class Color:
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"


def ensure_database():
    """Garante que todas as tabelas essenciais existem no banco."""
    try:
        # 🔹 Importa explicitamente os modelos (garante que as tabelas sejam conhecidas)
        from backend.auth.models import User, Group, GroupMember, Message  # noqa: F401

        Base.metadata.create_all(bind=engine)
        print(f"{Color.GREEN}🗄️ Banco de dados verificado e atualizado com sucesso.{Color.RESET}")

    except Exception as e:
        print(f"{Color.RED}💥 Erro ao verificar/criar banco: {e}{Color.RESET}")


# ----------------------------
# 🚀 Inicialização do servidor
# ----------------------------
async def main():
    """Start the secure messaging server."""
    ensure_database()
    ssl_context = create_ssl_context()
    free_port(PORT)

    retry_count = 0
    while True:
        try:
            server = await asyncio.start_server(
                handle_client, HOST, PORT, ssl=ssl_context
            )
            addr = server.sockets[0].getsockname()
            print(f"[SERVER] Servidor seguro rodando em {addr} (TLS habilitado)")
            logging.info(f"[START] Servidor ativo em {addr} com TLS")
            async with server:
                await server.serve_forever()
            break
        except OSError as e:
            retry_count += 1
            print(f"⚠️ Porta {PORT} ocupada ou erro ao iniciar ({retry_count}). Tentando novamente em 2s...")
            logging.warning(f"[WARN] Falha ao iniciar servidor ({e}), tentativa {retry_count}")
            await asyncio.sleep(2)
        except Exception as e:
            print(f"💥 Erro inesperado ao iniciar servidor: {e}")
            logging.error(f"[FATAL] {e}")
            await asyncio.sleep(2)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[SERVER] Encerrado pelo usuário.")
        logging.info("[STOP] Servidor encerrado manualmente.")
