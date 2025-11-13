"""
server.py
----------

Servidor de mensagens seguro baseado em AsyncIO para CipherTalk.
- Suporta múltiplas conexões TLS de usuários
- Gerencia register, login, resume_session, list_users e send_message
- Mantém roteamento com criptografia ponta-a-ponta (IDEA + RSA)
"""

import sys
import os
import asyncio
import json
import ssl
import subprocess
from typing import Dict

# ----------------------------
# Garantir import global
# ----------------------------
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from dotenv import load_dotenv
from sqlalchemy.orm import Session
from backend.database.connection import SessionLocal, engine
from backend.auth.models import Base
from backend.server.handlers import (
    handle_register,
    handle_login,
    handle_list_users,
    handle_send_message,
    handle_send_group_message,
)
from backend.auth.auth_jwt import verify_access_token
from backend.utils.logger_config import disponibilidade_logger as log

# ----------------------------
# Configurações gerais
# ----------------------------
load_dotenv()
HOST = os.getenv("SERVER_HOST", "0.0.0.0")
PORT = int(os.getenv("SERVER_PORT", "8888"))

ONLINE_USERS: Dict[str, asyncio.StreamWriter] = {}


# ==========================================================
# 🔐 CONFIGURAÇÃO SSL/TLS
# ==========================================================
def ensure_certificates():
    """Gera certificados TLS autoassinados se não existirem."""
    if not (os.path.exists("cert.pem") and os.path.exists("key.pem")):
        print("🔐 Gerando certificado TLS autoassinado...")

        comandos_openssl = [
            "openssl", "req", "-new", "-x509", "-days", "365",
            "-nodes", "-out", "cert.pem", "-keyout", "key.pem",
            "-subj", "/CN=CipherTalk-Server"
        ]

        ssl_candidates = [
            "openssl", "C:\\Program Files (x86)\\Git\\usr\\bin\\openssl.exe",
            "C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe",
            "C:\\Program Files (x86)\\OpenSSL-Win32\\bin\\openssl.exe",
            "C:\\Program Files\\Git\\usr\\bin\\openssl.exe"
        ]

        for ssl_bin in ssl_candidates:
            try:
                comandos_openssl[0] = ssl_bin
                subprocess.run(comandos_openssl, check=True, capture_output=True, text=True)
                print("✅ Certificados TLS gerados com sucesso.")
                log.info("🔐 Certificados TLS autoassinados gerados.")
                return
            except FileNotFoundError:
                log.warning(f"⚠️ OpenSSL não encontrado: {ssl_bin}")
            except subprocess.CalledProcessError as e:
                log.error(f"❌ Falha ao executar OpenSSL ({ssl_bin}): {e.stderr or e}")
            except Exception as e:
                log.error(f"❌ Erro inesperado ao tentar gerar certificados: {e}")

        log.error("🚫 Nenhuma versão funcional do OpenSSL foi encontrada.")


def create_ssl_context() -> ssl.SSLContext:
    ensure_certificates()
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
    return context


# ==========================================================
# 🧩 BANCO E PORTA
# ==========================================================
def ensure_database():
    Base.metadata.create_all(bind=engine)
    print("🗄️ Banco de dados verificado e atualizado com sucesso.")
    log.info("🗄️ Banco de dados verificado e atualizado com sucesso.")


def free_port(port: int):
    """Libera a porta caso esteja ocupada (Unix/mac)."""
    try:
        output = subprocess.getoutput(f"lsof -ti:{port}")
        if output:
            for pid in output.splitlines():
                subprocess.run(["kill", "-9", pid], check=False)
            log.warning(f"⚙️ Porta {port} liberada de processos antigos.")
    except Exception as e:
        log.error(f"⚠️ Não foi possível liberar a porta {port}: {e}")


# ==========================================================
# 🧠 CONEXÕES TLS
# ==========================================================
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Gerencia nova conexão TLS e mantém sessão ativa indefinidamente."""
    db: Session = SessionLocal()
    username = None
    addr = writer.get_extra_info("peername")
    log.info(f"[CONNECT] Nova conexão recebida de {addr}")
    print(f"📡 Nova conexão recebida de {addr}")

    try:
        # Espera primeira ação (login ou resume_session)
        data = await reader.readline()
        if not data:
            log.warning(f"[WARN] Conexão sem dados iniciais de {addr}")
            return

        message = json.loads(data.decode().strip())
        action = message.get("action")

        # =====================================================
        # LOGIN OU RESTAURAÇÃO
        # =====================================================
        if action == "resume_session":
            token = message.get("token")
            try:
                username = verify_access_token(token)
                print(f"[SERVER DEBUG] Token recebido no TLS: {token}")
            except Exception as e:
                log.error(f"[RESUME ERROR] Falha ao verificar token: {e}")
                username = None

            if not username:
                writer.write('{"status":"error","message":"AUTH_FAILED"}\n'.encode("utf-8"))
                await writer.drain()
                log.warning(f"[RESUME_FAIL] Token inválido em {addr}")
                return

            # guarda a conexão do usuário
            ONLINE_USERS[username] = writer
            log.info(f"[RESUME] Sessão restaurada para {username}")
            print(f"✅ [RESUME] {username} adicionado ao ONLINE_USERS. Total de usuários online: {len(ONLINE_USERS)}")
            writer.write('{"status":"ok","message":"Sessão restaurada"}\n'.encode("utf-8"))
            await writer.drain()

        elif action == "register":
            await handle_register(db, writer, message)
            return

        elif action == "login":
            username, token = await handle_login(db, writer, message, ONLINE_USERS)
            if not username:
                return
            print(f"✅ [LOGIN] {username} adicionado ao ONLINE_USERS via login. Total de usuários online: {len(ONLINE_USERS)}")

        else:
            writer.write('{"status":"error","message":"Ação inicial inválida"}\n'.encode("utf-8"))
            await writer.drain()
            log.warning(f"[INVALID_ACTION] {action}")
            return

        # =====================================================
        # LOOP PRINCIPAL — NÃO FECHA AUTOMATICAMENTE
        # =====================================================
        while True:
            data = await reader.readline()

            # não fecha em inatividade — apenas continua
            if not data:
                await asyncio.sleep(0.5)
                continue

            try:
                payload = json.loads(data.decode().strip())
                action = payload.get("action")

                if action == "ping":
                    writer.write('{"status":"pong"}\n'.encode("utf-8"))
                    await writer.drain()

                elif action == "resume_session":
                    from backend.server.handlers import handle_resume_session
                    await handle_resume_session(db, writer, payload, ONLINE_USERS)
                    continue

                elif action == "list_users":
                    await handle_list_users(db, writer, payload, ONLINE_USERS)

                elif action == "send_message":
                    await handle_send_message(db, payload, ONLINE_USERS)

                elif action == "send_group_message":
                    await handle_send_group_message(db, payload, ONLINE_USERS)

                else:
                    writer.write('{"status":"warn","message":"Ação desconhecida"}\n'.encode("utf-8"))
                    await writer.drain()

            except json.JSONDecodeError:
                writer.write('{"status":"error","message":"JSON inválido"}\n'.encode("utf-8"))
                await writer.drain()
            except Exception as e:
                log.error(f"[ERROR] Falha ao processar ação: {e}")
                print(f"⚠️ Erro ao processar ação: {e}")
                await asyncio.sleep(1)

    except Exception as e:
        log.error(f"[ERROR] Conexão encerrada com erro: {e}")
        print(f"💥 Erro de conexão: {e}")

    finally:
        # Não fecha writer — apenas limpa referência
        if username and username in ONLINE_USERS:
            del ONLINE_USERS[username]
            log.info(f"[LOGOUT] {username} desconectado.")
        db.close()


# ==========================================================
# 🚀 MAIN
# ==========================================================
async def main():
    ensure_database()
    ssl_context = create_ssl_context()
    free_port(PORT)

    retry_count = 0
    while True:
        try:
            server = await asyncio.start_server(handle_client, HOST, PORT, ssl=ssl_context)
            addr = server.sockets[0].getsockname()
            print(f"[SERVER] Servidor seguro rodando em {addr} (TLS habilitado)")
            log.info(f"[START] Servidor ativo em {addr} com TLS")

            async with server:
                await server.serve_forever()

        except OSError as e:
            retry_count += 1
            print(f"⚠️ Porta {PORT} ocupada ou erro ({retry_count}). Tentando em 2s...")
            await asyncio.sleep(2)
        except Exception as e:
            log.error(f"[FATAL] {e}")
            await asyncio.sleep(2)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[SERVER] Encerrado pelo usuário.")
        log.info("[STOP] Servidor encerrado manualmente.")