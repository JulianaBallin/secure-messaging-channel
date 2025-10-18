# backend/server/handlers_rest.py
import asyncio
import json
from sqlalchemy.orm import Session
from backend.server.handlers import handle_register, handle_login
from backend.auth.auth_jwt import create_access_token
from backend.database.connection import SessionLocal
import ssl

TCP_HOST = "127.0.0.1"
TCP_PORT = 8888
SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE

# ------------------------------
# Registro REST-friendly
# ------------------------------
async def handle_register_rest(db: Session, creds: dict):
    """Chama handle_register e devolve resposta REST."""
    class DummyWriter:
        """Writer fake para capturar saída JSON."""
        def __init__(self):
            self.data = b""

        def write(self, b):
            self.data += b

        async def drain(self):
            pass

    writer = DummyWriter()
    await handle_register(db, writer, creds)
    try:
        result = json.loads(writer.data.decode())
        return result
    except Exception:
        return {"status": "error", "message": "Falha ao registrar"}

# ------------------------------
# Login REST-friendly
# ------------------------------
async def handle_login_rest(db: Session, creds: dict):
    """Chama handle_login e notifica servidor TCP para marcar online."""
    class DummyWriter:
        def write(self, b):
            self.data = b

        async def drain(self):
            pass

    writer = DummyWriter()
    online_users = {}  # temporário, só para chamar handle_login
    username, token = await handle_login(db, writer, creds, online_users)

    if not username:
        return {"status": "error", "message": "Credenciais inválidas"}, None

    # Agora abrimos conexão TCP/TLS para notificar o servidor que está online
    try:
        reader, writer_tcp = await asyncio.open_connection(
            TCP_HOST, TCP_PORT, ssl=SSL_CONTEXT
        )
        payload = {
            "action": "resume_session",
            "token": token
        }
        writer_tcp.write((json.dumps(payload) + "\n").encode())
        await writer_tcp.drain()
        writer_tcp.close()
        await writer_tcp.wait_closed()
    except Exception as e:
        print(f"[REST LOGIN WARNING] Não foi possível notificar TCP server: {e}")

    return {"status": "ok", "username": username, "token": token}, token
