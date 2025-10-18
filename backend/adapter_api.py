import asyncio
import ssl
import json
from typing import Dict
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import joinedload

from backend.database.connection import SessionLocal
from backend.server.handlers_rest import handle_register_rest, handle_login_rest
from backend.auth.models import User, Message
from backend.auth.auth_jwt import verify_access_token

# ======================================================
# 🔐 CONFIGURAÇÃO DE REDE (TLS)
# ======================================================
TCP_HOST = "127.0.0.1"
TCP_PORT = 8888
SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE

# ======================================================
# 🔄 CONEXÕES TLS PERSISTENTES
# ======================================================
TLS_CONNECTIONS: Dict[str, Dict[str, asyncio.StreamWriter]] = {}

async def ensure_tls_connection(username: str, token: str):
    """
    🧪 TESTE: Mantém conexão TLS aberta indefinidamente (nunca fecha).
    """
    conn = TLS_CONNECTIONS.get(username)

    if conn and not conn["writer"].is_closing():
        # Já tem conexão ativa
        return conn

    # 🔗 Cria nova conexão TLS
    reader, writer = await asyncio.open_connection(TCP_HOST, TCP_PORT, ssl=SSL_CONTEXT)
    TLS_CONNECTIONS[username] = {"reader": reader, "writer": writer}
    print(f"[TLS TEST] 🔗 Conexão TLS aberta para {username} — nunca será fechada.")

    # 🔐 Envia ação de restauração de sessão
    resume_payload = {"action": "resume_session", "token": token}
    writer.write(json.dumps(resume_payload).encode() + b"\n")
    await writer.drain()

    # 🔄 Mantém o socket aberto pra sempre
    async def keep_forever():
        try:
            while True:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass

    asyncio.create_task(keep_forever())

    # 🔍 Também escuta as mensagens TLS (apenas printa)
    async def listen_tls():
        try:
            while not reader.at_eof():
                data = await reader.readline()
                if not data:
                    break
                msg = data.decode().strip()
                print(f"[TLS][{username}] {msg}")
        except Exception as e:
            print(f"[TLS_READ_ERROR][{username}] {e}")

    asyncio.create_task(listen_tls())

    return TLS_CONNECTIONS[username]


# ======================================================
# 🫀 PING AUTOMÁTICO (KEEP-ALIVE)
# ======================================================
async def start_keepalive():
    """Envia ping TLS a cada 30 segundos pra manter sessões abertas."""
    while True:
        await asyncio.sleep(30)
        for username, conn in list(TLS_CONNECTIONS.items()):
            writer = conn.get("writer")
            if writer and not writer.is_closing():
                try:
                    writer.write(json.dumps({"action": "ping"}).encode() + b"\n")
                    await writer.drain()
                    print(f"[PING] mantida conexão ativa para {username}")
                except Exception as e:
                    print(f"[PING_FAIL][{username}] {e}")


# ======================================================
# 🚀 FASTAPI APP
# ======================================================
app = FastAPI(title="CipherTalk Adapter API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ======================================================
# 📦 MODELOS DE REQUISIÇÃO
# ======================================================
class AuthRequest(BaseModel):
    username: str
    password: str


# ======================================================
# 👤 REGISTRO E LOGIN
# ======================================================
@app.post("/api/register")
async def api_register(req: AuthRequest):
    """Cria um novo usuário no banco de dados."""
    db = SessionLocal()
    try:
        return await handle_register_rest(db, req.dict())
    finally:
        db.close()


@app.post("/api/login")
async def api_login(req: AuthRequest):
    """Autentica o usuário e retorna o token JWT."""
    db = SessionLocal()
    try:
        result, token = await handle_login_rest(db, req.dict())
        if result.get("status") == "error":
            raise HTTPException(status_code=401, detail=result.get("message"))
        return result
    finally:
        db.close()


# ======================================================
# 💬 MENSAGENS - HISTÓRICO (INBOX)
# ======================================================
@app.get("/api/messages/inbox/{username}")
async def api_inbox(username: str):
    """Retorna todas as mensagens destinadas a um usuário."""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail=f"Usuário '{username}' não encontrado.")

        messages = (
            db.query(Message)
            .join(User, User.id == Message.receiver_id)
            .filter(User.username == username)
            .options(joinedload(Message.sender))
            .all()
        )

        formatted = []
        for msg in messages:
            sender_user = db.query(User).get(msg.sender_id)
            formatted.append({
                "id": msg.id,
                "sender": sender_user.username if sender_user else "Desconhecido",
                "receiver": username,
                "content": msg.content_encrypted or "(vazio)",
                "timestamp": str(msg.timestamp),
            })

        return {"messages": formatted}

    except HTTPException:
        raise
    except Exception as e:
        print(f"[ERROR] /api/messages/inbox -> {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


# ======================================================
# 💌 MENSAGENS - ENVIO
# ======================================================
@app.post("/api/messages/send")
async def api_send_message(req: Request):
    data = await req.json()
    print(f"[DEBUG] Dados recebidos do frontend: {data}")

    """Recebe mensagem do frontend e repassa ao servidor TLS."""
    db = SessionLocal()
    try:
        data = await req.json()
        token = data.get("token")
        to = data.get("to")
        content = data.get("content")

        if not token or not to or not content:
            raise HTTPException(status_code=400, detail="Campos obrigatórios ausentes (token, to, content).")

        username = verify_access_token(token)
        print(f"[DEBUG] Token recebido: {token}")
        print(f"[DEBUG] Usuário decodificado: {username}")
        await ensure_tls_connection(username, token)

        payload = {
            "action": "send_message",
            "token": token,
            "to": to,
            "content_encrypted": content,
            "key_encrypted": "dummy-key",  # valor placeholder
        }

        writer = TLS_CONNECTIONS[username]["writer"]
        writer.write(json.dumps(payload).encode() + b"\n")
        await writer.drain()

        print(f"[SEND_OK] {username} → {to}")
        return {"status": "success", "message": f"Mensagem enviada de {username} para {to}."}

    except HTTPException:
        raise
    except Exception as e:
        print(f"[ERROR] /api/messages/send -> {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


# ======================================================
# ♻️ LIMPEZA DE CONEXÕES TLS INATIVAS
# ======================================================
async def cleanup_tls():
    """Fecha conexões inativas para evitar vazamento."""
    while True:
        await asyncio.sleep(15)
        to_remove = [u for u, c in TLS_CONNECTIONS.items() if c["writer"].is_closing()]
        for u in to_remove:
            del TLS_CONNECTIONS[u]
            print(f"[CLEANUP] Conexão TLS removida: {u}")


# ======================================================
# 🌐 WEBSOCKET (opcional futuro)
# ======================================================
class ConnectionManager:
    """Gerencia conexões WebSocket com o navegador."""
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for ws in list(self.active_connections):
            try:
                await ws.send_json(message)
            except:
                self.disconnect(ws)


manager = ConnectionManager()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Futuro canal WebSocket em tempo real."""
    await manager.connect(websocket)
    try:
        while True:
            msg = await websocket.receive_text()
            await manager.broadcast({"message": msg})
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ======================================================
# 🏁 EVENTO DE STARTUP
# ======================================================
@app.on_event("startup")
async def startup_event():
    asyncio.create_task(start_keepalive())
    asyncio.create_task(cleanup_tls())
