import asyncio
import base64
import ssl
import json
from typing import Dict
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

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
    Mantém conexão TLS aberta (não fecha).
    """
    conn = TLS_CONNECTIONS.get(username)
    if conn and not conn["writer"].is_closing():
        return conn

    reader, writer = await asyncio.open_connection(TCP_HOST, TCP_PORT, ssl=SSL_CONTEXT)
    TLS_CONNECTIONS[username] = {"reader": reader, "writer": writer}
    print(f"[TLS TEST] 🔗 Conexão TLS aberta para {username} — ativa.")

    # Restaura sessão
    resume_payload = {"action": "resume_session", "token": token}
    writer.write(json.dumps(resume_payload).encode() + b"\n")
    await writer.drain()

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
    db = SessionLocal()
    try:
        return await handle_register_rest(db, req.dict())
    finally:
        db.close()


@app.post("/api/login")
async def api_login(req: AuthRequest):
    db = SessionLocal()
    try:
        result, token = await handle_login_rest(db, req.dict())
        if result.get("status") == "error":
            raise HTTPException(status_code=401, detail=result.get("message"))
        return result
    finally:
        db.close()


# ======================================================
# 💬 MENSAGENS - HISTÓRICO (INBOX) com decifração condicional
# ======================================================
@app.get("/api/messages/inbox/{username}")
async def api_inbox(username: str):
    """
    Retorna mensagens trocadas com o usuário.
    Decifra **apenas** quando o usuário é o destinatário.
    Para mensagens enviadas pelo próprio usuário (outgoing),
    não tenta decifrar (evita erro) e marca `outgoing: true`.
    """
    from backend.crypto.idea_manager import IDEAManager

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail=f"Usuário '{username}' não encontrado.")

        # Carrega PEM da chave privada do usuário (p/ decifrar quando ele for o destinatário)
        priv_path = f"keys/{username}_private.pem"
        try:
            with open(priv_path, "r") as f:
                private_key_pem = f.read()
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail=f"Chave privada de '{username}' não encontrada em {priv_path}")

        # Busca todas as mensagens enviadas/recebidas por esse usuário
        messages = (
            db.query(Message)
            .filter((Message.sender_id == user.id) | (Message.receiver_id == user.id))
            .order_by(Message.timestamp.asc())
            .all()
        )

        formatted = []
        for msg in messages:
            sender_user = db.query(User).get(msg.sender_id)
            receiver_user = db.query(User).get(msg.receiver_id)

            # Define se é outgoing (eu enviei) ou incoming (eu recebi)
            is_outgoing = sender_user and sender_user.username == username
            content_plain = None

            if not is_outgoing:
                # Decifra APENAS quando eu sou o destinatário real
                try:
                    content_plain = IDEAManager().decifrar_do_chat(
                        packet=msg.content_encrypted,
                        cek_b64=msg.key_encrypted,
                        destinatario=username,
                        chave_privada_pem=private_key_pem,
                    )
                except Exception as e:
                    print(f"[DECRYPT_FAIL] {msg.id} → {e}")
                    content_plain = "(erro ao decifrar)"
            else:
                # Eu enviei: não tenta decifrar (CEK cifrada com a chave do outro).
                # Se quiser, você pode retornar o ciphertext para depuração:
                # content_plain = msg.content_encrypted
                content_plain = None  # mantém limpo; o front pode lidar usando `outgoing: true`

            formatted.append({
                "id": msg.id,
                "sender": sender_user.username if sender_user else "Desconhecido",
                "receiver": receiver_user.username if receiver_user else "Desconhecido",
                "content": content_plain,                   # somente claro se eu for destinatário
                "content_encrypted": msg.content_encrypted, # útil se quiser exibir rótulo/depuração
                "key_encrypted": msg.key_encrypted,
                "outgoing": is_outgoing,
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
    """
    Cifra com IDEA + RSA (E2EE) e envia ao servidor TLS com a CEK cifrada.
    """
    from backend.crypto.idea_manager import IDEAManager
    from hashlib import sha256

    db = SessionLocal()
    try:
        data = await req.json()
        token = data.get("token")
        to = data.get("to")
        content = data.get("content", "")
        signature_b64 = data.get("signature")  # opcional

        if not token or not to or not content:
            raise HTTPException(status_code=400, detail="Campos obrigatórios ausentes (token, to, content).")

        sender = verify_access_token(token)
        if not sender:
            raise HTTPException(status_code=401, detail="❌ Token inválido.")

        receiver = db.query(User).filter(User.username == to).first()
        if not receiver or not receiver.public_key:
            raise HTTPException(status_code=404, detail=f"Destinatário '{to}' não encontrado ou sem chave pública.")

        pubkey_pem = receiver.public_key.decode("utf-8", errors="ignore")

        idea = IDEAManager()
        content_encrypted_b64, cek_rsa_b64 = idea.cifrar_para_chat(
            texto_plano=content,
            remetente=sender,
            destinatario=to,
            chave_publica_destinatario_pem=pubkey_pem,
        )

        content_hash = sha256(content.encode("utf-8")).hexdigest()

        payload = {
            "action": "send_message",
            "token": token,
            "to": to,
            "content_encrypted": content_encrypted_b64,
            "key_encrypted": cek_rsa_b64,
            "content_hash": content_hash,
            "signature": signature_b64,
        }

        await ensure_tls_connection(sender, token)
        writer = TLS_CONNECTIONS[sender]["writer"]
        writer.write(json.dumps(payload).encode() + b"\n")
        await writer.drain()

        print(f"[SEND_OK] {sender} → {to}")
        return {"status": "success", "message": f"Mensagem enviada de {sender} para {to}."}

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
    await manager.connect(websocket)
    try:
        while True:
            msg = await websocket.receive_text()
            await manager.broadcast({"message": msg})
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ======================================================
# 🏁 STARTUP
# ======================================================
@app.on_event("startup")
async def startup_event():
    asyncio.create_task(start_keepalive())
    asyncio.create_task(cleanup_tls())
