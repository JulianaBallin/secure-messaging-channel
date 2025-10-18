import asyncio
import ssl
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.database.connection import SessionLocal
from backend.server.handlers_rest import handle_register_rest, handle_login_rest
from backend.auth.auth_jwt import verify_access_token
import json

TCP_HOST = "127.0.0.1"
TCP_PORT = 8888
SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE

app = FastAPI(title="CipherTalk Adapter API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------
# REST Models
# -------------------
class AuthRequest(BaseModel):
    username: str
    password: str

# -------------------
# REST Endpoints
# -------------------
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

# -------------------
# WebSocket Endpoint (com broadcast)
# -------------------
class ConnectionManager:
    """Gerencia conexão WebSocket com navegador."""
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        """Envia mensagem apenas para um cliente."""
        await websocket.send_json(message)

    async def broadcast(self, message: dict):
        """Envia mensagem para todos os clientes conectados."""
        disconnected = []
        for ws in self.active_connections:
            try:
                await ws.send_json(message)
            except:
                disconnected.append(ws)
        # remove conexões quebradas
        for ws in disconnected:
            self.disconnect(ws)


manager = ConnectionManager()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    tcp_reader, tcp_writer = None, None

    try:
        # Conecta ao servidor TCP (criptografado)
        tcp_reader, tcp_writer = await asyncio.open_connection(
            TCP_HOST, TCP_PORT, ssl=SSL_CONTEXT
        )

        async def tcp_to_ws():
            while True:
                data = await tcp_reader.readline()
                if not data:
                    break
                msg = data.decode().strip()
                # Envia a mensagem para todos conectados
                await manager.broadcast({"message": msg})

        tcp_task = asyncio.create_task(tcp_to_ws())

        while True:
            msg = await websocket.receive_text()

            try:
                parsed = json.loads(msg)
                if parsed.get("action") == "send_message":
                    content = parsed.get("content", "")
                    tcp_writer.write((content + "\n").encode())
                    await tcp_writer.drain()
                    # Envia mensagem também para todos conectados
                    await manager.broadcast({"message": f"Usuário: {content}"})

                elif parsed.get("action") == "resume_session":
                    token = parsed.get("token", "")
                    try:
                        verify_access_token(token)
                        await manager.send_personal_message(
                            {"message": "Sessão restaurada com sucesso."}, websocket
                        )
                    except Exception:
                        await manager.send_personal_message(
                            {"message": "Token inválido."}, websocket
                        )
            except json.JSONDecodeError:
                tcp_writer.write((msg + "\n").encode())
                await tcp_writer.drain()

    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"[WS ERROR] {e}")
        try:
            await websocket.send_json({"error": str(e)})
        except:
            pass
    finally:
        if tcp_writer:
            tcp_writer.close()
            await tcp_writer.wait_closed()
        manager.disconnect(websocket)
