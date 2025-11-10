from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from backend.utils.logger_config import get_logger
from client.auth import login_cli, signup_cli
from backend.messages import cli as msg_cli
from backend.messages import listener

logger = get_logger("messages_logger")

app = FastAPI()

# Permitir acesso do frontend (Next.js)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/signup")
def signup(data: dict):
    username = data.get("username")
    password = data.get("password")
    logger.info(f"Tentando cadastrar {username}")
    try:
        result = signup_cli.signup(username, password)
        return {"success": True, "message": "Cadastro realizado!", "result": result}
    except Exception as e:
        logger.error(f"Erro no signup: {e}")
        return {"success": False, "error": str(e)}


@app.post("/login")
def login(data: dict):
    username = data.get("username")
    password = data.get("password")
    logger.info(f"Tentando login de {username}")
    try:
        result = login_cli.login(username, password)
        return {"success": True, "message": "Login ok", "result": result}
    except Exception as e:
        logger.error(f"Erro no login: {e}")
        return {"success": False, "error": str(e)}


@app.post("/send")
def send_message(data: dict):
    sender = data.get("username")
    msg = data.get("message")
    try:
        msg_cli.send_message(sender, msg)
        return {"success": True}
    except Exception as e:
        logger.error(f"Erro ao enviar mensagem: {e}")
        return {"success": False, "error": str(e)}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    logger.info("Cliente conectado ao WebSocket.")

    # Exemplo básico com listener em thread
    import queue, threading
    msg_queue = queue.Queue()
    threading.Thread(
        target=listener.start_listener_with_reconnect,
        args=("0.0.0.0", 9000, 5, msg_queue),
        daemon=True
    ).start()

    try:
        while True:
            # mensagens novas do listener
            if not msg_queue.empty():
                msg = msg_queue.get()
                await websocket.send_text(f"{msg['from']}: {msg['body']}")
            # mensagens do frontend
            data = await websocket.receive_text()
            logger.info(f"Mensagem do cliente: {data}")
    except Exception as e:
        logger.error(f"WebSocket desconectado: {e}")