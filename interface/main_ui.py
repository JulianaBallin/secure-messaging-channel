import asyncio
import threading
import queue
import datetime
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Button, Input, Static, Log
from textual.containers import Vertical, Horizontal
from backend.utils.logger_config import get_logger

logger = get_logger("messages_logger")

# === importar funções do projeto ===
try:
    from client.auth import login_cli, signup_cli
    from backend.messages import cli as msg_cli
    from backend.messages import listener as msg_listener
    from backend.server import handlers as handlers_mod
except Exception as e:
    logger.warning(f"Falha ao importar módulos: {e}")
    login_cli = signup_cli = msg_cli = msg_listener = handlers_mod = None


# =============== TELAS ===============

class LoginScreen(Vertical):
    def compose(self):
        yield Header(show_clock=True)
        yield Static("🔐 LOGIN", classes="center title")
        yield Input(placeholder="Usuário", id="username")
        yield Input(placeholder="Senha", password=True, id="password")
        yield Button("Entrar", id="login_btn")
        yield Button("Criar conta", id="goto_signup")
        yield Log(id="log_area")
        yield Footer()

    async def on_button_pressed(self, event):
        if event.button.id == "login_btn":
            username = self.query_one("#username").value
            password = self.query_one("#password").value
            await self.app.handle_login(username, password)
        elif event.button.id == "goto_signup":
            self.app.switch_screen("signup")


class SignupScreen(Vertical):
    def compose(self):
        yield Header(show_clock=True)
        yield Static("📝 CADASTRO", classes="center title")
        yield Input(placeholder="Usuário", id="username")
        yield Input(placeholder="Senha", password=True, id="password")
        yield Button("Cadastrar", id="signup_btn")
        yield Button("Voltar", id="goto_login")
        yield Log(id="log_area")
        yield Footer()

    async def on_button_pressed(self, event):
        if event.button.id == "signup_btn":
            username = self.query_one("#username").value
            password = self.query_one("#password").value
            await self.app.handle_signup(username, password)
        elif event.button.id == "goto_login":
            self.app.switch_screen("login")


class ChatScreen(Vertical):
    def __init__(self, username):
        super().__init__()
        self.username = username
        self.listener_queue = queue.Queue()

    def compose(self):
        yield Header(show_clock=True)
        yield Static(f"💬 Chat - {self.username}", classes="center title")
        yield Log(id="chat_area", highlight=True, wrap=True)
        with Horizontal():
            yield Input(placeholder="Digite sua mensagem...", id="msg_input")
            yield Button("Enviar", id="send_btn")
        yield Footer()

    async def on_mount(self):
        # Carregar mensagens offline
        await self.app.load_offline_messages(self.username)
        # Iniciar listener em thread separada
        threading.Thread(target=self.app.start_listener, args=(self.listener_queue,), daemon=True).start()
        # Iniciar consumo da fila de mensagens
        self.set_interval(0.5, self.consume_listener_queue)

    async def on_button_pressed(self, event):
        if event.button.id == "send_btn":
            msg = self.query_one("#msg_input").value
            if msg.strip():
                await self.app.send_message(self.username, msg)
                self.query_one("#msg_input").value = ""

    def consume_listener_queue(self):
        while not self.listener_queue.empty():
            item = self.listener_queue.get()
            chat_area = self.query_one("#chat_area")
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            chat_area.write(f"[{timestamp}] 📥 {item['from']}: {item['body']}")
            logger.info(f"Mensagem recebida: {item}")


# =============== APP PRINCIPAL ===============

class MessagingApp(App):
    CSS_PATH = None
    TITLE = "Secure Messaging UI"

    def on_mount(self):
        self.username = None
        self.screens = {
            "login": LoginScreen(),
            "signup": SignupScreen()
        }
        self.switch_screen("login")

    def switch_screen(self, name):
        # Remove qualquer tela montada
        for screen in self.screens.values():
            if screen.is_mounted:
                screen.remove()
        # Monta a nova tela
        self.mount(self.screens.get(name))

    async def handle_login(self, username, password):
        try:
            if login_cli:
                if hasattr(login_cli, "do_login"):
                    result = login_cli.do_login(username, password)
                elif hasattr(login_cli, "login"):
                    result = login_cli.login(username, password)
                else:
                    result = {"success": True}
            else:
                result = {"success": True}
        except Exception as e:
            result = {"success": False, "error": str(e)}

        log = self.query_one("#log_area")
        if result.get("success"):
            log.write("✅ Login bem-sucedido!")
            logger.info(f"{username} fez login com sucesso.")
            self.username = username
            self.mount(ChatScreen(username))
        else:
            log.write(f"❌ Falha no login: {result.get('error', 'Erro desconhecido')}")
            logger.error(f"Erro no login: {result}")

    async def handle_signup(self, username, password):
        try:
            if signup_cli:
                if hasattr(signup_cli, "do_signup"):
                    result = signup_cli.do_signup(username, password)
                elif hasattr(signup_cli, "signup"):
                    result = signup_cli.signup(username, password)
                else:
                    result = {"success": True}
            else:
                result = {"success": True}
        except Exception as e:
            result = {"success": False, "error": str(e)}

        log = self.query_one("#log_area")
        if result.get("success"):
            log.write("✅ Cadastro realizado com sucesso! Faça login.")
            logger.info(f"Usuário {username} cadastrado.")
        else:
            log.write(f"❌ Falha no cadastro: {result.get('error', 'Erro desconhecido')}")
            logger.error(f"Erro no cadastro: {result}")

    async def send_message(self, username, msg):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        chat_area = self.query_one("#chat_area")
        chat_area.write(f"[{timestamp}] 📨 Você: {msg}")
        logger.info(f"Mensagem enviada: {msg}")
        try:
            if msg_cli and hasattr(msg_cli, "send_message"):
                msg_cli.send_message(username, msg)
        except Exception as e:
            logger.error(f"Erro ao enviar mensagem: {e}")

    def start_listener(self, msg_queue):
        if not msg_listener:
            logger.warning("Listener não encontrado.")
            return
        try:
            if hasattr(msg_listener, "start_listener_with_reconnect"):
                msg_listener.start_listener_with_reconnect("127.0.0.1", 9000, retry_delay=5, msg_queue=msg_queue)
            elif hasattr(msg_listener, "start_listener"):
                msg_listener.start_listener("127.0.0.1", 9000, msg_queue=msg_queue)
            else:
                logger.warning("Função start_listener não encontrada.")
        except Exception as e:
            logger.error(f"Erro ao iniciar listener: {e}")

    async def load_offline_messages(self, username):
        try:
            if handlers_mod and hasattr(handlers_mod, "retrieve_offline_messages"):
                db = getattr(handlers_mod, "get_db", lambda: None)()
                msgs = handlers_mod.retrieve_offline_messages(db, username)
                chat_area = self.query_one("#chat_area")
                for m in msgs:
                    chat_area.write(f"[Offline] {m}")
                logger.info(f"{len(msgs)} mensagens offline carregadas.")
        except Exception as e:
            logger.warning(f"Não foi possível carregar mensagens offline: {e}")


if __name__ == "__main__":
    app = MessagingApp()
    app.run()