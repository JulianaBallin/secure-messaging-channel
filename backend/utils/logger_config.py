"""
logger_config.py
----------------

Configuração centralizada e completa de logging para o CipherTalk.

Características:
- Armazena logs rotativos (5 MB, 3 backups)
- Exibe logs coloridos no terminal (usando colorlog)
- Remove cores ANSI dos arquivos .log
- Ajusta timestamps para horário de Manaus (UTC−4)
- Inclui loggers dedicados para cada módulo:
  server, messages, auth, api, crypto e database
"""

import logging
from logging.handlers import RotatingFileHandler
import os
import re
from datetime import datetime, timezone, timedelta

# ======================================================
# Diretório base
# ======================================================
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_DIR = os.path.join(ROOT_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# ======================================================
# 🕒 Fuso horário de Manaus
# ======================================================
MANAUS_TZ = timezone(timedelta(hours=-4))

def manaus_time(*args):
    """Força datetime.now() no timezone de Manaus nos logs."""
    return datetime.now(MANAUS_TZ).timetuple()

# ======================================================
# 🧹 Formatter sem cor (para arquivos)
# ======================================================
class NoColorFormatter(logging.Formatter):
    """Remove códigos ANSI (cores) para logs em arquivo."""
    def format(self, record):
        msg = super().format(record)
        return re.sub(r"\x1b\[[0-9;]*m", "", msg)

# ======================================================
# 🎨 Formatter colorido (para console)
# ======================================================
try:
    import colorlog

    COLOR_FORMAT = "%(log_color)s%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
    color_formatter = colorlog.ColoredFormatter(
        COLOR_FORMAT,
        datefmt="%Y-%m-%d %H:%M:%S",
        log_colors={
            "DEBUG": "cyan",
            "INFO": "green",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "bold_red",
        },
    )
except ImportError:
    color_formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

# ======================================================
# 🔧 Função auxiliar
# ======================================================
def setup_logger(name: str, filename: str, level=logging.INFO) -> logging.Logger:
    """
    Cria e configura um logger rotativo com saída no arquivo e no console.

    Args:
        name (str): Nome lógico do logger (ex: 'server', 'auth', 'database').
        filename (str): Nome do arquivo de log.
        level (int): Nível mínimo de log.
    """
    log_path = os.path.join(LOG_DIR, filename)

    # 🎯 Handler para arquivo (sem cores)
    file_handler = RotatingFileHandler(
        log_path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_formatter = NoColorFormatter(
        "%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_formatter)

    # 🎨 Handler para console (colorido)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(color_formatter)

    # 🧱 Criação do logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers.clear()  # Evita handlers duplicados
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    logger.propagate = False

    # ⏰ Ajusta timestamps para Manaus
    logging.Formatter.converter = manaus_time

    logger.info(f"🔧 Logger '{name}' inicializado (arquivo: {filename}) em {datetime.now(MANAUS_TZ)}")
    return logger

# ======================================================
# 🌐 Loggers globais do sistema
# ======================================================
server_logger = setup_logger("server", "server.log")
messages_logger = setup_logger("messages", "messages.log")
auth_logger = setup_logger("auth", "auth.log")
api_logger = setup_logger("api", "api.log")
crypto_logger = setup_logger("crypto", "crypto.log")
database_logger = setup_logger("database", "database.log")

# ======================================================
# 🔒 CryptoLogger personalizado (para operações criptográficas)
# ======================================================
class CryptoLogger:
    """Logger personalizado para operações criptográficas detalhadas."""
    
    def __init__(self):
        self.logger = crypto_logger
    
    def log_usuario_criado(self, nome: str, chave_publica: str, chave_privada: str):
        """Log quando um usuário é criado."""
        self.logger.info("=== NOVO USUARIO CRIADO ===")
        self.logger.info(f"Usuario: {nome}")
        self.logger.info(f"Chave Publica (RSA): {chave_publica[:50]}...")
        self.logger.info(f"Chave Privada (RSA): {chave_privada[:50]}...")
        self.logger.info("=" * 50)
    
    def log_envio_mensagem(self, remetente: str, destinatario: str, mensagem_original: str, 
                          chave_sessao_hex: str, chave_sessao_criptografada: str,
                          mensagem_criptografada: str, chave_publica_destinatario: str):
        """Log quando uma mensagem é enviada."""
        self.logger.info("=== ENVIO DE MENSAGEM ===")
        self.logger.info(f"De: {remetente} | Para: {destinatario}")
        self.logger.info(f"Mensagem Original: {mensagem_original}")
        self.logger.info(f"Chave de Sessao (IDEA): {chave_sessao_hex}")
        self.logger.info(f"Chave de Sessao Criptografada: {chave_sessao_criptografada[:50]}...")
        self.logger.info(f"Mensagem Criptografada: {mensagem_criptografada}")
        self.logger.info("=" * 50)
    
    def log_recebimento_mensagem(self, destinatario: str, remetente: str,
                                mensagem_criptografada: str, chave_sessao_criptografada: str,
                                chave_sessao_decifrada: str, mensagem_decifrada: str,
                                chave_privada_destinatario: str):
        """Log quando uma mensagem é recebida."""
        self.logger.info("=== RECEBIMENTO DE MENSAGEM ===")
        self.logger.info(f"Para: {destinatario} | De: {remetente}")
        self.logger.info(f"Mensagem Criptografada: {mensagem_criptografada}")
        self.logger.info(f"Chave de Sessao Criptografada: {chave_sessao_criptografada[:50]}...")
        self.logger.info(f"Chave de Sessao Decifrada: {chave_sessao_decifrada}")
        self.logger.info(f"Mensagem Decifrada: {mensagem_decifrada}")
        self.logger.info("=" * 50)
    
    def log_operacao_idea(self, operacao: str, chave_sessao: str, iv: str = None,
                         bloco_entrada: str = None, bloco_saida: str = None):
        """Log de operações IDEA internas."""
        self.logger.info(f"IDEA {operacao.upper()}")
        self.logger.info(f"Chave de Sessao: {chave_sessao}")
        if iv:
            self.logger.info(f"IV: {iv}")
        if bloco_entrada:
            self.logger.info(f"Bloco Entrada: {bloco_entrada}")
        if bloco_saida:
            self.logger.info(f"Bloco Saida: {bloco_saida}")
        self.logger.info("-" * 30)

# Instância global do CryptoLogger personalizado
crypto_logger_personalizado = CryptoLogger()

# 🟢 Mensagens iniciais de status
crypto_logger.info("🔒 Logger de criptografia inicializado (IDEA + RSA tracking ativo).")
database_logger.info("🗄️ Logger de banco de dados inicializado (SQLAlchemy tracking ativo).")
server_logger.info("🌐 Logger do servidor inicializado.")