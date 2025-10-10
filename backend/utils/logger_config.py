"""
logger_config.py
----------------

Configuração centralizada e completa de logging para o CipherTalk.

Características:
- Armazena logs rotativos (5 MB, 3 backups)
- Exibe logs coloridos no terminal (usando colorlog)
- Inclui loggers dedicados para cada módulo:
  server, messages, auth, api, crypto e database
- Totalmente compatível com auditoria acadêmica e produção
"""

import logging
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime

# ======================================================
# Diretório base
# ======================================================
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_DIR = os.path.join(ROOT_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# ======================================================
# Configuração de formatação
# ======================================================
try:
    import colorlog

    COLOR_FORMAT = "%(log_color)s%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
    formatter = colorlog.ColoredFormatter(
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
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# ======================================================
# Função auxiliar
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
    handler = RotatingFileHandler(
        log_path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        logger.addHandler(handler)
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        logger.addHandler(console)

    logger.propagate = False
    logger.info(f"🔧 Logger '{name}' inicializado (arquivo: {filename}) em {datetime.now()}")
    return logger


# ======================================================
# Loggers globais do sistema
# ======================================================
server_logger = setup_logger("server", "server.log")
messages_logger = setup_logger("messages", "messages.log")
auth_logger = setup_logger("auth", "auth.log")
api_logger = setup_logger("api", "api.log")
crypto_logger = setup_logger("crypto", "crypto.log")
database_logger = setup_logger("database", "database.log")

# Mensagens iniciais de status
crypto_logger.info("🔒 Logger de criptografia inicializado (IDEA + RSA tracking ativo).")
database_logger.info("🗄️ Logger de banco de dados inicializado (SQLAlchemy tracking ativo).")
