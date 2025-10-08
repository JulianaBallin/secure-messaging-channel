"""
logger_config.py
--------------------------------------------------

Configuração centralizada de logging para o backend do CipherTalk.

Recursos:
- Armazena arquivos de log rotativos dentro do diretório /logs
- Suporta loggers por módulo (server, messages, auth, api, crypto)
- Inclui saída colorida no terminal para fins demonstrativos
- Mantém rotação automática (5 MB máx, 3 backups)
- Totalmente compatível com auditoria acadêmica (exibe eventos IDEA/RSA)
"""

import logging
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime

# ======================================
# Diretório base de logs
# ======================================
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_DIR = os.path.join(ROOT_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# ======================================
# Configuração de formatação
# ======================================
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
    # Fallback padrão sem cores
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# ======================================
# Função auxiliar para criação de loggers
# ======================================
def setup_logger(name: str, filename: str, level=logging.INFO) -> logging.Logger:
    """
    Cria e configura um logger com rotação automática de arquivos.

    Args:
        name (str): Nome do logger (ex: 'server', 'auth', 'messages').
        filename (str): Nome do arquivo de log (ex: 'server.log').
        level (int): Nível mínimo de log (padrão: INFO).

    Returns:
        logging.Logger: Instância configurada.
    """
    log_path = os.path.join(LOG_DIR, filename)

    # Rotação: 5 MB máx. por arquivo, mantém 3 backups
    handler = RotatingFileHandler(
        log_path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )

    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        logger.addHandler(handler)

        # Adiciona também saída no console (útil na defesa e testes)
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        logger.addHandler(console)

    logger.propagate = False
    logger.info(f"🔧 Logger '{name}' inicializado (arquivo: {filename}) em {datetime.now()}")
    return logger


# ======================================
# Loggers prontos para uso
# ======================================
server_logger = setup_logger("server", "server.log")
messages_logger = setup_logger("messages", "messages.log")
auth_logger = setup_logger("auth", "auth.log")
api_logger = setup_logger("api", "api.log")

# Logger dedicado a eventos criptográficos (IDEA + RSA)
crypto_logger = setup_logger("crypto", "crypto.log")
crypto_logger.info("🔒 Logger de criptografia inicializado (IDEA + RSA tracking ativo).")

