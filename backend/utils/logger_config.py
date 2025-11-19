"""
logger_config.py
----------------

Configuração centralizada e completa de logging para o CipherTalk.

Características:
- Armazena logs rotativos (5 MB, 3 backups)
- Exibe logs coloridos no terminal (usando colorlog)
- Remove cores ANSI dos arquivos .log
- Ajusta timestamps para horário de Manaus (UTC−4)
- Inclui loggers dedicados para: Confidencialidade, Integridade, Disponibilidade, 
  Autenticidade, Criptografia, Chat Individual e Grupo
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
    Implementa singleton para evitar handlers duplicados.

    Args:
        name (str): Nome lógico do logger.
        filename (str): Nome do arquivo de log.
        level (int): Nível mínimo de log.
    """
    # Singleton: verifica se logger já existe e tem handlers
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    
    log_path = os.path.join(LOG_DIR, filename)

    # 🎯 Handler para arquivo (sem cores)
    file_handler = RotatingFileHandler(
        log_path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setLevel(level)
    file_formatter = NoColorFormatter(
        "%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_formatter)

    # 🎨 Handler para console (colorido)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(color_formatter)

    # 🧱 Configuração do logger
    logger.setLevel(level)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    logger.propagate = False

    # ⏰ Ajusta timestamps para Manaus
    logging.Formatter.converter = manaus_time

    # 🔥 GARANTE que os logs sejam escritos imediatamente (flush)
    def force_flush():
        for handler in logger.handlers:
            if hasattr(handler, 'stream') and hasattr(handler.stream, 'flush'):
                handler.stream.flush()
    
    # Adiciona flush após cada log
    original_info = logger.info
    def info_with_flush(msg, *args, **kwargs):
        result = original_info(msg, *args, **kwargs)
        force_flush()
        return result
    logger.info = info_with_flush
    
    return logger

# ======================================================
# 🌐 Loggers principais do sistema
# ======================================================

# Loggers de segurança
messages_logger = setup_logger("messages", "messages.log")
integridade_logger = setup_logger("integridade", "integridade.log")
disponibilidade_logger = setup_logger("disponibilidade", "disponibilidade.log")
autenticidade_logger = setup_logger("autenticidade", "autenticidade.log")

# Loggers de chat
individual_chat_logger = setup_logger("individual_chat", "individual_chat.log")
group_chat_logger = setup_logger("group_chat", "group_chat.log")

# Loggers de confidencialidade para chat (separados por tipo)
confidencialidade_chat_individual_logger = setup_logger("confidencialidade_chat_individual", "confidencialidade_chat_individual.log")
confidencialidade_chat_grupo_logger = setup_logger("confidencialidade_chat_grupo", "confidencialidade_chat_grupo.log")

# ======================================================
# 📝 Função log_event para eventos específicos
# ======================================================
def log_event(event_type: str, username: str, message: str):
    """
    Registra um evento específico no logger apropriado.
    
    Args:
        event_type: Tipo do evento
        username: Nome do usuário relacionado ao evento
        message: Mensagem descritiva do evento
    """
    # Mapeia tipos de evento para os loggers apropriados
    if event_type.startswith("INTEGRIDADE"):
        integridade_logger.info(f"[{event_type}] {username}: {message}")
    elif event_type.startswith("DISPONIBILIDADE"):
        disponibilidade_logger.info(f"[{event_type}] {username}: {message}")
    elif event_type.startswith("AUTENTICIDADE"):
        autenticidade_logger.info(f"[{event_type}] {username}: {message}")
    elif event_type.startswith("INDIVIDUAL_CHAT"):
        individual_chat_logger.info(f"[{event_type}] {username}: {message}")
    elif event_type.startswith("GROUP_CHAT"):
        group_chat_logger.info(f"[{event_type}] {username}: {message}")


# ======================================================
# Mensagens iniciais de status (apenas uma vez por logger)
# ======================================================
_initialized_loggers = set()

def _log_initialization(logger, message):
    """Registra mensagem de inicialização apenas uma vez por logger."""
    logger_name = logger.name
    if logger_name not in _initialized_loggers:
        # Usar DEBUG ao invés de INFO para não poluir os logs principais
        logger.debug(message)
        _initialized_loggers.add(logger_name)

# Mensagens de inicialização removidas para não poluir os logs
# Os loggers já são inicializados automaticamente quando criados