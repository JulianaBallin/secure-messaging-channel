import logging
import os
import sys
from datetime import datetime
from pathlib import Path

def setup_logger(nome_logger, arquivo_log, nivel=logging.INFO, formato_personalizado=None):
    
    # Cria a pasta de logs se não existir
    Path(arquivo_log).parent.mkdir(parents=True, exist_ok=True)
    
    logger = logging.getLogger(nome_logger)
    logger.setLevel(nivel)
    
    if logger.handlers:
        return logger
    
    # Formato  das mensagens de log
    if formato_personalizado is None:
        formato = logging.Formatter(
            '%(asctime)s | %(name)-12s | %(levelname)-8s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    else:
        formato = formato_personalizado
    
    file_handler = logging.FileHandler(arquivo_log, encoding='utf-8')
    file_handler.setFormatter(formato)
    logger.addHandler(file_handler)
    
    if os.getenv('DEBUG', 'False').lower() == 'true':
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formato)
        logger.addHandler(console_handler)
    
    return logger

# Loggers específicos para cada parte do sistema
def get_crypto_logger():
    #Logger para operações criptográficas
    return setup_logger(
        'CRYPTO', 
        'logs/crypto.log',
        logging.INFO
    )

def get_auth_logger():
    #Logger para autenticação (login/cadastro)
    return setup_logger(
        'AUTH', 
        'logs/auth.log',
        logging.INFO
    )

def get_chat_logger():
    #Logger para operações do chat
    return setup_logger(
        'CHAT', 
        'logs/chat.log', 
        logging.INFO
    )

def get_security_logger():
    #Logger para eventos de segurança críticos
    formato_critico = logging.Formatter(
        '🚨 %(asctime)s | %(name)-12s | %(levelname)-8s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return setup_logger(
        'SECURITY', 
        'logs/security.log',
        logging.WARNING,
        formato_critico
    )

def log_operation(logger_name='CRYPTO'):
    """Decorator para log automático de operações"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            logger = globals()[f'get_{logger_name.lower()}_logger']()
            
            logger.info(f"INICIANDO: {func.__name__}")
            
            try:
                result = func(*args, **kwargs)
                logger.info(f"SUCESSO: {func.__name__}")
                return result
            except Exception as e:
                logger.error(f"ERRO em {func.__name__}: {str(e)}")
                raise
            finally:
                logger.info(f"FINALIZADO: {func.__name__}")
                
        return wrapper
    return decorator
