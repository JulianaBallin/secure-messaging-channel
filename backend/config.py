"""
config.py
----------

Carrega variáveis de ambiente para a aplicação CipherTalk usando python-dotenv.
Este módulo centraliza todas as configurações sensíveis como SECRET_KEY, IDEA_KEY
e URLs de banco de dados para acesso seguro em todo o projeto.
"""

import os
from dotenv import load_dotenv

# Carrega variáveis do arquivo .env
load_dotenv()

# Segurança e Criptografia
SECRET_KEY = os.getenv("SECRET_KEY", "default-insecure-key")
IDEA_KEY = os.getenv("IDEA_KEY", "1234567890ABCDEF").encode()  # IDEA precisa de 16 bytes

# JWT
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))

# Banco de Dados (opcional)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cipher_talk.db")
