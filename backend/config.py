"""
config.py
----------

Loads environment variables for the CipherTalk application using python-dotenv.
This module centralizes all sensitive configurations like SECRET_KEY, IDEA_KEY,
and database URLs for secure access across the project.
"""

import os
from dotenv import load_dotenv

# Carrega variáveis do arquivo .env
load_dotenv()

# 🔐 Segurança e Criptografia
SECRET_KEY = os.getenv("SECRET_KEY", "default-insecure-key")
IDEA_KEY = os.getenv("IDEA_KEY", "1234567890ABCDEF").encode()  # IDEA precisa de 16 bytes

# 🕐 JWT
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))

# 🗄️ Banco de Dados (opcional)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cipher_talk.db")
