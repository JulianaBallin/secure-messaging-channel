"""
main.py
--------

Ponto de entrada da API de comunicação segura CipherTalk.
Este arquivo inicializa a aplicação FastAPI, configura as rotas principais para
autenticação e mensagens, e define o endpoint raiz.

Módulos:
    - backend.auth.routes: gerencia registro, login e autenticação de usuários
    - backend.routes.messaging: gerencia troca de mensagens criptografadas
"""


from fastapi import FastAPI
from backend.auth import routes as auth_routes
from backend.routes import messaging

app = FastAPI(
    title="CipherTalk",
    description="Canal de comunicação seguro com RSA, IDEA e autenticação com hash.",
    version="0.1.0"
)

# Rotas principais
app.include_router(auth_routes.router, prefix="/auth", tags=["Autenticação"])
app.include_router(messaging.router, prefix="/messages", tags=["Mensagens"])

@app.get("/")
async def root():
    return {"message": "🔐 Bem-vindo ao CipherTalk!"}
