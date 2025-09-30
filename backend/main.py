"""
main.py
--------

Entry point of the CipherTalk secure communication API.  
This file initializes the FastAPI application, sets up the main routes for 
authentication and messaging, and defines the root endpoint.

Modules:
    - backend.auth.routes: handles user registration, login, and authentication.
    - backend.routes.messaging: manages encrypted message exchange.
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
