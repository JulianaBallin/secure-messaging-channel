#!/bin/bash
set -e

echo "🚀 Iniciando CipherTalk Backend..."

# Instalar netcat se necessário (para verificar conexão com banco)
if ! command -v nc &> /dev/null; then
    echo "📦 Instalando netcat..."
    apt-get update -qq && apt-get install -y -qq netcat-openbsd > /dev/null 2>&1 || \
    (echo "⚠️ Não foi possível instalar netcat, continuando..." && true)
fi

# Aguardar banco de dados se necessário (para PostgreSQL)
if [ -n "$DB_HOST" ] && [ "$DB_HOST" != "localhost" ] && [ "$DB_HOST" != "127.0.0.1" ]; then
    echo "⏳ Aguardando banco de dados em $DB_HOST:$DB_PORT..."
    if command -v nc &> /dev/null; then
        until nc -z "$DB_HOST" "$DB_PORT" 2>/dev/null; do
            echo "   Banco não está pronto ainda. Aguardando..."
            sleep 2
        done
        echo "✅ Banco de dados está pronto!"
    else
        echo "⏳ Aguardando 5 segundos para banco de dados inicializar..."
        sleep 5
    fi
fi

# Inicializar banco de dados
echo "📦 Inicializando banco de dados..."
python backend/database/init_db.py || echo "⚠️ Aviso: Erro ao inicializar banco (pode já existir)"

# Criar diretórios necessários se não existirem
mkdir -p /app/backend/keys /app/logs /app/backend/database

# Executar servidor FastAPI em background
echo "🌐 Iniciando servidor FastAPI na porta 8000..."
python -m uvicorn backend.adapter_api:app --host 0.0.0.0 --port 8000 --reload &
UVICORN_PID=$!

# Aguardar um pouco para o FastAPI iniciar
sleep 3

# Executar servidor TCP/TLS em foreground
echo "🔒 Iniciando servidor TCP/TLS na porta 8888..."
python backend/server/server.py &
TCP_PID=$!

# Função para encerrar processos quando o container parar
cleanup() {
    echo "🛑 Encerrando processos..."
    kill $UVICORN_PID $TCP_PID 2>/dev/null || true
    wait $UVICORN_PID $TCP_PID 2>/dev/null || true
    exit 0
}

trap cleanup SIGTERM SIGINT

# Aguardar processos
wait $UVICORN_PID $TCP_PID

