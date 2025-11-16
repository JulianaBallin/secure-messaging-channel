# 🐳 Docker Setup - CipherTalk

Este documento explica como usar Docker e Docker Compose para executar o CipherTalk.

## 📋 Pré-requisitos

- [Docker](https://www.docker.com/get-started) instalado
- [Docker Compose](https://docs.docker.com/compose/install/) instalado (geralmente vem com Docker Desktop)

## 🚀 Início Rápido

### 1. Construir e iniciar todos os serviços

```bash
docker-compose up -d
```

Este comando irá:
- Construir as imagens do backend e frontend
- Iniciar o backend (FastAPI na porta 8000 + TCP/TLS na porta 8888)
- Iniciar o frontend (Next.js na porta 3000)
- Criar volumes para persistir dados (banco, chaves, logs)

### 2. Ver logs dos serviços

```bash
# Ver todos os logs
docker-compose logs -f

# Ver apenas backend
docker-compose logs -f backend

# Ver apenas frontend
docker-compose logs -f frontend
```

### 3. Parar todos os serviços

```bash
docker-compose down
```

Para remover também os volumes (⚠️ apaga banco de dados e dados):

```bash
docker-compose down -v
```

## 📂 Estrutura dos Volumes

Os seguintes diretórios são persistidos entre reinicializações:

- `./backend/database/` - Banco de dados SQLite
- `./backend/keys/` - Chaves privadas RSA dos usuários
- `./logs/` - Arquivos de log do sistema

## 🔧 Comandos Úteis

### Reconstruir containers após mudanças no código

```bash
docker-compose up -d --build
```

### Ver status dos serviços

```bash
docker-compose ps
```

### Executar comando dentro de um container

```bash
# Backend
docker-compose exec backend python --version
docker-compose exec backend python backend/database/init_db.py --reset

# Frontend
docker-compose exec frontend npm --version
```

### Acessar shell do container

```bash
# Backend
docker-compose exec backend bash

# Frontend
docker-compose exec frontend sh
```

## 🌐 Acessos

Após iniciar os serviços:

- **Frontend**: http://localhost:3000
- **API REST (FastAPI)**: http://localhost:8000
- **Documentação da API**: http://localhost:8000/docs
- **TCP/TLS Server**: localhost:8888

## 🔍 Troubleshooting

### Porta já em uso

Se as portas 3000, 8000 ou 8888 estiverem ocupadas, você pode alterar no `docker-compose.yml`:

```yaml
ports:
  - "3001:3000"  # Frontend na porta 3001
  - "8001:8000"  # API na porta 8001
  - "8889:8888"  # TCP na porta 8889
```

### Ver logs de erro

```bash
docker-compose logs backend | grep ERROR
docker-compose logs frontend | grep ERROR
```

### Reconstruir do zero

```bash
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d
```

### Resetar banco de dados

```bash
docker-compose exec backend python backend/database/init_db.py --reset
```

## 📝 Notas

- O hot reload está habilitado por padrão (volumes montados)
- Para produção, remova os volumes de hot reload do `docker-compose.yml`
- Os logs são persistidos no diretório `./logs/` do host
- As chaves privadas são criadas em `./backend/keys/{username}/`

