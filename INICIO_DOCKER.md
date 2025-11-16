# 🚀 Guia Rápido - Iniciar com Docker

## ⚠️ PRÉ-REQUISITO: Docker Desktop deve estar rodando!

Antes de executar qualquer comando, certifique-se de que o **Docker Desktop está iniciado**.

### Como verificar se Docker está rodando:

**Windows:**
- Abra o Docker Desktop
- Aguarde até aparecer "Docker Desktop is running" na barra de tarefas

**Verificar via terminal:**
```powershell
docker ps
```
Se não estiver rodando, você verá um erro. Nesse caso, inicie o Docker Desktop.

---

## 📝 Comandos para Iniciar

### 1. Construir e iniciar todos os serviços:

```powershell
docker compose up -d --build
```

Este comando:
- ✅ Constrói as imagens do backend e frontend
- ✅ Inicia o backend (porta 8000 e 8888)
- ✅ Inicia o frontend (porta 3000)
- ✅ Cria volumes para persistir dados

### 2. Ver logs em tempo real:

```powershell
# Todos os serviços
docker compose logs -f

# Apenas backend
docker compose logs -f backend

# Apenas frontend
docker compose logs -f frontend
```

### 3. Ver status dos containers:

```powershell
docker compose ps
```

### 4. Parar todos os serviços:

```powershell
docker compose down
```

---

## 🌐 Acessos

Após iniciar os serviços:

- **Frontend**: http://localhost:3000
- **API REST**: http://localhost:8000
- **Documentação API**: http://localhost:8000/docs
- **TCP/TLS Server**: localhost:8888

---

## 🔧 Troubleshooting

### Erro: "The system cannot find the file specified"
**Solução:** Inicie o Docker Desktop e aguarde alguns segundos até ele estar totalmente inicializado.

### Erro: "port is already allocated"
**Solução:** As portas 3000, 8000 ou 8888 estão em uso. Encerre os processos que estão usando essas portas ou altere as portas no `docker-compose.yml`.

### Ver logs de erro específicos:
```powershell
docker compose logs backend | Select-String "ERROR"
docker compose logs frontend | Select-String "ERROR"
```

### Reconstruir do zero:
```powershell
docker compose down -v
docker compose build --no-cache
docker compose up -d
```

---

## ✅ Pronto!

Agora você pode usar o CipherTalk via Docker! 🎉

