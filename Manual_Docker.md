# Manual Docker - Windows

## Pre-requisitos:

- Windows 10 ou superior (64-bit)
- Internet para download

## 1 -  Instalar Docker Desktop

1. Baixe: https://www.docker.com/products/docker-desktop/
4. Abra o Docker Desktop e aguarde iniciar (icone verde na bandeja)

**Verificar se de fato foi instalado:**
```powershell 
docker --version
docker-compose --version
```

## 2 - Na pasta do projeto:
```powershell
git pull origin main
```

## 4 - Iniciar Docker Desktop
### 4.1 - Construir Imagem e Iniciar Container

```powershell
docker-compose up -d --build
```
 **Primeira vez:** 10-20 minutos (download de imagens)  - demora um pouco
---

## 5 - Verificar containers:

```powershell
docker-compose ps
```

## 6 - Acessar

- **Frontend:** http://localhost:3000
- **API Docs:** http://localhost:8000/docs


## 8 - Comandos Uteis

```powershell
# Parar containers
docker-compose stop

# Iniciar containers
docker-compose up -d

# Ver logs
docker-compose logs -f

# Reiniciar apos mudancas no codigo
docker-compose up -d --build
```

---
