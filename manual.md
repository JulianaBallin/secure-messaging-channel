# 🔐 CipherTalk — Manual

## 1. Preparar Ambiente

#### Criar ambiente virtual
```bash
python -m venv venv
venv\Scripts\activate     # Windows
# ou
source venv/bin/activate  # Linux/Mac
```

#### Instalar dependências
```bash
pip install -r requirements.txt
```

#### Rodar o servidor TLS
Em um primeiro terminal:
```bash
python backend/server/server.py
```

#### Rodar a API (FastAPI)
Em um segundo terminal:
```bash
uvicorn backend.adapter_api:app --host 0.0.0.0 --port 8000 --reload
```

> ⚠️ **Importante:** o servidor TLS deve SEMPRE estar rodando **antes** da API Adapter (FastAPI).

---

### 3️⃣ Rodar o **Frontend**
Em um terceiro terminal:

#### Entrar na pasta do frontend
```bash
cd frontend
```

#### Instalar dependências
```bash
npm install
```

#### Rodar o app
```bash
npm run dev
```

Acesse o sistema em:  
👉 [http://localhost:3000](http://localhost:3000)

---

## 🔑 Funcionalidades Principais

✅ Autenticação com JWT  
✅ Envio e recebimento de mensagens privadas cifradas  
✅ Criação e gerenciamento de grupos  
✅ Adição e remoção de membros (somente para admin)  
✅ Rotação manual de chaves IDEA  
✅ Comunicação segura via TLS  
✅ Interface moderna, responsiva e intuitiva  

---

## 🧰 Comandos úteis

| Ação | Comando |
|------|----------|
| Rodar o servidor TLS | `python backend/server/server.py` |
| Rodar o Adapter API | `uvicorn backend.adapter_api:app --host 127.0.0.1 --port 8000 --reload` |
| Rodar o frontend | `npm run dev` |
| Instalar pacotes do backend | `pip install -r requirements.txt` |
| Instalar pacotes do frontend | `npm install` |

---
