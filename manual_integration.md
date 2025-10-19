# 🔐 CipherTalk — Sistema de Comunicação Segura (RSA + IDEA)

O **CipherTalk** é uma aplicação de **mensagens seguras** que utiliza **criptografia híbrida RSA + IDEA** e transporte **TLS** para proteger a comunicação entre usuários.  
O sistema permite **mensagens privadas e em grupo**, com recursos de **administração**, **rotação de chaves**, e **logs criptográficos**.

---

## 🚀 Tecnologias Utilizadas

### 🔹 Backend
- Python 3.10+
- FastAPI
- SQLAlchemy (SQLite)
- PyCryptodome e Cryptography (RSA + IDEA)
- TLS/SSL (OpenSSL)
- JWT para autenticação

### 🔹 Frontend
- Next.js 14 (App Router)
- React 18
- Tailwind CSS
- shadcn/ui
- Framer Motion
- Lucide Icons

---

## 🧠 Estrutura Principal do Projeto

```
CipherTalk/
├── backend/
│   ├── server/
│   │   ├── server.py        # Servidor de transporte seguro (TLS)
│   ├── auth/                    # Modelos e autenticação de usuários
│   ├── crypto/                  # Criptografia RSA e IDEA
│   ├── database/                # Conexão e queries SQLite
│   ├── utils/                   # Logs e utilitário
│   └── adapter_api.py       # API REST principal (FastAPI)
│
├── frontend/
│   ├── app/                     # Rotas Next.js (login, chat)
│   ├── components/ui/           # Componentes de interface (shadcn/ui)
│   └── lib/utils.ts             # Função fetchJSON e helpers
│
├── requirements.txt             # Dependências do backend
├── package.json                 # Dependências do frontend
└── README.md
```

---

## ⚙️ Como Executar o Projeto

### 1️⃣ Clonar o repositório

### 2️⃣ Instalar e rodar o **Backend**

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
```bash
python backend/server/server.py
```

#### Rodar a API (FastAPI)
```bash
python uvicorn backend.adapter_api:app --host 127.0.0.1 --port 8000 --reload
```

> ⚠️ **Importante:** o servidor TLS deve SEMPRE estar rodando **antes** da API Adapter (FastAPI).

---

### 3️⃣ Rodar o **Frontend**

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

## 🚫 Limitação Atual

> 🕒 O **cadastro via interface** ainda **não está funcional** devido ao tempo reduzido de implementação.  
> Para testar, **crie os usuários diretamente no banco SQLite** e depois faça **login normalmente** pela interface.

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
