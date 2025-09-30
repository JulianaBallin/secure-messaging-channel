# 🔐 CipherTalk – Canal de Comunicação Seguro

**CipherTalk** é um canal de comunicação seguro desenvolvido em **Python**, utilizando criptografia **IDEA** (simétrica) e **RSA** (assimétrica) para garantir confidencialidade e integridade das mensagens. O sistema inclui autenticação de usuários com **senhas criptografadas (hash com salt)**, exibição de **usuários online** e armazenamento seguro do histórico de conversas.  

---

## 🚀 Funcionalidades

- 🔑 **Login e registro de usuários** com senha protegida por hash (SHA-256 + salt)  
- 🔐 **Criptografia RSA** para troca segura de chaves  
- 🔄 **Criptografia IDEA** para mensagens trocadas entre usuários  
- 👥 **Lista de usuários online** (exibe quem possui cadastro e está conectado)  
- 🗄️ **Histórico de mensagens criptografado** armazenado de forma segura  
- 📡 **Comunicação escalável**: suporta conversas entre pares e grupos  

---

## 🛠️ Tecnologias Utilizadas

- **Python 3.12+** – linguagem principal  
- **cryptography** – geração e gerenciamento de chaves RSA  
- **pycryptodome** – implementação do algoritmo IDEA  
- **Flask** ou **FastAPI** – criação da API de comunicação  
- **SQLite** ou **PostgreSQL** – armazenamento seguro de usuários e mensagens  

---

## 📁 Estrutura Inicial do Projeto
```
secure-messaging-channel/
├─ backend/
│  ├─ __init__.py
│  ├─ main.py                     # ponto de entrada da API (FastAPI)
│  │
│  ├─ auth/                       # autenticação de usuários
│  │  ├─ __init__.py
│  │  ├─ models.py                # modelos de usuário
│  │  ├─ routes.py                # rotas de login e cadastro
│  │  └─ security.py              # hash de senha e geração de tokens
│  │
│  ├─ crypto/                     # lógica de criptografia
│  │  ├─ __init__.py
│  │  ├─ rsa_manager.py           # geração e troca de chaves RSA
│  │  └─ idea_manager.py          # criptografia e descriptografia IDEA
│  │
│  ├─ database/                   # conexão e inicialização do banco
│  │  ├─ __init__.py
│  │  └─ connection.py
│  │
│  └─ routes/                     # rotas principais do sistema
│     ├─ __init__.py
│     └─ messaging.py             # envio/recebimento de mensagens
│
├─ tests/                         # testes automatizados
│  ├─ __init__.py
│  ├─ test_auth.py
│  ├─ test_crypto.py
│  └─ test_messaging.py
│
├─ .gitignore
├─ Makefile
├─ LICENSE
├─ README.md
├─ requirements.txt
└─ .env.example                  
```

---

## ✅ Checklist de Desenvolvimento

### 🏗️ Configuração Inicial
- [ ] Criar estrutura de diretórios do projeto  
- [ ] Configurar ambiente virtual e instalar dependências  
- [ ] Criar servidor inicial com Flask ou FastAPI  

### 🔑 Autenticação Segura
- [ ] Implementar registro de usuários com hash de senha (SHA-256 + salt)  
- [ ] Criar sistema de login com geração de sessão/token  
- [ ] Conectar banco de dados para armazenamento seguro  

### 🔐 Criptografia
- [ ] Implementar geração de chaves RSA por usuário  
- [ ] Realizar troca segura de chaves RSA entre clientes  
- [ ] Implementar criptografia e descriptografia IDEA para mensagens  

### 📨 Núcleo de Mensagens
- [ ] Criar endpoints para envio e recebimento de mensagens  
- [ ] Armazenar histórico de mensagens criptografadas  
- [ ] Exibir lista de usuários online (ativos no sistema)  

### 🧪 Testes e Segurança
- [ ] Criar testes unitários para autenticação e criptografia  
- [ ] Validar fluxo completo de troca de mensagens cifradas  
- [ ] Testar contra vulnerabilidades comuns (replay, MITM, etc.)  

---

## 🧭 Melhorias Futuras

- 📱 Interface web simples com Streamlit ou React  
- 🧠 Autenticação multifator (MFA)  
- 📊 Logs e monitoramento de segurança  

---

## 👩‍💻 Equipe de Desenvolvimento

Este projeto foi desenvolvido pelos estudantes do curso de Sistemas de Informação da **Universidade do Estado do Amazonas (UEA)**:

| Nome | E-mail |
|------|--------|
| 👩‍💻 Ana Beatriz Maciel Nunes | [abmn.snf23@uea.edu.br](mailto:abmn.snf23@uea.edu.br) |
| 👨‍💻 Marcelo Heitor De Almeida Lira | [mhdal.snf23@uea.edu.br](mailto:mhdal.snf23@uea.edu.br) |
| 👨‍💻 Fernando Luiz Da Silva Freire | [fldsf.snf23@uea.edu.br](mailto:fldsf.snf23@uea.edu.br) |
| 👩‍💻 Juliana Ballin Lima | [jbl.snf23@uea.edu.br](mailto:jbl.snf23@uea.edu.br) |



## 📜 Licença

Este projeto é distribuído sob a licença **MIT** – veja o arquivo [LICENSE](LICENSE) para mais detalhes.
