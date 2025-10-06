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
│  ├─ main.py                     # ponto de entrada CLI principal (não FastAPI por enquanto)
│  │
│  ├─ auth/                       
│  │  ├─ __init__.py
│  │  ├─ models.py                # modelos ORM (User, Message, Group, GroupMember)
│  │  ├─ routes.py                # rotas auxiliares (se necessário futuramente)
│  │  ├─ security.py              # hash seguro de senhas e verificação
│  │  └─ auth_jwt.py              # geração e validação de tokens JWT
│  │
│  ├─ crypto/                     
│  │  ├─ __init__.py
│  │  ├─ rsa_manager.py           # geração e uso de chaves RSA
│  │  └─ idea_manager.py          # criptografia IDEA para mensagens
│  │
│  ├─ database/                  
│  │  ├─ __init__.py
│  │  ├─ connection.py            # engine e sessão do banco (SQLite)
│  │  └─ queries/                 # 📂 consultas diretas ao banco (isoladas)
│  │     ├─ __init__.py
│  │     ├─ users.py              # consultas de usuários
│  │     ├─ messages.py           # consultas de mensagens
│  │     └─ groups.py             # consultas de grupos
│  │
│  ├─ server/                     # 🌐 servidor asyncio (TCP)
│  │  ├─ __init__.py
│  │  ├─ server.py                # servidor que gerencia conexões e mensagens
│  │  └─ client.py                # cliente simples para testes individuais (auxiliar)
│  │
│  ├─ messages/                   # lógica de mensagens (futuramente ampliada)
│  │  └─ cli.py
│  │
│  ├─ groups/                     # lógica de grupos (admin, membros, etc)
│  │  └─ cli.py
│  │
│  └─ routes/                     
│     ├─ __init__.py
│     └─ messaging.py             # rotas internas do sistema (se migrarmos p/ FastAPI depois)
│
├─ keys/                          # 📂 chaves privadas dos usuários (armazenadas localmente)
│
├─ logs/                          # 📂 logs detalhados de segurança e consultas
│  └─ security.log
│
├─ tests/                         
│  ├─ __init__.py
│  ├─ test_auth.py
│  ├─ test_crypto.py
│  └─ test_messaging.py
│
├─ run_cli.py                     # 🚀 CLI principal com cadastro, login e consultas
├─ run_queries.py                 # utilitário para consultas rápidas ao banco
├─ init_db.py                     # inicializa o banco de dados
├─ checklist.MD                   # lista de funcionalidades implementadas/faltantes
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
