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
├── backend
│   ├── auth
│   │   ├── admin_cli.py
│   │   ├── auth_jwt.py
│   │   ├── __init__.py
│   │   ├── models.py
│   │   ├── routes.py
│   │   └── security.py
│   ├── config.py
│   ├── crypto
│   │   ├── idea_manager.py
│   │   ├── __init__.py
│   │   └── rsa_manager.py
│   ├── database
│   │   ├── cipher_talk.db
│   │   ├── connection.py
│   │   ├── __init__.py
│   │   └── queries
│   │       ├── groups.py
│   │       ├── __init__.py
│   │       ├── messages.py
│   │       └── users.py
│   ├── groups
│   │   └── admin_cli.py
│   ├── __init__.py
│   ├── main.py
│   ├── messages
│   │   ├── admin_cli.py
│   │   └── __init__.py
│   ├── routes
│   │   ├── __init__.py
│   │   └── messaging.py
│   └── server
│       ├── handlers.py
│       ├── __init__.py
│       └── server.py
├── cert.pem
├── checklist.MD
├── cipher_talk.db
├── client
│   ├── auth
│   │   ├── __init__.py
│   │   ├── login_cli.py
│   │   ├── session_manager.py
│   │   └── signup_cli.py
│   ├── __init__.py
│   ├── menus
│   │   ├── __init__.py
│   │   ├── menu_inicial.py
│   │   └── menu_pos_login.py
│   ├── messages
│   │   ├── __init__.py
│   │   └── message_cli.py
│   ├── network
│   │   ├── client_socket.py
│   │   └── __init__.py
│   ├── run_cli.py
│   └── utils
│       ├── helpers.py
│       ├── __init__.py
│       ├── logger.py
│       └── validator.py
├── init_db.py
├── key.pem
├── keys
│   ├── JulianaBallin_private.pem
│   └── JulianaTest2_private.pem
├── LICENSE
├── logs
│   └── server.log
├── Makefile
├── README.md
├── requirements.txt
├── run_cli.py
└── run_queries.py
     
```

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
