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
- **SQLite** – armazenamento seguro de usuários e mensagens  

---

## 📁 Estrutura Inicial do Projeto
```
>>> secure-messaging-channel
├── backend
│   ├── auth
│   │   ├── admin_cli.py
│   │   ├── auth_jwt.py
│   │   ├── __init__.py
│   │   ├── models.py
│   │   ├── routes.py
│   │   └── security.py
│   ├── crypto
│   │   ├── idea_fallback.py
│   │   ├── idea_manager.py
│   │   ├── idea.py
│   │   ├── __init__.py
│   │   ├── main.py
│   │   └── rsa_manager.py
│   ├── database
│   │   ├── queries
│   │   │   ├── groups.py
│   │   │   ├── __init__.py
│   │   │   ├── members.py
│   │   │   ├── messages.py
│   │   │   └── users.py
│   │   ├── cipher_talk.db
│   │   ├── connection.py
│   │   ├── init_db.py
│   │   ├── __init__.py
│   │   └── run_banco_dados.py
│   ├── groups
│   │   └── cli.py
│   ├── messages
│   │   ├── cli.py
│   │   ├── __init__.py
│   │   └── listener.py
│   ├── routes
│   │   ├── __init__.py
│   │   └── messaging.py
│   ├── server
│   │   ├── handlers.py
│   │   ├── handlers_rest.py
│   │   ├── __init__.py
│   │   ├── server.py
│   │   └── tcp_server.py
│   ├── utils
│   │   ├── db_utils.py
│   │   ├── log_formatter.py
│   │   └── logger_config.py
│   ├── adapter_api.py
│   ├── config.py
│   ├── __init__.py
│   └── main.py
├── client
│   ├── auth
│   │   ├── __init__.py
│   │   ├── login_cli.py
│   │   └── signup_cli.py
│   ├── messages
│   │   ├── __init__.py
│   │   └── message_cli.py
│   ├── network
│   │   ├── client_socket.py
│   │   └── __init__.py
│   ├── utils
│   │   ├── helpers.py
│   │   ├── __init__.py
│   │   ├── logger.py
│   │   └── validator.py
│   ├── __init__.py
│   └── run_cli.py
├── api_server.py
├── banco_dados_estrutura.md
├── LICENSE
├── Makefile
├── manual.md
├── README.md
├── requirements.txt
├── run_cli.py
└── run_gui.py
     
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
