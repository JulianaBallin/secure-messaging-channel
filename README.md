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
secure-messaging-channel/
├── backend
     
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
