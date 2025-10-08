# 🧩 Mapeamento de Implementação — Canal de Comunicação Seguro (Python + IDEA + RSA)

> ⚠️ Status geral: todos os módulos estão **parcialmente implementados**, com base funcional já existente.  
> Cada responsável deve revisar, otimizar e completar o código conforme descrito abaixo.

---

## 👩‍💻 Pessoa 1 — Criptografia e Segurança

### 🧱 Caminhos e status

- **Criptografia simétrica IDEA (modo CBC + PKCS7)**  
  📂 `backend/crypto/idea_manager.py`  
  ➤ Implementação funcional com logs e fallback automático.  
  ➤ Necessário testar novamente após reinstalação do IDEA nativo (`pycryptodomex`).  

- **Fallback Python puro (IDEA)**  
  📂 `backend/crypto/idea_fallback.py`  
  ➤ Implementação completa, mas precisa revisão da função `decrypt()` (erro de padding).  
  ➤ Testar compatibilidade total com `idea_manager.py`.  

- **Criptografia assimétrica RSA (PKCS1_OAEP)**  
  📂 `backend/crypto/rsa_manager.py`  
  ➤ Implementado com funções `generate_rsa_keypair()`, `encrypt_with_rsa()`, `decrypt_with_rsa()`.  
  ➤ Falta revisar integração com `signup_cli.py` e armazenamento de chaves RSA no banco.  

- **Autoteste `verify_encryption_cycle()`**  
  📂 `backend/crypto/idea_manager.py`  
  ➤ Implementado, mas retorna erro de padding no fallback.  
  ➤ Requer correção da função `decrypt_message()` no fallback.  

- **Hash seguro de senhas (bcrypt/passlib)**  
  📂 `backend/auth/security.py`  
  ➤ Implementado parcialmente — utiliza `passlib` com hash e verificação.  
  ➤ Verificar se o mesmo hash é usado em `handlers.py` e `login_cli.py`.  

- **Logs de segurança (`logs/crypto.log`)**  
  📂 `backend/utils/logger_config.py`  
  ➤ Loggers configurados (`crypto_logger` ativo).  
  ➤ Revisar para incluir logs de exceções e falhas de integridade.  

- **Compatibilidade com o servidor e fallback automático**  
  📂 `backend/crypto/idea_manager.py` e `backend/server/handlers.py`  
  ➤ Parcialmente implementado — IDEA com fallback ativo e RSA funcional.  
  ➤ Verificar integração E2EE no fluxo `send_message()`.

---

## 🧠 Pessoa 2 — Servidor e Comunicação (Backend)

### 🧱 Caminhos e status

- **Servidor assíncrono com TLS**  
  📂 `backend/server/server.py`  
  ➤ Implementado e funcional, usa asyncio + TLS com certificados automáticos.  
  ➤ Falta revisão de reconexão (`resume_session`) e tratamento de erros SSL.  

- **Manipuladores (`handlers.py`)**
  📂 `backend/server/handlers.py`  
  ➤ `register`, `login`, `list_users`, `send_message` implementados.  
  ➤ `group_message` ainda não implementado.  
  ➤ Adicionar logs detalhados para cada ação e auditoria de chaves.  

- **Bloqueio global `USERS_LOCK`**  
  📂 `backend/server/handlers.py`  
  ➤ Implementado corretamente para evitar race conditions.  
  ➤ Testar com múltiplas conexões simultâneas.  

- **Mensagens offline e reconexão**
  📂 `backend/server/handlers.py`  
  ➤ Entrega offline implementada, mas testar se mensagens persistem corretamente no banco.  
  ➤ Falta lógica de restauração de sessão (`resume_session`).  

- **Logs do servidor (`logs/server.log`)**  
  📂 `backend/utils/logger_config.py`  
  ➤ Loggers ativos e configurados.  
  ➤ Adicionar logs de handshake TLS, falhas de autenticação e conexões encerradas.

---

## 💾 Pessoa 3 — Banco de Dados e Persistência (JUJUBA)

### 🧱 Caminhos e status

- **Banco SQLite com SQLAlchemy**
  📂 `backend/database/connection.py`  
  ➤ Implementado, cria o engine e gerencia a sessão.  
  ➤ Revisar `ensure_database()` para confirmar criação de tabelas automáticas.  

- **Modelagem de tabelas**
  📂 `backend/auth/models.py`  
  ➤ Tabelas `User` e `Message` implementadas.  
  ➤ Falta `Group` e `GroupMembers`.  

- **Consultas e funções**
  📂 `backend/database/queries/`  
  ➤ Arquivos `users.py` e `messages.py` contêm consultas básicas.  
  ➤ Adicionar funções para histórico, grupos e mensagens pendentes.  

- **Histórico criptografado**
  📂 `backend/server/handlers.py` + `backend/database/messages.py`  
  ➤ Parcialmente implementado (mensagens armazenadas cifradas).  
  ➤ Falta descriptografia automática no recebimento.  

- **Logs de banco**
  📂 `backend/utils/logger_config.py`  
  ➤ Logger `database_logger` ainda não existe — criar para `logs/database.log`.  

---

## 💬 Pessoa 4 — Interface CLI e Experiência do Usuário

### 🧱 Caminhos e status

- **CLI principal (`run_cli.py`)**
  📂 `run_cli.py` (raiz do projeto)  
  ➤ Implementado com menus e subfunções (login, envio, leitura).  
  ➤ Falta limpar terminal após cada ação e centralizar logs.  

- **Autenticação (`client/auth/`)**
  📂 `client/auth/signup_cli.py` e `client/auth/login_cli.py`  
  ➤ Ambos funcionais com TLS, mas sem tratamento de erros detalhado.  
  ➤ Verificar integração RSA no cadastro e JWT no login.  

- **Envio e recebimento de mensagens**
  📂 `backend/messages/cli.py`  
  ➤ Implementado parcialmente com E2EE.  
  ➤ Corrigir handshake TLS e leitura de respostas JSON.  
  📂 `backend/messages/listener.py`  
  ➤ Listener funcional, falta reconexão automática e logs independentes.  

- **Mensagens offline**
  📂 `backend/server/handlers.py` e `backend/messages/cli.py`  
  ➤ Parcialmente implementado (armazenamento no banco).  
  ➤ Falta leitura automática no login.  

- **Lista de contatos**
  📂 `backend/messages/cli.py`  
  ➤ Implementado parcialmente via `list_users`.  
  ➤ Precisa atualização em tempo real com listener.  

- **Logs de ações do cliente (`logs/messages.log`)**
  📂 `backend/utils/logger_config.py`  
  ➤ Logger `messages_logger` ativo.  
  ➤ Falta integração direta nos scripts CLI.

---

## 🧭 Conclusão — Caminho para Finalização

| Área | Arquivo-chave | Status | Próximos passos |
|------|----------------|---------|----------------|
| IDEA / RSA | `backend/crypto/idea_manager.py` | ⚠️ Parcial | Corrigir fallback e testar com IDEA nativo |
| Servidor | `backend/server/server.py` | ⚙️ Funcional | Revisar reconexão e TLS persistente |
| Banco de Dados | `backend/auth/models.py` | ⚠️ Incompleto | Adicionar tabelas de grupos e histórico |
| CLI | `run_cli.py` | ⚙️ Funcional | Melhorar UX e logs no terminal |
| Logs | `backend/utils/logger_config.py` | ✅ Ativo | Criar `database_logger` e revisar formato JSON |

---

