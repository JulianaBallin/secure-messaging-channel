# 🧩 Mapeamento de Implementação — Canal de Comunicação Seguro (Python + IDEA + RSA)

> ⚠️ Status geral: todos os módulos estão **parcialmente implementados**, com base funcional já existente.  
> Cada responsável deve revisar, otimizar e completar o código conforme descrito abaixo.

---

## 👩‍💻 Pessoa 1 — Criptografia e Segurança

### 🧱 Caminhos e status


- **Criptografia simétrica IDEA (modo CBC + PKCS7)**   ✅ **100% Concluído**
  📂 `backend/crypto/idea_manager.py`  
  ➤ Implementação funcional com logs e fallback automático.  
  ➤ Necessário testar novamente após reinstalação do IDEA nativo (`pycryptodomex`).  

- **Fallback Python puro (IDEA)**   ✅ **100% Concluído**
  📂 `backend/crypto/idea_fallback.py`  
  ➤ Implementação completa, mas precisa revisão da função `decrypt()` (erro de padding).  
  ➤ Testar compatibilidade total com `idea_manager.py`.  

- **Criptografia assimétrica RSA (PKCS1_OAEP)**  ✅ **100% Concluído**

  📂 `backend/crypto/rsa_manager.py` ✅ **100% Concluído**
  ➤ Implementado com funções `generate_rsa_keypair()`, `encrypt_with_rsa()`, `decrypt_with_rsa()`.  
  ➤ Falta revisar integração com `signup_cli.py` e armazenamento de chaves RSA no banco.  

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

### 🧱 Caminhos e Status Geral

Responsável pela **camada de persistência e integridade de dados** do CipherTalk.  
Garante que **usuários, grupos e mensagens criptografadas** sejam armazenados e auditados com total segurança,  
seguindo boas práticas de SQLAlchemy, logging e arquitetura modular integrada ao servidor.

---

### 🗄️ Banco SQLite + Conexão SQLAlchemy  
📂 `backend/database/connection.py`

✅ **100% Concluído**
- Cria e gerencia o `engine`, `SessionLocal` e `Base` do SQLAlchemy.  
- Banco fixo e seguro localizado em `backend/database/cipher_talk.db`.  
- Função `ensure_database()` garante criação e verificação de todas as tabelas.  
- Log detalhado de inicialização e verificação com tags `[DB_INIT]` e `[DB_VERIFY]`.  
- Compatível com servidor (`server.py`), painel de auditoria (`run_queries.py`) e scripts locais.

---

### 🧩 Modelagem de Tabelas  
📂 `backend/auth/models.py`

✅ **100% Concluído**
- Tabelas: `User`, `Group`, `GroupMember`, `Message`.  
- Relacionamentos totalmente integrados com `cascade="all, delete-orphan"`.  
- `User.is_online` implementado (sincronizado com status do servidor).  
- `Message` com validação XOR (`CheckConstraint`) para mensagens privadas ou de grupo.  
- Índices otimizados (`sender_id`, `receiver_id`, `timestamp`) para alto desempenho.  
- Constraints únicas e relacionamentos bidirecionais para consistência de dados.  
- Pronto para auditoria, testes e uso em produção.

---

### 💬 Consultas e Funções SQL  
📂 `backend/database/queries/`

✅ **100% Concluído**
- `users.py`: CRUD completo, atualização de chave pública e status online.  
- `groups.py`: criação, adição, remoção e listagem de membros; transferência automática de admin.  
- `messages.py`: histórico, mensagens pendentes, descriptografia local e limpeza periódica.  
- Todas as operações possuem logs automáticos (`[MSG_SAVE]`, `[GROUP_ADD]`, `[USER_CREATE]`, etc.).  
- Integrado ao painel de auditoria (`run_queries.py`) para inspeção e validação em tempo real.  

---

### 🔐 Histórico Criptografado  
📂 `backend/database/queries/messages.py` + `backend/server/handlers.py`

✅ **100% Concluído**
- Armazenamento 100% criptografado (IDEA + RSA híbrido).  
- Função `decrypt_stored_message()` permite descriptografia segura local (modo auditoria).  
- Logs integrados aos módulos `database.log` e `crypto.log`.  
- Entrega e armazenamento de mensagens automáticos via handlers (`handle_send_message`, `handle_send_group_message`).  
- Compatível com auditoria, testes e inspeção via CLI.  

---

### 🧾 Logs de Banco de Dados  
📂 `backend/utils/logger_config.py`

✅ **100% Concluído**
- Logger `database_logger` configurado com rotação automática (`logs/database.log`).  
- Saída colorida, timestamps e rastreamento de transações.  
- Logs dedicados para cada módulo (`server`, `messages`, `auth`, `crypto`, `database`).  
- Total integração com o backend e o painel de auditoria.  
- Mensagens padronizadas com tags `[AUDIT]`, `[DB_INIT]`, `[TX_COMMIT]`, `[TX_ROLLBACK]`.

---

### 🧮 Painel de Auditoria (CLI de Inspeção)
📂 `backend/database/run_queries.py`

✅ **100% Concluído**
- Painel interativo em **modo somente leitura** (sem alterações no banco).  
- Consultas disponíveis:  
  1️⃣  Listar usuários  
  2️⃣  Buscar usuário (detalhes + grupos)  
  3️⃣  Listar grupos  
  4️⃣  Buscar grupo (informações + membros)  
  5️⃣  Listar usuários vinculados a grupos  
  6️⃣  Ver mensagens privadas (pares)  
  7️⃣  Ver mensagens em grupos  
- Logs automáticos `[AUDIT]` em cada ação.  
- Ideal para uso da professora em demonstrações e validações de persistência.

---

### ✅ Status Final

| Área | Status | Observações |
|------|---------|-------------|
| Conexão SQLite | 🟩 Concluída | Com logs `[DB_INIT]` e `[DB_VERIFY]` |
| Modelagem ORM | 🟩 Concluída | Cascata e índices otimizados |
| Consultas SQL | 🟩 Concluída | Inclui auditoria e limpeza de mensagens |
| Histórico Criptografado | 🟩 Concluída | Totalmente funcional e auditável |
| Logs de Banco | 🟩 Concluída | Integrados e rotativos |
| Painel de Auditoria | 🟩 Concluída | Somente leitura, seguro e validado |

---

💾 **Resumo Final — Parte da Jujuba**
> A camada de persistência do CipherTalk está **completa, funcional e auditável**.  
> Todas as operações de banco estão seguras, criptografadas e registradas em logs.  
> O sistema suporta auditoria acadêmica, integração com o servidor e visualização em tempo real via CLI.


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

