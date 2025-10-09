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

### Caminhos e Status Geral

Responsável pela **camada de persistência e integridade de dados** do CipherTalk.  
Essa parte garante que **usuários, mensagens e grupos sejam armazenados de forma segura, criptografada e auditável**, com suporte total a consultas e logs de auditoria.



### 🗄️ Banco SQLite + Conexão SQLAlchemy  
📂 `backend/database/connection.py`

✅ **Implementado**
- Cria e gerencia o `engine` e `SessionLocal` (ORM do SQLAlchemy).  
- Banco fixo e seguro em `backend/database/cipher_talk.db`.  
- Compatível com o servidor (`ensure_database()` integrado ao boot do backend).  
- Totalmente integrado aos loggers (`database.log` registra inicialização e conexões).

🔧 **Pendentes**
- Adicionar função `ensure_database()` reutilizável no CLI para setup local.  
- Criar log adicional de verificação automática do esquema (`[DB_VERIFY]`).


### 🧩 Modelagem de Tabelas  
📂 `backend/auth/models.py`

✅ **Implementado**
- Tabelas: `User`, `Message`, `Group`, `GroupMember`.  
- Relacionamentos configurados com integridade referencial e *constraints* completas.  
- Suporte tanto a mensagens privadas quanto de grupo (regra XOR validada via `CheckConstraint`).  
- Estrutura pronta para consultas avançadas de auditoria (joins entre usuários, mensagens e grupos).

🔧 **Pendentes**
- Adicionar flag `User.is_online` (refletindo cache do servidor).  
- Inserir `cascade="all, delete-orphan"` nos relacionamentos dependentes (`sent_messages`, `received_messages`, `members`, `messages`).  
- Revisar indexação por data e chaves compostas para otimizar consultas grandes.


### 💬 Consultas e Funções SQL  
📂 `backend/database/queries/`

✅ **Implementado**
- `users.py`: consultas completas (`list_all_users`, `get_user_by_username`, `update_public_key`).  
- `messages.py`: histórico, mensagens pendentes e descriptografia (`decrypt_stored_message`).  
- `groups.py`: criação, adição, remoção e listagem de membros, com logs administrativos.  
- Consultas compatíveis com o **painel de auditoria `run_queries.py`**.

🔧 **Pendentes**
- Implementar funções de manutenção e consistência:  
  - `transfer_group_admin(db, group_name)` — promove novo admin se o atual sair.  
  - `delete_empty_groups(db)` — remove grupos órfãos sem membros.  
- Adicionar logs explícitos de transação (`commit`, `rollback`) e falhas SQL.


### 🔐 Histórico Criptografado  
📂 `backend/database/queries/messages.py` + `backend/server/handlers.py`

✅ **Implementado**
- Armazenamento de mensagens 100% criptografado (IDEA + RSA híbrido).  
- Função `decrypt_stored_message()` permite auditoria e descriptografia local segura.  
- Logs integrados (`database.log` + `crypto.log`) documentam envio, recebimento e armazenamento.  
- Estrutura preparada para descriptografia automática no recebimento.

🔧 **Pendentes**
- Integrar descriptografia automática no fluxo de login (`handle_login`).  
- Criar cache opcional de mensagens descriptografadas (modo auditoria offline).  


### 🧾 Logs de Banco de Dados  
📂 `backend/utils/logger_config.py`

✅ **Implementado**
- Logger `database_logger` com rotação automática (`logs/database.log`).  
- Saída colorida e rastreamento de ações SQL e ORM.  
- Integração total com os loggers `server_logger`, `auth_logger` e `crypto_logger`.  
- Mensagens de auditoria registradas a cada consulta (`[AUDIT]` tags).

🔧 **Pendentes**
- Adicionar logs de transação detalhados:
  - `[TX_COMMIT]`, `[TX_ROLLBACK]`, `[TX_PENDING]`.  
- (Opcional) Criar logger secundário `transaction_logger` para auditoria de transações longas.


### 🧮 Painel de Auditoria (CLI de Inspeção)
📂 `backend/database/run_queries.py`

✅ **Implementado**
- Painel interativo somente leitura (modo auditoria).  
- Consultas disponíveis:  
  1️⃣  Listar usuários  
  2️⃣  Buscar usuário (detalhes + grupos)  
  3️⃣  Listar grupos  
  4️⃣  Buscar grupo (informações + membros)  
  5️⃣  Listar usuários vinculados a grupos  
  6️⃣  Ver mensagens privadas (pares)  
  7️⃣  Ver mensagens de grupo  
- Todas as consultas são `SELECT` (sem alterações no banco).  
- Logs automáticos de cada ação no `database.log` com tag `[AUDIT]`.

🔧 **Pendentes**
- Adicionar exportador opcional (`--export`) para gerar relatórios `.csv`.  
- Criar modo de filtro temporal (`--since <data>`) para limitar histórico em consultas grandes.


### ✅ Status Resumido
| Área | Status | Observações |
|------|---------|-------------|
| Conexão SQLite | 🟩 Completa | Pequenos ajustes de log |
| Modelagem ORM | 🟩 Completa | Melhorar cascatas |
| Consultas SQL | 🟨 Parcial | Faltam funções de manutenção |
| Histórico Criptografado | 🟨 Parcial | Integrar descriptografia automática |
| Logs de Banco | 🟩 Completa | Adicionar rastreamento de transações |
| Painel de Auditoria | 🟩 Completa | Adicionar exportação opcional |

---


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

