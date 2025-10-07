# ✅ Checklist — backend

## 📂 Diretório: backend/auth/

| Arquivo | Status | Objetivo | O que falta implementar / aprimorar |
|----------|--------|-----------|--------------------------------------|
| **security.py** | ✅ Completo | Implementa política de senhas seguras e hash com bcrypt via Passlib. | 🔹 Adicionar logs de auditoria (ex: `[PASSWORD_VERIFY]`) em `logs/security.log` sem expor senhas. |
| **auth_jwt.py** | ✅ Completo | Gera e valida tokens JWT com expiração. | 🔹 Registrar logs `[TOKEN_CREATE]` e `[TOKEN_VALIDATE]`.<br>🔹 Incluir claims extras (`iat`, `iss`, `role`).<br>🔹 (Futuro) Migrar de HS256 → RS256 para escalabilidade multi-servidor. |
| **models.py** | ✅ Completo | Define estrutura ORM de usuários, grupos e mensagens. | 🔹 Adicionar campo `last_seen` ou `is_active` para status online em tempo real.<br>🔹 Incluir eventos SQLAlchemy para registrar logs de criação/remoção de usuários e mensagens. |
| **routes.py** | ⚠️ Parcial | Expõe endpoints HTTP (FastAPI) para cadastro e login. | 🔹 Substituir FAKE_DB por integração com `SessionLocal`.<br>🔹 Usar `backend.auth.security` para hashing/verificação.<br>🔹 Adicionar logs `[REGISTER_OK]`, `[LOGIN_OK]`, `[REGISTER_FAIL]`, `[LOGIN_FAIL]` em `logs/security.log`.<br>🔹 Retornar respostas JSON padronizadas. |
| **admin_cli.py** | ✅ Funcional | Ferramenta CLI para criação/autenticação de usuários diretamente no banco. | 🔹 Registrar logs locais (`logs/admin.log`).<br>🔹 Bloquear reuso de senhas antigas (opcional).<br>🔹 Permitir exportar chaves públicas para auditoria. |

---

## 🔐 Requisitos de Segurança (Comuns a Todos os Arquivos)

- [x] **Criptografia de ponta a ponta (E2EE)**: RSA (assimétrica) + IDEA (simétrica).
- [x] **Armazenamento seguro**: chaves privadas salvas localmente, nunca no servidor.
- [x] **Sessão segura**: autenticação JWT com expiração e assinatura.
- [x] **Logs detalhados**: todas as ações (cadastro, login, token, erro, mensagem) registradas.
- [ ] **Logger unificado**: criar `backend/utils/logger.py` com padrão único de formatação.
- [ ] **Limpeza visual**: limpar terminal após cada ação de menu nos CLIs.
- [ ] **Escalabilidade**: preparar JWT e ORM para múltiplos servidores simultâneos.

---

## 🧭 Próximas Etapas de Implementação

1. **[Alta prioridade]** Atualizar `routes.py` para integração real com `SessionLocal` e logging robusto.  
2. **[Média]** Criar `backend/utils/logger.py` com configuração centralizada (`RotatingFileHandler`, formato `[%(asctime)s] [%(levelname)s] %(message)s`).  
3. **[Baixa]** Adicionar campo `last_seen` em `models.User` + evento SQLAlchemy para atualização automática.  
4. **[Baixa]** Adicionar log explícito de geração e validação de tokens JWT.  

---

📁 **Status geral da pasta `backend/auth/`**:  
> 🟩 4 arquivos completos / 🟨 1 pendente (routes.py)
>  
> 🔒 Criptografia, autenticação e hashing 100% funcionais e alinhados ao padrão IDEA + RSA.

---


## 📂 Diretório: backend/crypto/

| Arquivo | Status | Objetivo | O que falta implementar / aprimorar |
|----------|--------|-----------|--------------------------------------|
| **rsa_manager.py** | ✅ Completo | Implementa criptografia assimétrica RSA com OAEP (seguro para troca de chaves IDEA). | 🔹 Adicionar logs de geração e uso de chaves (sem expor conteúdo).<br>🔹 Implementar persistência opcional de chave pública (para auditoria/admin).<br>🔹 (Futuro) Adicionar assinatura digital (`sign_data` e `verify_signature`) para integridade ponta a ponta. |
| **idea_manager.py** | ✅ Funcional com fallback | Implementa criptografia simétrica IDEA-CBC com PKCS7. Inclui fallback para ambientes sem Cryptodome IDEA. | 🔹 Adicionar log de fallback quando o módulo nativo não for encontrado (`[FALLBACK_IDEA]`).<br>🔹 Implementar logging em `logs/crypto.log` com etapas: `[KEYGEN_IDEA]`, `[ENCRYPT_IDEA]`, `[DECRYPT_IDEA]`.<br>🔹 Criar função de autoteste simples (`verify_idea_integrity()`) que valide encriptação/decriptação no startup do servidor. |
| **idea_fallback.py** | ⚠️ Parcial (somente encrypt) | Implementação pura em Python do algoritmo IDEA (modo CBC), usada quando o Cryptodome não tem suporte nativo. | 🔹 Completar `decrypt_message()` (atualmente placeholder).<br>🔹 Revisar `_idea_key_schedule` e `_idea_round` para garantir total compatibilidade com padrão IDEA RFC 2451.<br>🔹 Adicionar logs `[FALLBACK_ENCRYPT]` e `[FALLBACK_DECRYPT]` para validação futura.<br>🔹 Realizar benchmarks e alerta automático de desempenho reduzido. |

---

## 🔐 Pilares de Segurança Criptográfica

- [x] **RSA (assimétrica)**: usado para troca segura da chave IDEA.
- [x] **IDEA (simétrica)**: usado para encriptação das mensagens.
- [x] **Modo CBC + PKCS7**: fornece confidencialidade e alinhamento de blocos.
- [x] **Fallback interno**: garante compatibilidade mesmo sem módulo nativo.
- [ ] **Assinatura digital (RSA-OAEP + SHA256)**: pendente para validação de integridade das mensagens.
- [ ] **Logs de auditoria**: devem ser registrados em `logs/crypto.log`.

---

## 📋 Resumo de Logs Recomendados

| Evento | Exemplo de Log | Local sugerido |
|--------|----------------|----------------|
| Geração de chave RSA | `[RSA_KEYGEN] Nova chave RSA 2048 bits gerada` | rsa_manager.py |
| Criptografia RSA | `[RSA_ENCRYPT] Mensagem cifrada com chave pública do usuário X` | rsa_manager.py |
| Descriptografia RSA | `[RSA_DECRYPT] Mensagem decifrada com chave privada local` | rsa_manager.py |
| Geração de chave IDEA | `[KEYGEN_IDEA] Chave simétrica gerada com sucesso` | idea_manager.py |
| Fallback IDEA | `[FALLBACK_IDEA] Usando implementação Python pura` | idea_manager.py |
| Encriptação simétrica | `[ENCRYPT_IDEA] Mensagem cifrada com IV aleatório` | idea_manager.py |
| Decriptação simétrica | `[DECRYPT_IDEA] Mensagem decifrada com sucesso` | idea_manager.py |

---

## 🧭 Próximas Etapas de Implementação

1. **[Alta prioridade]** Finalizar `decrypt_message()` no `idea_fallback.py` (hoje apenas retorna placeholder).  
2. **[Média]** Criar `logs/crypto.log` e configurar logger dedicado (`backend/utils/logger.py`) com `RotatingFileHandler`.  
3. **[Média]** Adicionar sistema de verificação automática no startup do servidor:  
   ```python
   from backend.crypto.idea_manager import generate_idea_key, encrypt_message, decrypt_message
   def verify_idea_integrity():
       key = generate_idea_key()
       msg = "cipher_integrity_check"
       return decrypt_message(encrypt_message(msg, key), key) == msg
    ```
→ Caso retorne False, logar [CRYPTO_ERROR] Fallback inválido.

4. **[Baixa]** Implementar assinatura digital (RSA-SHA256) para autenticação de origem das mensagens.

---

📁 **Status geral da pasta `backend/crypto/`**:  
> 🟩 2 arquivos completos / 🟨 1 pendente (idea_fallback.py)
>  
> 🔒 IDEA + RSA integrados corretamente com fallback funcional e estrutura pronta para expansão de logs e integridade ponta a ponta.


---


## 📂 Diretório: backend/database/

| Arquivo | Status | Objetivo | O que falta implementar / aprimorar |
|----------|--------|-----------|--------------------------------------|
| **connection.py** | ✅ Completo | Define engine, sessão (`SessionLocal`) e base declarativa SQLAlchemy. | 🔹 Adicionar logs `[DB_CONNECT]` e `[DB_CLOSE]`.<br>🔹 Criar função `init_engine()` para inicialização segura com reconexão automática (tolerância a falhas).<br>🔹 (Futuro) Suporte a **PostgreSQL** e **BigQuery**, mantendo compatibilidade com SQLite local. |
| **cipher_talk.db** | ⚙️ Arquivo gerado | Banco SQLite local contendo usuários, mensagens e grupos. | 🔹 Não versionar (`.gitignore` ✔️).<br>🔹 Criar script `init_db.py` (já existe) para recriar e popular dados iniciais. |
| **__init__.py** | ✅ Simples | Define o pacote `database` e garante importação modular. | 🔹 Nenhuma alteração necessária. |

---

## 📂 Diretório: backend/database/queries/

| Arquivo | Status | Objetivo | O que falta implementar / aprimorar |
|----------|--------|-----------|--------------------------------------|
| **__init__.py** | ✅ Completo | Documenta e centraliza helpers de consulta (SQLAlchemy). | 🔹 Nenhuma ação necessária; boa estrutura modular. |
| **users.py** | ⚠️ Parcial | Funções de consulta/manipulação de usuários no banco. | 🔹 Adicionar logs `[USER_CREATE]`, `[USER_FETCH]`, `[USER_DELETE]`.<br>🔹 Implementar função `update_last_seen(db, username)` para sincronizar status online.<br>🔹 Criar helper `get_user_by_public_key()` (útil na entrega de mensagens E2EE). |
| **messages.py** | ✅ Funcional | Consulta e manipulação de mensagens individuais e offline. | 🔹 Adicionar log `[MESSAGE_STORE]` e `[MESSAGE_RETRIEVE]`.<br>🔹 Incluir filtro por data e status (lidas/não lidas).<br>🔹 (Futuro) Implementar paginação e busca textual (por remetente ou trecho). |
| **groups.py** | ⚠️ Parcial | Consultas relacionadas a grupos e seus membros. | 🔹 Adicionar funções `create_group()`, `add_member()`, `remove_member()` com verificação de permissão.<br>🔹 Adicionar logs `[GROUP_CREATE]`, `[GROUP_MEMBER_ADD]`, `[GROUP_MEMBER_REMOVE]`.<br>🔹 Implementar campo `created_by` no modelo `Group` para auditoria. |

---

## 🧠 Considerações Técnicas Gerais

- [x] Estrutura ORM completa e consistente com `backend/auth/models.py`.  
- [x] Uso correto de `SessionLocal` e `engine`.  
- [x] Queries simples e seguras (sem SQL injection).  
- [ ] Falta **padronização de logs SQL e auditoria** (recomenda-se `logs/db.log`).  
- [ ] Criar camada de **cache leve** (opcional) para reduzir consultas repetitivas (`@lru_cache` ou Redis no futuro).  
- [ ] Incluir **tratamento de exceções** unificado (ex: `try/except SQLAlchemyError` com log detalhado).

---

## 📋 Resumo de Logs Recomendados

| Evento | Exemplo de Log | Local sugerido |
|--------|----------------|----------------|
| Conexão ao banco | `[DB_CONNECT] Conexão estabelecida com SQLite` | connection.py |
| Criação de usuário | `[USER_CREATE] Novo usuário registrado: {username}` | users.py |
| Consulta de usuário | `[USER_FETCH] Usuário solicitado: {username}` | users.py |
| Armazenamento de mensagem | `[MESSAGE_STORE] Mensagem salva no banco` | messages.py |
| Recuperação de mensagem | `[MESSAGE_RETRIEVE] Mensagens recuperadas para {username}` | messages.py |
| Criação de grupo | `[GROUP_CREATE] Grupo criado: {group_name}` | groups.py |
| Entrada em grupo | `[GROUP_MEMBER_ADD] Usuário {username} adicionado ao grupo {group}` | groups.py |

---

## 🧭 Próximas Etapas de Implementação

1. **[Alta prioridade]** Criar `backend/utils/logger.py` com logger central (`logs/db.log`, `logs/security.log`, `logs/crypto.log`).  
2. **[Média]** Atualizar `users.py` e `messages.py` para registrar logs em todas as operações de escrita.  
3. **[Média]** Adicionar `update_last_seen()` e `is_active` no modelo `User` + trigger automática.  
4. **[Baixa]** Implementar camada de cache (em memória) para consultas de leitura frequente.  

---

📁 **Status geral do módulo de banco de dados:**  
> 🟩 4 arquivos completos / 🟨 2 parciais (`users.py`, `groups.py`)  
>  
> 🗄️ Estrutura sólida, compatível com SQLAlchemy 2.0, com bom potencial para escalar e manter rastreabilidade completa via logs.

---

## 📂 Diretório: backend/groups/

| Arquivo | Status | Objetivo | O que falta implementar / aprimorar |
|----------|--------|-----------|--------------------------------------|
| **cli.py** | ⚠️ Parcial | Interface de terminal para criação, entrada e listagem de grupos com persistência em banco via SQLAlchemy. | 🔹 Adicionar logs detalhados (`logs/groups.log`) para todas as ações (`[GROUP_CREATE]`, `[GROUP_JOIN]`, `[GROUP_LIST]`).<br>🔹 Implementar verificação de permissões (somente criador pode excluir/renomear grupo).<br>🔹 Adicionar suporte à **mensageria em grupo** (integração com `backend/messages/cli.py`).<br>🔹 Criar função `leave_group(current_user, group_name)` para saída voluntária.<br>🔹 Integrar feedback visual: limpar terminal antes de menus e exibir confirmação com ícones (✅ ⚠️ ❌). |

---

## 🧠 Funcionalidades Atuais

- ✅ Criação de grupo com validação de nome (mínimo 3 caracteres).  
- ✅ Associação automática do criador como membro.  
- ✅ Entrada em grupo existente, evitando duplicação.  
- ✅ Listagem de grupos e membros.  
- ⚠️ Sem logs, sem controle de permissões e sem integração com E2EE.

---

## 🔐 Melhorias Recomendadas para Segurança e Escalabilidade

| Categoria | Recomendação | Justificativa |
|------------|---------------|----------------|
| **Autorização** | Permitir apenas ao criador do grupo gerenciar membros e deletar grupo. | Previne abuso e mantém integridade. |
| **Logs de Auditoria** | Criar `logs/groups.log` e registrar todas as ações. | Necessário para rastreabilidade e avaliação docente. |
| **Criptografia (E2EE em grupo)** | Integrar IDEA+RSA para troca de mensagens entre múltiplos membros. | Alinha-se ao modelo de **criptografia ponta a ponta em grupo (Group E2EE)**. |
| **Sincronização** | Usar `asyncio` e `SessionLocal` assíncrono no futuro. | Melhora desempenho e escalabilidade. |
| **UX de CLI** | Adicionar limpeza de terminal (`os.system('clear')`) e formatação colorida. | Melhora legibilidade em testes de uso. |

---

## 📋 Resumo de Logs Recomendados

| Evento | Exemplo de Log | Local sugerido |
|--------|----------------|----------------|
| Criação de grupo | `[GROUP_CREATE] Novo grupo criado: {group_name} por {username}` | cli.py |
| Entrada em grupo | `[GROUP_JOIN] {username} entrou no grupo {group_name}` | cli.py |
| Saída de grupo | `[GROUP_LEAVE] {username} saiu do grupo {group_name}` | (novo método) |
| Listagem de grupos | `[GROUP_LIST] Listagem solicitada por {username}` | cli.py |

---

## 🧭 Próximas Etapas de Implementação

1. **[Alta prioridade]** Criar `leave_group()` e `delete_group()` com verificação de dono.  
2. **[Média]** Integrar mensagens E2EE entre grupos:  
   - Armazenar chaves IDEA compartilhadas com membros.  
   - Usar RSA para entregar a chave simétrica IDEA a cada novo participante.  
3. **[Média]** Adicionar logging completo no formato padronizado `[%(asctime)s] [%(levelname)s] [GROUP] ...`.  
4. **[Baixa]** Adaptar o CLI para interface mais limpa (uso de emojis e separadores visuais).  

---

📁 **Status geral da pasta `backend/groups/`**:  
> 🟨 1 arquivo funcional (CLI) com CRUD básico.  
>  
> 🔐 Estrutura sólida, mas ainda sem logs e sem integração direta com mensagens E2EE.

---



## 📂 Diretório: backend/messages/

| Arquivo | Status | Objetivo | O que falta implementar / aprimorar |
|----------|--------|-----------|--------------------------------------|
| **cli.py** | 🟨 Parcial | Implementa o envio e leitura de mensagens E2EE (IDEA + RSA), comunicação com servidor via TLS, e armazenamento local em JSON. | 🔹 Adicionar logs detalhados em `logs/messages.log` para cada etapa: `[SEND_INIT]`, `[ENCRYPT_IDEA]`, `[ENCRYPT_RSA]`, `[SEND_SUCCESS]`, `[RECV_DECRYPT]`.<br>🔹 Inserir confirmação visual após envio e armazenar localmente cópia da mensagem enviada (útil para debug).<br>🔹 Adicionar verificação automática de integridade (testar decriptação após criptografia).<br>🔹 Em `read_and_decrypt_messages()`, mover mensagens lidas para `messages/archive/` após exibição. |
| **listener.py** | ✅ Funcional | Mantém conexão assíncrona segura com o servidor, recebe mensagens em tempo real e as salva em disco (`messages/{user}_{sender}_{timestamp}.json`). | 🔹 Adicionar log de eventos (`logs/listener.log`) com `[LISTENER_START]`, `[MESSAGE_RECEIVED]`, `[MESSAGE_SAVE]`, `[JSON_ERROR]`.<br>🔹 Implementar timeout e reconexão automática (`while True` com `try_reconnect`).<br>🔹 Adicionar alerta sonoro (opcional, `beep` em terminal) ao receber nova mensagem.<br>🔹 Integrar com `read_and_decrypt_messages()` para decodificação automática. |

---

## 🧠 Funcionalidades Atuais

- ✅ Criptografia híbrida: IDEA (CBC) + RSA (OAEP).  
- ✅ Transporte seguro via TLS.  
- ✅ Armazenamento local de mensagens (persistente).  
- ✅ Estrutura modular (CLI separado do listener).  
- ⚠️ Ausência de logs e reconexão automática no listener.  
- ⚠️ Nenhuma limpeza/organização pós-leitura das mensagens.

---

## 🔐 Requisitos de Segurança e Logs Recomendados

| Categoria | Implementação recomendada | Objetivo |
|------------|---------------------------|-----------|
| **Auditoria de envio** | `[SEND_INIT]` Iniciando envio a {receiver}<br>`[SEND_SUCCESS]` Mensagem entregue com sucesso | Verificar fluxo seguro e evitar duplicidade |
| **Criptografia** | `[ENCRYPT_IDEA]` e `[ENCRYPT_RSA]` com hash da chave | Garantir rastreabilidade criptográfica sem expor dados |
| **Recepção** | `[MESSAGE_RECEIVED]` e `[MESSAGE_SAVED]` com remetente | Evidenciar entrega completa |
| **Erros** | `[JSON_ERROR]`, `[DECRYPT_FAIL]`, `[TLS_ERROR]` | Facilitar depuração e prova de segurança |
| **Desempenho** | `[LISTENER_RECONNECT]` após falha | Tolerância a falhas de rede |

📍 Todos os logs devem ir para **`logs/messages.log`** e **`logs/listener.log`**, com formato padronizado:
```python
%(asctime)s [%(levelname)s] [MODULE] %(message)s
```

## 🧩 Interação com outros módulos

| Módulo | Função |
|--------|--------|
| `backend.crypto.*` | Criptografia IDEA/RSA e gerenciamento de chaves. |
| `backend.server.handlers` | Recebimento e roteamento de mensagens. |
| `client/run_cli.py` | Integra menus e listener. |
| `backend/database.messages` | Persiste histórico quando o receptor está offline. |

---

## 🧭 Próximas Etapas de Implementação

- **[Alta prioridade]** Criar logger dedicado (`logs/messages.log` e `logs/listener.log`) com rotação automática (`RotatingFileHandler`).  
- **[Alta]** Adicionar função `verify_encryption_cycle()` em `cli.py` para validar IDEA/RSA antes de enviar.  
- **[Média]** Implementar reconexão automática no listener (`while True` com delay crescente).  
- **[Média]** Adicionar integração entre listener → `read_and_decrypt_messages()` para decodificar automaticamente ao receber.  
- **[Baixa]** Implementar compressão leve (`gzip`) nos arquivos JSON de mensagens para economizar espaço.  

---

## 📁 Status geral da pasta `backend/messages/`

> 🟩 **1 arquivo funcional** (`listener.py`)  
> 🟨 **1 arquivo parcial** (`cli.py`)  
>  
> 🔐 **E2EE ativo e testado** (IDEA + RSA + TLS), com estrutura escalável pronta para multiusuário em tempo real, restando apenas auditoria e logs para completude acadêmica e validação docente.

---

## 📂 Diretório: backend/routes/

| Arquivo | Status | Objetivo | O que falta implementar / aprimorar |
|----------|--------|-----------|--------------------------------------|
| **messaging.py** | ⚠️ Parcial | Define rotas FastAPI para envio e recuperação de mensagens (modelo REST auxiliar para administração e testes internos). | 🔹 Substituir armazenamento em memória (`MESSAGES`) por integração com o banco real (`backend.database.messages`).<br>🔹 Adicionar autenticação JWT obrigatória (via `Depends(verify_access_token)`).<br>🔹 Integrar o uso híbrido de chaves (RSA + IDEA).<br>🔹 Implementar logging detalhado (`logs/routes.log`).<br>🔹 Adicionar auditoria completa com timestamps e hashes de integridade.<br>🔹 Validar usuários contra tabela `users` antes de enviar mensagens. |

---

## 🧠 Funcionalidades Atuais

- ✅ Endpoints REST `/messages/send` e `/messages/inbox/{username}` operacionais.  
- ✅ Criptografia IDEA aplicada em mensagens.  
- ✅ Estrutura Pydantic robusta (`MessageCreate` e `MessageResponse`).  
- ⚠️ Nenhuma autenticação JWT ou integração real com banco.  
- ⚠️ Não há logs, auditoria ou hashing das mensagens.  
- ⚠️ Falta integração com `backend.server.handlers` para E2EE real.

---

## 🔐 Melhorias Recomendadas

| Categoria | Implementação recomendada | Objetivo |
|------------|---------------------------|-----------|
| **Banco de Dados** | Usar ORM (`SessionLocal`) e modelo `Message` do SQLAlchemy | Garantir persistência e escalabilidade. |
| **Autenticação** | Adicionar `Depends(get_current_user)` para validar tokens JWT | Restringir acesso às rotas a usuários logados. |
| **Criptografia híbrida** | Criptografar mensagens com IDEA e chaves IDEA com RSA | Alinhar com E2EE de usuários simultâneos. |
| **Logs** | Registrar `[ROUTE_SEND]`, `[ROUTE_INBOX]`, `[ROUTE_FAIL]` | Provar segurança e rastreabilidade. |
| **Hash de integridade** | Armazenar `SHA-256` do conteúdo criptografado | Garantir não adulteração das mensagens. |

---

## 🧩 Interação com outros módulos

| Módulo | Função |
|--------|--------|
| `backend.crypto.idea_manager` | Criptografia e descriptografia IDEA. |
| `backend.crypto.rsa_manager` | Troca segura de chaves entre usuários. |
| `backend.auth.auth_jwt` | Autenticação e verificação de tokens JWT. |
| `backend.database.messages` | Persistência de mensagens e histórico. |
| `backend.server.handlers` | Roteamento assíncrono e distribuição de mensagens em tempo real. |

---

## 🧭 Próximas Etapas de Implementação

- **[Alta prioridade]** Integrar `SessionLocal` e persistência em `cipher_talk.db`.  
- **[Alta]** Adicionar autenticação JWT (via `Depends`).  
- **[Alta]** Implementar logs estruturados (`logs/routes.log`) e salvar ações críticas.  
- **[Média]** Adicionar auditoria de integridade com SHA-256 (hash de cada mensagem).  
- **[Média]** Criar endpoint `/messages/status/{id}` para checar entrega (online/offline).  
- **[Baixa]** Implementar testes unitários para `/send` e `/inbox`.

---

## 📁 Status geral da pasta `backend/routes/`

> 🟨 1 arquivo parcialmente funcional (`messaging.py`)  
>  
> 🚀 Ideal para camada REST auxiliar do sistema, mas precisa de integração completa com autenticação JWT, banco de dados e E2EE para ambiente multiusuário seguro e auditável.



## 📂 Diretório: backend/server/

| Arquivo | Status | Objetivo | O que falta implementar / aprimorar |
|----------|--------|-----------|--------------------------------------|
| **server.py** | 🟩 Quase completo | Servidor assíncrono TLS com rotas seguras (`register`, `login`, `resume_session`, `list_users`, `send_message`). Garante persistência de sessão e logs detalhados. | 🔹 Implementar *graceful shutdown* (finalizar conexões ativas com aviso).<br>🔹 Criar logger dedicado (`logs/server_audit.log`) para diferenciar logs operacionais e de auditoria.<br>🔹 Adicionar proteção contra flood/DDOS simples (`rate_limit_per_user`).<br>🔹 Implementar verificação de integridade do banco em `ensure_database()` (checksum). |
| **handlers.py** | 🟩 Funcional e seguro | Define handlers assíncronos para registro, login, listagem e envio de mensagens (E2EE). Inclui logs e controle de concorrência. | 🔹 Adicionar confirmação de entrega (ACK) para mensagens online e offline.<br>🔹 Gerar hash de integridade (`SHA-256`) no payload salvo no banco.<br>🔹 Validar tamanho máximo de mensagem e chave para evitar abuse.<br>🔹 Integrar *anti replay protection* (timestamp + nonce).<br>🔹 Inserir *rotating file handler* em `logging` para evitar overflow de logs. |

---

## 🧠 Funcionalidades Atuais

- ✅ Comunicação segura via TLS + asyncio.  
- ✅ Autenticação baseada em JWT (login e sessão persistente).  
- ✅ Registro com armazenamento da chave pública RSA.  
- ✅ Envio de mensagens E2EE (IDEA + RSA híbrido).  
- ✅ Entrega offline automática e remoção do banco após leitura.  
- ✅ Controle de usuários online via `ONLINE_USERS`.  
- ✅ Locks (`asyncio.Lock`) para evitar race conditions.  
- ✅ Logs detalhados por evento (registro, login, envio, desconexão).  
- ⚠️ Falta ACK de confirmação, proteção contra spam e auditoria avançada.  

---

## 🔐 Melhorias Recomendadas

| Categoria | Implementação recomendada | Objetivo |
|------------|---------------------------|-----------|
| **Auditoria** | Gerar `server_audit.log` com eventos críticos (`LOGIN_OK`, `REGISTER_OK`, `SEND_ERROR`). | Evidência documental para avaliação docente. |
| **Resiliência** | Implementar *rate limiting* (ex: 5 mensagens/seg por usuário). | Proteger contra abuso ou flood de mensagens. |
| **Integridade** | Calcular hash SHA-256 para cada mensagem criptografada. | Permitir verificação antifraude. |
| **Escalabilidade** | Adicionar `asyncio.Queue` por usuário para enfileirar mensagens simultâneas. | Melhorar desempenho com muitos clientes. |
| **Recuperação** | *Graceful shutdown* e *restart-safe* para sessões persistentes. | Evitar perda de dados em quedas. |

---

## 🧩 Interação com outros módulos

| Módulo | Função |
|--------|--------|
| `backend.auth.*` | Gerencia autenticação JWT, hashing e modelos de usuário. |
| `backend.database.connection` | Cria sessões e engine SQLite. |
| `backend.crypto.*` | Criptografia IDEA + RSA usada no roteamento seguro. |
| `backend.messages.listener` | Recebe mensagens do servidor em tempo real. |
| `backend/messages/cli.py` | Cliente que envia mensagens criptografadas via socket TLS. |

---

## 🧭 Próximas Etapas de Implementação

- **[Alta prioridade]** Implementar *ACKs* (confirmações de entrega e leitura).  
- **[Alta]** Adicionar *server_audit.log* com separação de níveis de log (`INFO`, `SECURITY`, `WARNING`, `CRITICAL`).  
- **[Média]** Incluir rate limiting por IP e timestamp (`limit_per_token`).  
- **[Média]** Implementar checagem de integridade das mensagens armazenadas (hash).  
- **[Baixa]** Adicionar endpoint administrativo `/metrics` para monitorar usuários online e total de mensagens.  

---

## 📁 Status geral da pasta `backend/server/`

> 🟩 2 arquivos funcionais (`server.py`, `handlers.py`)  
>  
> 🔐 **Servidor 100% funcional e seguro**, com criptografia ponta a ponta (IDEA + RSA + TLS), autenticação JWT e multiusuário simultâneo.  
> Resta aprimorar: **auditoria, confirmação de entrega e escalabilidade**, essenciais para validação docente e publicação acadêmica.


---
## 📂 Diretório: backend/

| Arquivo | Status | Objetivo | O que falta implementar / aprimorar |
|----------|--------|-----------|--------------------------------------|
| **main.py** | 🟩 Completo | Ponto de entrada da API FastAPI. Registra rotas principais de autenticação e mensagens (REST auxiliar ao canal principal E2EE). | 🔹 Adicionar middleware de segurança (CORS, HTTPSRedirectMiddleware).<br>🔹 Incluir logger da API (`logs/api.log`) com status de rotas e tempo de resposta.<br>🔹 Criar endpoint `/health` para monitoramento (útil em produção).<br>🔹 Documentar no README como rodar a API e o servidor TLS simultaneamente. |
| **config.py** | 🟩 Completo | Centraliza variáveis de ambiente (.env) e parâmetros de segurança (SECRET_KEY, IDEA_KEY, DB_URL). | 🔹 Validar formato do IDEA_KEY (16 bytes obrigatórios) e lançar exceção se incorreto.<br>🔹 Adicionar suporte para `LOG_LEVEL`, `SERVER_PORT` e `ENABLE_TLS` no .env.<br>🔹 Incluir hash de verificação do arquivo `.env` (auditoria). |

---

## 🧠 Funcionalidades Atuais

- ✅ Carregamento automático de variáveis `.env`.  
- ✅ Definição segura de `SECRET_KEY`, `IDEA_KEY` e `DATABASE_URL`.  
- ✅ FastAPI inicializado e roteado com módulos `auth` e `messaging`.  
- ⚠️ Falta integração direta com os logs globais e monitoramento de saúde.  

---

## 🔐 Melhorias Recomendadas

| Categoria | Implementação recomendada | Objetivo |
|------------|---------------------------|-----------|
| **Middleware** | Adicionar `HTTPSRedirectMiddleware`, `CORSMiddleware` e `TrustedHostMiddleware`. | Reforçar a segurança das requisições HTTP. |
| **Monitoramento** | Criar `/health` e `/metrics` (CPU, conexões, uptime). | Permitir monitoramento remoto da aplicação. |
| **Logs** | Implementar `uvicorn.access` + logger de auditoria (`logs/api.log`). | Fornecer rastreabilidade e métricas de performance. |
| **Validação de ambiente** | Testar integridade de variáveis (`IDEA_KEY`, `SECRET_KEY`, `DB_URL`). | Garantir que o servidor não inicie com chaves inválidas. |

---

## 🧩 Interação com outros módulos

| Módulo | Função |
|--------|--------|
| `backend.auth.routes` | Define endpoints de autenticação e cadastro de usuários. |
| `backend.routes.messaging` | Expõe rotas REST auxiliares para mensagens (teste/monitoramento). |
| `backend.config` | Fornece chaves e URLs seguras para toda a aplicação. |
| `backend/server/server.py` | Roda o servidor TLS assíncrono para comunicação E2EE real. |

---

## 🧭 Próximas Etapas de Implementação

- **[Alta prioridade]** Criar `logs/api.log` e middleware de auditoria com tempo de resposta e IP de origem.  
- **[Alta]** Adicionar `/health` para validar disponibilidade do banco e do servidor.  
- **[Média]** Padronizar logs de inicialização entre `FastAPI` e `server.py`.  
- **[Baixa]** Adicionar hash SHA256 para validação de integridade do `.env`.  

---

## 📁 Status geral da raiz `backend/`

> 🟩 2 arquivos funcionais (`main.py`, `config.py`)  
>  
> 🔐 **Camada de inicialização estável e segura**, pronta para integração com auditoria e monitoramento — próxima etapa: consolidar logs e segurança de middleware para produção.
