# 🧩 CipherTalk – Checklist de Implementação e Segurança

**Status atual:** sistema funcional com comunicação segura (TLS), registro de usuários com RSA e armazenamento seguro no banco.  
**Objetivo final:** mensageria criptografada ponta a ponta (E2EE), multiusuário e escalável.

---

## ✅ 1. Estrutura Geral

- [x] Estrutura modular (`backend/`, `client/`, `keys/`, `logs/`)
- [x] Módulos separados por responsabilidade (auth, crypto, server, etc.)
- [x] CLI principal com menus base (`run_cli.py`)
- [x] Makefile com targets de setup, test, run e lint
- [x] `.gitignore` configurado para excluir chaves, caches e ambientes virtuais

---

## ⚙️ 2. Backend – Servidor e Banco de Dados

### 🧱 Servidor (`backend/server/server.py`)
- [x] Servidor assíncrono (asyncio) com suporte multiusuário
- [x] Comunicação segura via **TLS (SSL)**
- [x] Certificados gerados automaticamente (`cert.pem`, `key.pem`)
- [x] Liberação automática de porta ocupada
- [x] Logging detalhado (`logs/server.log`)
- [x] Modularização com `handlers.py`
- [x] Criação automática de banco (`ensure_database()` com cores ANSI)

🔒 **Segurança atual:**
- [x] Canal de transporte criptografado (TLS 1.2+)
- [x] Hash seguro de senhas
- [x] Tokens JWT com expiração
- [x] Armazenamento de chaves públicas no servidor
- [x] Chaves privadas mantidas apenas localmente

🧩 **Melhorias futuras:**
- [ ] Limite de conexões por IP (proteção DDoS)
- [ ] Rotação automática de certificados TLS
- [ ] Assinatura digital de mensagens (RSA + SHA256)
- [ ] Criptografia de integridade (HMAC)
- [ ] Handler completo de grupos (broadcast e permissões)

---

## 🗄️ 3. Banco de Dados (SQLite via SQLAlchemy)

- [x] Banco fixo em `backend/database/cipher_talk.db`
- [x] Modelos ORM: `User`, `Message`, `Group`, `GroupMember`
- [x] Criação automática via `Base.metadata.create_all()`
- [x] Sessões seguras (`SessionLocal`)
- [x] Caminho absoluto configurado em `connection.py`

🧩 **Faltante:**
- [ ] Migração para PostgreSQL (escala real)
- [ ] Criptografia de dados (SQLCipher)
- [ ] Índices otimizados
- [ ] Tabela de auditoria (ações, IPs, timestamps)

---

## 🔐 4. Criptografia – RSA + IDEA

- [x] RSA 2048 bits (par de chaves público/privado)
- [x] IDEA 128 bits para mensagens simétricas
- [x] Chave IDEA cifrada com RSA antes do envio
- [x] Armazenamento seguro das chaves privadas (`chmod 600`)
- [x] E2EE parcial já implementado

🧩 **Faltante:**
- [ ] Assinatura digital (autenticidade)
- [ ] Troca de chaves efêmera (Diffie-Hellman)
- [ ] Armazenamento seguro de metadados cifrados
- [ ] Rotação/revogação de chaves RSA

---

## 👥 5. Autenticação e Autorização

- [x] Login e registro com hash de senha e JWT
- [x] Políticas de senha forte
- [x] Nomes de usuário únicos e validados
- [x] Tokens JWT expiram após 30 min
- [x] Tentativas de login registradas

🧩 **Faltante:**
- [ ] Logout e revogação de tokens
- [ ] Controle de múltiplas sessões por usuário
- [ ] Limite de tentativas (anti-brute force)
- [ ] Refresh tokens e reautenticação
- [ ] Logs de auditoria detalhados

---

## 💬 6. Clientes (CLI) – Comunicação Segura

- [x] `client/auth/signup_cli.py`: registro TLS + RSA
- [x] Criação local de chave privada
- [x] Transmissão segura (JSON via TLS)
- [ ] `client/auth/login_cli.py`: login com TLS + JWT
- [ ] `client/messages/send_cli.py`: envio de mensagens E2EE
- [ ] `client/messages/read_cli.py`: leitura e decriptação local
- [ ] `client/groups/manage_cli.py`: administração de grupos
- [ ] `client/utils/session_manager.py`: persistência de tokens

---

## 🔄 7. Escalabilidade e Multiusuário

- [x] Multiusuário em tempo real (StreamWriter por conexão)
- [x] Armazenamento de mensagens offline
- [x] Lista de usuários online/offline
- [ ] Suporte a Redis (cache/sessões)
- [ ] PostgreSQL (banco distribuído)
- [ ] Balanceamento de carga (múltiplas instâncias)
- [ ] Containerização (Docker + Nginx TLS passthrough)
- [ ] API REST/GraphQL futura

---

## 🧠 8. Segurança Avançada

| Categoria | Implementado | Faltante |
|------------|---------------|-----------|
| Transporte | ✅ TLS ativo | 🔄 Certificado CA externo |
| Ponta a ponta | ⚙️ Parcial (RSA + IDEA) | 🔒 Assinatura digital e autenticação forte |
| Armazenamento | ✅ Hash e chaves locais | 🔄 Criptografia de logs e mensagens |
| Autenticação | ✅ JWT | 🔄 Roles, refresh tokens |
| Logs | ✅ `logs/server.log` | 🔄 Registro de ataques e erros TLS |

---

## 📈 9. Próximos Passos (Ordem Ideal)

| Etapa | Descrição | Objetivo |
|-------|------------|----------|
| 1️⃣ | Implementar `client/auth/login_cli.py` | Login seguro com TLS + JWT |
| 2️⃣ | Criar `client/messages/send_cli.py` e `read_cli.py` | Mensagens E2EE completas |
| 3️⃣ | Adicionar `handlers_groups.py` | Criação e administração de grupos |
| 4️⃣ | Assinatura digital RSA | Autenticidade e integridade |
| 5️⃣ | Migração para PostgreSQL + Redis | Escalabilidade |
| 6️⃣ | API REST paralela | Integração com web/mobile |

---

## 🔎 Resumo

> O CipherTalk já possui:
> - Servidor seguro (TLS + multiusuário)
> - Registro funcional via CLI com RSA
> - Estrutura modular pronta para expansão  
>
> Próximo foco: **autenticação segura (login TLS + JWT)** e **mensagens E2EE completas**.

---
