# 🛡️ Checklist de Desenvolvimento – CipherTalk

## ✅ 1. Estrutura Inicial do Projeto
- [x] Criar repositório `secure-messaging-channel`
- [x] Adicionar `README.md` com descrição do projeto
- [x] Criar `LICENSE`
- [x] Gerar `.gitignore` completo
- [x] Criar `requirements.txt`
- [x] Estruturar diretórios principais:
  - `backend/auth/`
  - `backend/crypto/`
  - `backend/database/`
  - `backend/messages/`
  - `backend/groups/`
  - `backend/server/`
  - `tests/`

---

## ✅ 2. Banco de Dados (SQLite)
- [x] Configurar conexão com SQLite usando SQLAlchemy
- [x] Criar script `init_db.py` para geração do banco (`cipher_talk.db`)
- [x] Estruturar tabelas:
  - `users` → credenciais, chaves públicas/privadas, data de criação
  - `messages` → mensagens enviadas (armazenadas criptografadas)
  - `groups` → metadados de grupos
  - `group_members` → relação usuários ↔ grupos
- [x] Confirmar criação com `inspect(engine).get_table_names()`

---

## ✅ 3. Autenticação Segura
- [x] Criar hash de senha seguro com `passlib[bcrypt]`
- [x] Validar políticas de senha:
  - Mínimo 8 caracteres
  - Pelo menos 1 maiúscula
  - Pelo menos 1 número
  - Pelo menos 1 caractere especial
- [x] Restringir nome de usuário (sem acentos/caracteres especiais, apenas `_`)
- [x] Garantir unicidade de usernames no banco
- [x] Armazenar apenas hash de senha no banco
- [x] Carregar variáveis sensíveis com `os.getenv()` (`.env`)

---

## ✅ 4. Servidor Assíncrono Seguro (`asyncio`)
- [x] Criar servidor TCP assíncrono (`backend/server/server.py`)
- [x] Implementar criação de usuário (`action: register`)
- [x] Implementar login (`action: login`) com validação de hash
- [x] Gerar tokens JWT com expiração (30 min)
- [x] Validar tokens em todas as mensagens
- [x] Recusar conexões com token inválido/expirado
- [x] Gerenciar estado de usuários online
- [x] Armazenar mensagens se usuário estiver offline e entregar no login
- [x] Logger de eventos importantes (login, logout, mensagem entregue/salva, erros)
- [x] Corrigir bug de encoding UTF-8 em respostas do servidor
- [x] Resolver conflito de porta `[Errno 98] address already in use`

---

## ✅ 5. Cliente CLI
- [x] Criar cliente assíncrono (`backend/server/client.py`)
- [x] Menu interativo:
  - [x] Criar novo usuário
  - [x] Fazer login
  - [x] Sair
- [x] Conectar ao servidor e receber token JWT
- [x] Enviar mensagens autenticadas
- [x] Receber mensagens em tempo real
- [x] Exibir mensagens armazenadas ao logar
- [x] Corrigir `JSONDecodeError` ao lidar com respostas não-JSON
- [x] Melhorar UX com tratamento de erros de rede e autenticação

---

## 📁 6. Consultas ao Banco (novo módulo)
Criar pasta dedicada a consultas: `backend/database/queries/`

Funções planejadas:
- [ ] `get_all_users()` – retorna todos os usuários e status (online/offline)
- [ ] `get_user_by_username(username)` – busca usuário específico
- [ ] `get_all_groups()` – lista todos os grupos existentes
- [ ] `get_group_members(group_id)` – lista de membros de um grupo
- [ ] `get_user_messages(user_id)` – histórico completo de mensagens de um usuário
- [ ] `get_offline_messages(user_id)` – mensagens não lidas

---

## 🔐 Próximos Passos (planejados)
- [ ] Implementar criptografia automática RSA + IDEA no cliente
- [ ] Criptografia ponta a ponta em conversas em par e grupos
- [ ] Estrutura de grupos com:
  - [ ] Criação e exclusão
  - [ ] Adição/remoção de membros
  - [ ] Promoção a admin e regeneração de chaves
- [ ] Caixa de mensagens com filtros (par vs grupo, lidas vs não lidas)
- [ ] Lógica de histórico por usuário e por grupo
- [ ] Logs detalhados de segurança e chaves
- [ ] Interface de linha de comando para gerenciamento de grupos

---

📌 **Status atual:**  
✅ Banco de dados funcionando  
✅ Servidor assíncrono seguro com JWT  
✅ Criação e login de usuários com hash  
✅ Envio e recebimento de mensagens com autenticação  
✅ Estrutura pronta para próxima etapa: criptografia ponta a ponta e lógica de grupos
