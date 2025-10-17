# 🗄️ Manual do Banco de Dados — CipherTalk Secure Messaging Channel

## 📘 1. Visão Geral
O sistema CipherTalk utiliza um banco de dados SQLite local (`cipher_talk.db`) para armazenar:
- 👤 Usuários registrados com senhas hash (Argon2id) e chaves públicas RSA.
- 💬 Mensagens privadas e de grupo, criptografadas.
- 👥 Grupos e membros associados.
- ⏱️ Status de leitura das mensagens e timestamps no fuso de Manaus (-4h).

Todas as operações (CRUD — Create, Read, Update, Delete) são centralizadas em:
backend/database/run_banco_dados.py

Os scripts de inicialização, consultas e manutenção do banco são automatizados via Makefile.db.

------------------------------------------------------------

## ⚙️ 2. Estrutura de Arquivos Relevantes
```
backend/
 ├── database/
 │   ├── cipher_talk.db               ← Banco SQLite (gerado automaticamente)
 │   ├── init_db.py                   ← Cria/atualiza o banco
 │   ├── run_banco_dados.py           ← Painel CRUD interativo
 │   ├── queries/                     ← Funções de CRUD por tabela
 │   │   ├── users.py
 │   │   ├── groups.py
 │   │   ├── members.py
 │   │   └── messages.py
 │   └── connection.py                ← Configuração SQLAlchemy
 ├── utils/
 │   └── db_utils.py                 ← Decorator seguro com rollback automático
 └── auth/
     └── models.py                   ← Modelos ORM (Users, Groups, Messages)
Makefile.db                           ← Automação de tarefas do banco
```
------------------------------------------------------------

## 🧰 3. Configuração Inicial do Ambiente

Antes de rodar qualquer comando do banco, é necessário preparar o ambiente Python:

```bash
make setup
```

🔹 Este comando realiza:
1. Criação do ambiente virtual `.venv`
2. Instalação do `pip` atualizado
3. Instalação de todas as dependências listadas em `requirements.txt`

✅ Ao finalizar, você terá um ambiente isolado e pronto para usar todos os comandos do banco de dados.

------------------------------------------------------------

## 🧱 4. Inicializar ou Atualizar o Banco

Para criar ou atualizar o banco de dados automaticamente:

```bash
make db-init
```

🔸 O sistema:
- Cria `cipher_talk.db` se não existir.
- Atualiza o schema (cria novas tabelas sem apagar dados existentes).
- Mostra as tabelas criadas diretamente no terminal.
- Gera logs detalhados em `logs/database.log`.

📘 **Exemplo de saída:**
```
📦 Banco de dados alvo: sqlite:///backend/database/cipher_talk.db
🆕 Nenhum banco encontrado. Criando novo...
✅ Banco criado com sucesso!
📋 Estrutura final: ['users', 'groups', 'group_members', 'messages']
```

------------------------------------------------------------

## ♻️ 5. Recriar o Banco do Zero

Se desejar apagar o banco e recriar todas as tabelas do zero:

```bash
make db-reset
```

⚠️ **Atenção:** Este comando apaga todas as informações existentes no banco e cria uma nova estrutura limpa.  
Ideal para testes completos, reconfiguração do ambiente ou reset total de dados.

------------------------------------------------------------

## 🧭 6. Executar o Painel Central CRUD

O painel principal para gerenciar e testar o banco de forma interativa:

```bash
make db-run
```

🔹 Abre o painel com menus organizados:

```
=== 🧭 PAINEL CENTRAL — CIPHERTALK ===
1️⃣ - Inserir registros
2️⃣ - Consultar registros
3️⃣ - Editar informações
4️⃣ - Deletar registros
0️⃣ - Sair
```

Dentro de cada menu:
- **Inserir:** criar usuários, grupos, membros e mensagens.
- **Consultar:** listar ou detalhar registros.
- **Editar:** atualizar status de usuário, renomear grupos, marcar mensagens como lidas.
- **Deletar:** remover usuários, grupos ou mensagens.

🪵 Todos os logs de operações são registrados automaticamente em `logs/database.log`.

------------------------------------------------------------

## 🔍 7. Inspecionar o Banco

Para visualizar rapidamente as tabelas e o schema do banco SQLite:

```bash
make db-inspect
```

📘 **Exemplo de saída:**
```
🔍 Estrutura atual do banco:
group_members  groups  messages  users

CREATE TABLE users (
    id INTEGER NOT NULL,
    username VARCHAR(50) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    ...
);
```

------------------------------------------------------------

## 🗑️ 8. Remover Banco Manualmente

Se quiser apenas deletar o arquivo `.db` (sem recriar automaticamente):

```bash
make db-remove
```

📘 **Resultado esperado:**
```
🧹 Banco removido: backend/database/cipher_talk.db
```

------------------------------------------------------------

## 🧹 9. Limpar Logs e Caches

Para limpar logs, arquivos temporários e caches Python:

```bash
make db-clean
```

🧼 **Limpa automaticamente:**
- `logs/*.log`
- Diretórios `__pycache__`
- Caches Python (`.pytest_cache`, `.mypy_cache`, etc.)

✅ Ideal para manter o projeto limpo e organizado após execuções ou testes.


## 📒 10. Logs de Auditoria
Os logs do banco de dados são registrados em:
logs/database.log

Exemplo:
2025-10-17 10:12:21 [INFO] [database] 🧱 Novo banco criado
2025-10-17 10:12:25 [INFO] [database] [INSERT_USER_RSA] Usuário criado: Juliana
2025-10-17 10:15:10 [INFO] [database] [SELECT] Consulta de mensagens executada

Os timestamps usam o fuso horário de Manaus (-04:00).

------------------------------------------------------------

## 🧩 11. Funções de Segurança
Cada operação do banco (nas pastas queries/) utiliza o decorator:

@safe_db_operation
def create_user(db, username, password):
    ...

Esse decorator (backend/utils/db_utils.py) garante:
- Rollback automático em caso de erro SQL.
- Mensagens claras no terminal.
- Proteção contra travamentos da sessão SQLAlchemy.

------------------------------------------------------------

## 🚀 12. Fluxo Recomendado para Testes
Etapa | Comando | Descrição
------|----------|-----------
🐍 Preparar ambiente | make -f Makefile.db setup | Cria venv e instala dependências
🧱 Criar banco | make -f Makefile.db db-init | Cria/atualiza o banco
🧭 Testar CRUD | make -f Makefile.db db-run | Executa painel interativo
🔍 Conferir estrutura | make -f Makefile.db db-inspect | Mostra tabelas
♻️ Recriar do zero | make -f Makefile.db db-reset | Apaga e recria
🧹 Limpar ambiente | make -f Makefile.db db-clean | Remove logs e caches

------------------------------------------------------------

## 🧠 13. Boas Práticas
- Sempre execute o make -f Makefile.db db-init após alterar modelos ORM.
- Use o painel CRUD apenas com o ambiente virtual ativo (source .venv/bin/activate).
- Nunca compartilhe o arquivo .db sem antes criptografá-lo.
- Faça backups periódicos se estiver em ambiente de produção.
- Verifique os logs em caso de erros antes de reiniciar o sistema.

------------------------------------------------------------

✅ Fim do Manual do Banco de Dados CipherTalk
