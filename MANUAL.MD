# 🚀 Guia de Execução — Canal de Comunicação Seguro (CipherTalk)

Este guia explica **passo a passo** como rodar o sistema completo do projeto CipherTalk, incluindo o servidor, o banco de dados e os clientes CLI.  
O objetivo é permitir **comunicação segura ponta a ponta (E2EE)** entre múltiplos usuários em terminais diferentes.

---

## ⚙️ 1️⃣ Pré-requisitos

Antes de tudo, garanta que você possui instalado:
- 🐍 **Python 3.12+**
- 🧰 **Virtualenv** (para isolar dependências)
- 📦 **Make** (opcional, mas facilita comandos repetitivos)
- 🔐 **OpenSSL** (para gerar certificados TLS)

---

## 📦 2️⃣ Instalar dependências

```bash
# Crie e ative o ambiente virtual
python -m venv venv
source venv/bin/activate  # no Linux
# ou
venv\Scripts\activate     # no Windows

# Instale as dependências
pip install -r requirements.txt
```

Verifique se o módulo `pycryptodomex` está corretamente instalado:

```bash
pip show pycryptodomex
```

Se o IDEA nativo não estiver disponível, o sistema usará automaticamente o fallback em Python puro.

---

## 🗄️ 3️⃣ Inicializar o banco de dados

O servidor usa **SQLite** como banco de dados local.
Para garantir que as tabelas estão criadas corretamente, execute:

```bash
python init_db.py
```

ou simplesmente inicie o servidor (ele cria o banco automaticamente).

O arquivo do banco será salvo em:

```
backend/database/cipher_talk.db
```

---

## 🧱 4️⃣ Iniciar o servidor (backend)

O servidor é responsável por:

* Gerenciar conexões seguras (TLS/SSL)
* Autenticar usuários
* Armazenar mensagens criptografadas
* Roteamento entre clientes online/offline

### 🔹 Executar o servidor:

```bash
python backend/server/server.py
```

Durante a primeira execução:

* Certificados TLS (`cert.pem` e `key.pem`) serão gerados automaticamente.
* O banco será verificado/criado.
* O servidor iniciará na porta padrão `8888`.

Saída esperada:

```
🗄️ Banco de dados verificado e atualizado com sucesso.
[SERVER] Servidor seguro rodando em ('127.0.0.1', 8888) (TLS habilitado)
```

> 💡 **Mantenha esse terminal aberto**, pois ele é o "servidor central" — os clientes vão se conectar a ele.

---

## 💻 5️⃣ Executar o cliente (CLI)

Em outro terminal (ou outro computador na mesma rede), rode:

```bash
python run_cli.py
```

Este script é a interface principal do usuário (cliente CLI).
Ele permite **cadastro, login, envio e leitura de mensagens**.

---

## 🧭 6️⃣ Uso do cliente CLI

Após rodar o cliente, o menu principal será exibido:

```
=== 🔐 CipherTalk CLI ===
1️⃣  - Cadastrar novo usuário
2️⃣  - Fazer login
0️⃣  - Sair
```

### 📝 Cadastrar novo usuário

1️⃣ Escolha a opção `1`.
2️⃣ Informe nome de usuário e senha.
3️⃣ O sistema:

* Gera automaticamente um par RSA.
* Salva a chave privada localmente em `keys/<usuario>_private.pem`.
* Envia a chave pública ao servidor.

---

### 🔑 Fazer login

2️⃣ Escolha a opção `2`.
Informe seu usuário e senha cadastrados.
Após o login bem-sucedido, você verá o menu interno:

```
=== 💬 CipherTalk - Usuário: Juliana ===
1️⃣  - Listar usuários
2️⃣  - Enviar mensagem segura (E2EE)
3️⃣  - Ler mensagens recebidas
0️⃣  - Logout
```

---

### 👥 Listar usuários

1️⃣ Mostra todos os usuários cadastrados no servidor, indicando:

* 🟢 Online
* ⚫ Offline
  e se possuem chave pública válida.

---

### 💬 Enviar mensagem segura

2️⃣ Digite o nome do destinatário e a mensagem.
O sistema:

* Gera uma chave IDEA aleatória (128 bits);
* Criptografa a mensagem com IDEA (modo CBC);
* Criptografa a chave IDEA com a chave pública RSA do destinatário;
* Envia ao servidor via canal TLS.

> Se o destinatário estiver offline, a mensagem será armazenada criptografada no banco de dados até ele se conectar.

---

### 📥 Ler mensagens recebidas

3️⃣ Mostra todas as mensagens recebidas:

* Descriptografa automaticamente com a chave privada RSA local;
* Exibe o conteúdo decifrado no terminal.

Mensagens pendentes (armazenadas enquanto o usuário estava offline) também serão recuperadas ao fazer login.

---

## 📊 7️⃣ Monitorar logs

Todos os eventos são salvos na pasta `logs/`:

| Arquivo        | Conteúdo                                                |
| -------------- | ------------------------------------------------------- |
| `server.log`   | Conexões, autenticações, mensagens e erros do servidor. |
| `messages.log` | Logs do cliente (envios, recebimentos, falhas).         |
| `crypto.log`   | Operações de criptografia (IDEA e RSA).                 |
| `database.log` | Ações do banco (inserções, exclusões, falhas).          |

Visualize os logs com:

```bash
tail -f logs/server.log
```

---

## 🧪 8️⃣ Testar criptografia manualmente

Para testar o módulo IDEA isoladamente:

```bash
python - <<'EOF'
from backend.crypto.idea_manager import verify_encryption_cycle
verify_encryption_cycle()
EOF
```

Saída esperada:

```
✅ Teste IDEA bem-sucedido: criptografia e descriptografia íntegras.
```

---

## 🧩 9️⃣ Estrutura esperada (resumo)

```
secure-messaging-channel/
├── backend/
│   ├── auth/
│   ├── crypto/
│   ├── database/
│   ├── messages/
│   ├── server/
│   └── utils/
├── client/
│   ├── auth/
│   ├── messages/
│   ├── menus/
│   └── run_cli.py
├── logs/
│   ├── server.log
│   ├── messages.log
│   ├── crypto.log
│   └── database.log
├── keys/
│   └── <usuario>_private.pem
└── backend/database/cipher_talk.db
```

---

## ✅ 1️⃣0️⃣ Dicas finais

* Sempre mantenha o **servidor ativo** antes de abrir os clientes.
* Você pode abrir **vários terminais** para simular diferentes usuários.
* Caso a porta 8888 esteja ocupada, altere a variável no `.env`:

  ```
  SERVER_PORT=9999
  ```
* Em caso de erros, verifique o arquivo `logs/server.log`.

---
