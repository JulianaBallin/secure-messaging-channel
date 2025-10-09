# 🔐 Lógica Geral do Sistema de Comunicação — CipherTalk

## 🧩 Visão Geral

O CipherTalk é um sistema de **comunicação segura ponta a ponta (E2EE)** baseado em **criptografia híbrida**:
- RSA (assimétrica): usada para troca segura de chaves IDEA.
- IDEA (simétrica): usada para criptografar o conteúdo real das mensagens.

A segurança e escalabilidade do sistema se baseiam em três pilares:
1. **Criptografia ponta a ponta (E2EE)** — o servidor nunca lê as mensagens.
2. **Gerenciamento seguro de chaves** — cada conversa (par ou grupo) possui uma chave IDEA única.
3. **Persistência auditável** — histórico criptografado armazenado no banco SQLite, com logs de auditoria.

---

## 💬 Comunicação entre 2 Usuários (Chat Privado)

### 🔄 Fluxo Básico

1. **Autenticação**
   - Usuário A e Usuário B fazem login (via `handle_login`) e recebem token JWT.
   - Cada um tem um par RSA (privada local, pública no servidor).

2. **Troca de Chaves**
   - Usuário A gera uma chave IDEA aleatória para a conversa.
   - Essa chave é criptografada com a **chave pública RSA de B** e enviada junto à mensagem.

3. **Criptografia e Envio**
   - A mensagem é criptografada localmente com IDEA (CBC + PKCS7).
   - O pacote enviado ao servidor contém:
     ```json
     {
       "to": "UsuarioB",
       "content_encrypted": "<mensagem_criptografada>",
       "key_encrypted": "<chave_IDEA_criptografada_com_RSA>",
       "timestamp": "2025-10-09T14:35:00Z"
     }
     ```
   - O servidor apenas **roteia ou armazena** a mensagem — **nunca descriptografa.**

4. **Recebimento**
   - Usuário B recebe o pacote, descriptografa a chave IDEA com sua chave privada RSA.
   - Em seguida, descriptografa a mensagem com essa chave IDEA.

5. **Persistência**
   - O servidor salva no banco (`messages`):
     - `sender_id`, `receiver_id`
     - `content_encrypted`
     - `key_encrypted`
     - `timestamp`
   - Tudo é armazenado **criptografado**, garantindo confidencialidade.

---

## 👥 Comunicação em Grupo (Chats Coletivos)

### ⚙️ Estrutura e Segurança

Cada grupo funciona como uma **instância independente de sessão IDEA**, gerenciada por um **admin**.  
O servidor **não gera chaves** — apenas distribui e armazena mensagens criptografadas.

### 🧱 Fluxo de Criação e Gerenciamento

1. **Criação do Grupo**
   - Usuário criador se torna **admin** por padrão.
   - Uma chave IDEA única do grupo é gerada **no cliente do admin**.
   - Essa chave é criptografada com a chave pública de cada novo membro.

2. **Entrada de Novo Membro**
   - Apenas o **admin** pode adicionar usuários.
   - Ao adicionar um novo membro:
     - A chave IDEA do grupo é criptografada com a chave RSA pública do novo membro.
     - O membro passa a receber mensagens cifradas com essa chave.

3. **Envio de Mensagem**
   - Cada mensagem do grupo contém:
     - `group_id`, `content_encrypted`, `keys_encrypted` (um dicionário `{user: chave_RSA_cifrada}`)
   - O servidor envia individualmente a cada membro:
     - Mensagem cifrada + chave IDEA cifrada para aquele membro.

4. **Saída de Membro**
   - Qualquer membro (não admin) pode sair livremente.
   - Se o **admin sair**, o sistema deve:
     - Promover outro membro automaticamente (`transfer_group_admin`).
     - Gerar uma **nova chave IDEA do grupo**.
     - Recriptografar e distribuir a nova chave aos membros restantes.

5. **Troca de Chaves**
   - Sempre que um membro entra ou sai:
     - O admin **gera uma nova chave IDEA**.
     - A chave antiga é invalidada.
     - Cada novo membro recebe a nova chave via RSA.
   - Garante sigilo mesmo se um ex-membro mantiver o histórico antigo.

6. **Remoção de Grupo**
   - Se todos os membros saírem, o grupo é removido automaticamente (`delete_empty_groups`).
   - Logs registram o evento com tag `[GROUP_REMOVE]`.

---

## 🔐 Estratégia de Criptografia e Logs

### 📦 Criptografia Híbrida
| Etapa | Algoritmo | Descrição |
|-------|------------|-----------|
| Troca de chave | RSA (PKCS1_OAEP) | Garante sigilo da chave IDEA. |
| Mensagem | IDEA (CBC + PKCS7) | Rápida e segura para texto. |
| Armazenamento | Base64 + SQLite | Persistência criptografada. |

### 🪵 Logs e Auditoria
- **database.log** — operações de leitura e gravação SQL.
- **crypto.log** — geração, cifragem e falhas IDEA/RSA.
- **server.log** — conexões, entregas, desconexões e erros.
- **[AUDIT]** tags no CLI (`run_queries.py`) para consultas de verificação.

---

## 🧭 Regras de Segurança e Escalabilidade

- 🔒 **E2EE garantido** — o servidor nunca acessa o conteúdo das mensagens.
- ⚡ **Multiusuário** — múltiplos usuários simultâneos por TLS.
- 🗄️ **Mensagens Offline** — entregues automaticamente no próximo login.
- 🔁 **Rotação de Chaves IDEA** — a cada mudança de grupo.
- 🚫 **Servidor neutro** — nunca gera nem descriptografa chaves.
- 🧩 **Logs imutáveis** — cada ação importante é registrada para auditoria.

---

## 🧮 Exemplo de Fluxos Simplificados

### 🔹 Chat Privado
- [A] → Gera IDEA → Cifra mensagem → Envia ao servidor
Servidor → Roteia (não lê)
- [B] → Decifra RSA → Decifra IDEA → Exibe mensagem


### 🔹 Chat em Grupo
- Admin → Gera IDEA → Cria grupo → Envia chaves via RSA
- Membros → Recebem chaves IDEA → Participam da conversa
- Quando um sai → Admin gera nova chave IDEA → Redistribui
- Servidor → Armazena tudo criptografado

---

## ✅ Benefícios da Arquitetura

- Nenhuma chave ou mensagem trafega em texto claro.  
- Total conformidade com princípios de **privacidade e confidencialidade**.  
- Escalabilidade horizontal (suporta múltiplos grupos simultâneos).  
- Auditoria detalhada via logs e CLI.  
- Estrutura modular — permite evolução para interface web ou mobile no futuro.
