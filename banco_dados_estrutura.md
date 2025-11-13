# Tabelas da Banco de Dados
## 🗃️ Tabela: users
**Descrição:** Armazena os usuários do sistema com suas credenciais e chaves públicas.

| Campo        | Tipo           | Obrigatório | Descrição                          | Exemplo                          |
|--------------|----------------|-------------|------------------------------------|----------------------------------|
| id           | Integer        | ✅          | ID único (Primary Key)             | 1                                |
| username     | String(50)     | ✅          | Nome único (até 50 chars)          | "alice_silva"                    |
| password_hash| String(255)    | ✅          | Hash bcrypt da senha               | "$2b$12$LQv3c1..."               |
| public_key   | LargeBinary    | ❌          | Chave pública RSA (bytes)          | b'-----BEGIN PUBLIC KEY-----...' |
| is_online    | Boolean        | ✅          | Status online/offline              | true                             |
| created_at   | DateTime       | ✅          | Data criação (UTC-4)               | 2024-01-15 10:30:00              |


---

## 🗃️ Tabela: groups
**Descrição:** Grupos de conversa com administrador.

| Campo      | Tipo        | Obrigatório | Descrição               | Exemplo                  |
|------------|-------------|-------------|--------------------------|--------------------------|
| id         | Integer     | ✅          | ID único (Primary Key)  | 1                        |
| name       | String(100) | ✅          | Nome único do grupo     | "Equipe Dev"             |
| admin_id   | Integer     | ✅          | ID do usuário admin     | 1                        |
| created_at | DateTime    | ✅          | Data criação (UTC-4)    | 2024-01-15 11:00:00      |


---

## 🗃️ Tabela: group_members
**Descrição:** Associação entre usuários e grupos (N para N).

| Campo     | Tipo     | Obrigatório | Descrição                   | Exemplo              |
|-----------|----------|-------------|------------------------------|----------------------|
| id        | Integer  | ✅          | ID único (Primary Key)       | 1                    |
| user_id   | Integer  | ❌          | ID do usuário                 | 2                    |
| group_id  | Integer  | ❌          | ID do grupo                   | 1                    |
| joined_at | DateTime | ✅          | Data de entrada               | 2024-01-15 11:05:00 |

**Constraint:** `UNIQUE(user_id, group_id)` — o usuário não pode entrar 2x no mesmo grupo.

---

## 🗃️ Tabela: messages
**Descrição:** Mensagens privadas ou em grupo (conteúdo criptografado).

| Campo             | Tipo         | Obrigatório | Descrição                                  | Exemplo                       |
|-------------------|--------------|-------------|----------------------------------------------|-------------------------------|
| id                | Integer      | ✅          | ID único (Primary Key)                       | 1                             |
| sender_id         | Integer      | ✅          | ID do remetente                              | 1                             |
| receiver_id       | Integer      | ❌          | ID destinatário (msg privada)                | 2                             |
| group_id          | Integer      | ❌          | ID do grupo (msg grupo)                      | NULL                          |
| signature         | LargeBinary  | ❌          | Assinatura digital                           | b'signature_data'             |
| content_hash      | String(64)   | ❌          | Hash SHA256 do conteúdo                      | "a1b2c3..."                   |
| content_encrypted | Text         | ✅          | Conteúdo criptografado                       | "U2FsdGVkX18z5Yl4..."         |
| key_encrypted     | Text         | ❌          | Chave simétrica criptografada                | "U2FsdGVkX19PQqBd..."         |
| is_read           | Boolean      | ❌          | Status de leitura                            | false                         |
| timestamp         | DateTime     | ❌          | Data/hora envio (UTC-4)                      | 2024-01-15 14:30:00           |

**Regra:**  
- Mensagem privada: `receiver_id NOT NULL AND group_id IS NULL`  
- Mensagem em grupo: `receiver_id IS NULL AND group_id NOT NULL`

---

## 🗃️ Tabela: session_keys
**Descrição:** Chaves de sessão criptografadas para usuários ou grupos.

| Campo          | Tipo        | Obrigatório | Descrição                           | Exemplo                         |
|----------------|-------------|-------------|---------------------------------------|---------------------------------|
| id             | Integer     | ✅          | ID único (Primary Key)               | 1                               |
| entity_type    | String(10)  | ✅          | 'user' ou 'group'                    | "user"                          |
| entity_id      | Integer     | ✅          | ID da entidade                       | 1                               |
| cek_encrypted  | Text        | ✅          | Chave de conteúdo criptografada       | "U2FsdGVkX1/abc123..."          |
| cek_fingerprint| String(64)  | ❌          | Hash SHA256 da CEK                    | "f6g7h8i9j0..."                 |
| created_at     | DateTime    | ❌          | Data criação (UTC-4)                  | 2024-01-15 10:25:00             | 

---
.  

.
# Regras de Integridade e Relacionamentos do Banco de Dados

## 🔗 Relacionamentos e Integridade

### `users → groups (admin_id)`
- Um usuário pode ser **admin de vários grupos**.
- Se o admin for deletado → `admin_id = NULL` (SET NULL).

---

### `users ↔ group_members ↔ groups`
- Um usuário pode participar de **vários grupos**.
- Um grupo pode ter **vários usuários**.
- Chave única garantindo associação exclusiva:  
  **`UNIQUE(user_id, group_id)`**.

---

### `messages`
Regra de existência dos destinos:
- Mensagem **privada**:  
  `receiver_id IS NOT NULL AND group_id IS NULL`
- Mensagem **de grupo**:  
  `receiver_id IS NULL AND group_id IS NOT NULL`
- Toda mensagem SEMPRE tem:  
  **`sender_id`**.

---

## 🧹 Cascatas de Deleção

### Quando um *usuário* é deletado:
- Suas mensagens são deletadas (`ON DELETE CASCADE`)
- Suas memberships em grupos são deletadas (`ON DELETE CASCADE`)

### Quando um *grupo* é deletado:
- Mensagens do grupo são deletadas (`ON DELETE CASCADE`)
- Membros vinculados ao grupo são deletados (`ON DELETE CASCADE`)

---

