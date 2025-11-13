## 📋 Tarefas em Andamento

### 🔧 Juliana
- [X] Apagar logs antigos  
- [X] Retornar **estrutura completa** de todas as tabelas do banco de dados  
- [X] Corrigir o **padrão de logs** para salvar por **pilar de segurança**
- [X] Consolidar toda a documentação em **um único manual**
- [X] Melhorar logs de autenticidade

### 🧹 Ana
- [ ] Apagar arquivos e funções não utilizadas  
- [ ] Indicar nova mensagem na lista de contatos (Com emoji ou Nova Mesagem ao lado do nome de contato)
- [ ] Verificar possibilidade de **manter histórico de mensagens no chat** mesmo após o usuário sair do grupo

### 🔑 Fernando
- [ ] Verificar **recuperação de chaves antigas** no log em grupo
- [ ] Criar **Docker Compose** para o sistema
- [ ] Melhorar logs de cryptografia:individual e grupo/confidencialidade

### 🐳 Marcelo
- [ ] Verificar **implementação de fila de mensagens**
- [ ] Melhorar logs de integridade
- [ ] Melhorar logs de disponibilidade

---

## 🧠 Estrutura dos Logs por Pilares da Segurança da Informação

| **Pilar** | **Descrição** | **Mecanismos / Exemplos Técnicos** |
|------------|----------------|------------------------------------|
| **Confidencialidade** | Garante que apenas pessoas autorizadas possam acessar as informações. | 🔒 Criptografia de dados e chaves seguras |
| **Integridade** | Assegura que a informação não foi alterada indevidamente. | 🧾 Hashes criptográficos (SHA-256, SHA-3, BLAKE2), assinaturas digitais (RSA) |
| **Disponibilidade** | Mantém o sistema acessível e funcional quando necessário. | ⚙️ Filas de mensagens, reconexão automática |
| **Autenticidade** | Confirma a identidade dos usuários e da origem das mensagens. | 🪪 Certificados digitais (TLS/SSL), tokens JWT, assinaturas digitais (RSA/ECC) |
