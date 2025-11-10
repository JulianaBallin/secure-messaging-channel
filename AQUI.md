## 📋 Tarefas em Andamento

### 🔧 Juliana
- [ ] Apagar logs antigos  
- [ ] Retornar **estrutura completa** de todas as tabelas do banco de dados  
- [ ] Corrigir o **padrão de logs** para salvar por **pilar de segurança** e **subpilar detalhado**  
- [ ] Consolidar toda a documentação em **um único manual**

### 🧹 Ana
- [ ] Apagar arquivos e funções não utilizadas  
- [ ] Indicar nova mensagem na lista de contatos (Com emoji ou Nova Mesagem ao lado do nome de contato)
- [ ] Verificar possibilidade de **manter histórico de mensagens no chat** mesmo após o usuário sair do grupo

### 🔑 Fernando
- [ ] Verificar **recuperação de chaves antigas** no log em grupo
- [ ] Criar **Docker Compose** para o sistema  

### 🐳 Marcelo
- [ ] Verificar **implementação de fila de mensagens**

---

## 🧠 Estrutura dos Logs por Pilares da Segurança da Informação

| **Pilar** | **Descrição** | **Mecanismos / Exemplos Técnicos** |
|------------|----------------|------------------------------------|
| **Confidencialidade** | Garante que apenas pessoas autorizadas possam acessar as informações. | 🔒 Criptografia de dados e chaves seguras |
| **Integridade** | Assegura que a informação não foi alterada indevidamente. | 🧾 Hashes criptográficos (SHA-256, SHA-3, BLAKE2), assinaturas digitais (RSA) |
| **Disponibilidade** | Mantém o sistema acessível e funcional quando necessário. | ⚙️ Filas de mensagens, reconexão automática |
| **Autenticidade** | Confirma a identidade dos usuários e da origem das mensagens. | 🪪 Certificados digitais (TLS/SSL), tokens JWT, assinaturas digitais (RSA/ECC) |
