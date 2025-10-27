# 🧪 Casos de Teste — Canal de Comunicação Seguro

## CT01: Mensagem Privada
**Objetivo:** Validar a criação de mensagens privadas, o envio/recebimento e a troca de usuários no terminal.

### Pré-condições
- 4 usuários criados e registrados no sistema.  
- Cada usuário possui par de chaves RSA gerado.  
- Conexão com o banco de dados ativa.

### Passos
1. Criar 4 usuários via terminal.  
2. Listar todos os usuários e confirmar o status (online/offline).  
3. Iniciar um chat privado com um usuário específico.  
4. Enviar e receber pelo menos uma mensagem criptografada.  
5. Encerrar o chat atual.  
6. Iniciar um novo chat com outro usuário.

### Resultados Esperados
- Os usuários são exibidos corretamente com seus status.  
- A primeira conversa ocorre com mensagens criptografadas de ponta a ponta.  
- Ao trocar de usuário, a sessão anterior é encerrada com segurança.  
- Cada conversa mantém isolamento e confidencialidade.

---

## CT02: Mensagem em Grupo (2 Usuários)
**Objetivo:** Validar criação de grupo, substituição de administrador e integridade da troca de chaves com 2 usuários.

### Pré-condições
- Pelo menos 2 usuários cadastrados.  
- Módulo de gerenciamento de chaves RSA e grupos ativo.

### Passos
1. Criar um novo grupo.  
2. Verificar se o grupo aparece na lista de grupos disponíveis.  
3. Adicionar um usuário a partir da lista de cadastrados.  
4. Remover o administrador atual — o outro usuário deve se tornar admin automaticamente.  
5. Verificar se o usuário removido mantém acesso ao histórico de conversas.  
6. Verificar se ocorreu troca de chaves após a mudança de admin.

### Resultados Esperados
- O grupo é criado e exibido corretamente.  
- A transferência de admin ocorre automaticamente.  
- O usuário removido mantém acesso apenas ao histórico anterior, sem receber novas mensagens.  
- As chaves são rotacionadas ou recriptografadas conforme esperado.

---

## CT03: Mensagem em Grupo (3 Usuários)
**Objetivo:** Validar a adição dinâmica de membros e o controle de acesso ao histórico de mensagens.

### Pré-condições
- 3 usuários registrados no sistema.  
- Sistema de criptografia e gerenciamento de grupo funcionando.

### Passos
1. Criar um grupo.  
2. Confirmar que o grupo está registrado.  
3. Adicionar um usuário a partir da lista de cadastrados.  
4. Iniciar uma conversa no grupo.  
5. Adicionar um terceiro usuário ao grupo.  
6. Verificar se o novo usuário tem acesso às mensagens enviadas antes de sua entrada.

### Resultados Esperados
- A conversa ocorre normalmente entre os membros existentes.  
- O novo usuário **não tem acesso ao histórico anterior à sua entrada**.  
- As mensagens enviadas após sua entrada são visíveis para todos.  
- O sistema realiza nova troca de chaves para incluir o novo membro.

---

## CT04: Mensagem em Grupo (Múltiplos Usuários e Troca de Admin)
**Objetivo:** Testar operações complexas de grupo com vários usuários, trocas de administrador e consistência do histórico.

### Pré-condições
- 4 ou mais usuários existentes.  
- Sistema suporta múltiplas rotações de chaves.

### Passos
1. Criar um novo grupo.  
2. Confirmar a exibição do grupo na lista.  
3. Adicionar 3 usuários cadastrados.  
4. Iniciar uma conversa.  
5. Remover um usuário e verificar se ele ainda acessa o histórico.  
6. Verificar se houve atualização das chaves após a remoção.  
7. Remover o admin — outro usuário deve se tornar admin automaticamente.  
8. Confirmar que o admin removido não tem acesso a novas mensagens.  
9. Verificar integridade da troca de chaves após a mudança de admin.

### Resultados Esperados
- Todas as operações de grupo ocorrem sem falhas.  
- Usuários removidos perdem acesso a novas mensagens.  
- O papel de admin é transferido corretamente.  
- O histórico é preservado para quem ainda está ativo.  
- O log do sistema registra corretamente as trocas de chaves.

---

## CT05: Mensagem em Grupo — Cenário de Remoção Total
**Objetivo:** Validar a consistência e preservação do histórico quando todos os usuários são removidos do grupo.

### Pré-condições
- Pelo menos um grupo existente com histórico de mensagens.  

### Passos
1. Selecionar um grupo já existente.  
2. Remover o admin (o papel deve ser transferido automaticamente).  
3. Remover os demais usuários um a um.  
4. Após cada remoção, verificar se o grupo mantém o histórico até aquele momento.  
5. Confirmar que o sistema impede estados sem admin ou inconsistentes.

### Resultados Esperados
- A cada remoção ocorre nova troca de chaves entre os usuários restantes.  
- O grupo mantém o histórico até a saída do último usuário.  
- Não ocorre perda de dados nem inconsistência no log.  
- O sistema registra com segurança todas as remoções e trocas de chaves.

---

**Resultado Geral Esperado:**  
Todos os fluxos de comunicação (privada e em grupo) devem garantir **criptografia ponta a ponta**, **rotação segura de chaves**, e **controle de acesso ao histórico de mensagens**, mantendo a integridade e confidencialidade das comunicações.
