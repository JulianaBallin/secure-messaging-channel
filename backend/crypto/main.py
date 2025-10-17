import os
from backend.crypto.idea_manager import IDEAManager
from backend.crypto.rsa_manager import RSAManager
from backend.utils.crypto_logger import crypto_logger
from backend.crypto.group_manager import GroupManager

def criar_usuario(nome: str) -> bool:
    pasta = f"keys/{nome}"
    if not os.path.exists(pasta):
        os.makedirs(pasta)

    privada_path = f"{pasta}/privada.pem"
    publica_path = f"{pasta}/publica.pem"

    if not os.path.exists(privada_path):
        print(f"Gerando chaves para {nome}...")
        privada_pem, publica_pem = RSAManager.gerar_par_chaves()
        with open(privada_path, "w", encoding="utf-8") as f:
            f.write(privada_pem)
        with open(publica_path, "w", encoding="utf-8") as f:
            f.write(publica_pem)

        crypto_logger.log_usuario_criado(nome, publica_pem, privada_pem)
        return True
    return False

def listar_usuarios():
    if not os.path.exists("keys"):
        return []
    usuarios = []
    for item in os.listdir("keys"):
        if os.path.isdir(f"keys/{item}") and os.path.exists(f"keys/{item}/publica.pem"):
            usuarios.append(item)
    return sorted(usuarios)

def enviar_mensagem(usuario_atual: str):
    usuarios = listar_usuarios()
    outros = [u for u in usuarios if u != usuario_atual]

    if not outros:
        print("Crie outros usuários primeiro.")
        return

    print("\nEnviar para:")
    for i, u in enumerate(outros, 1):
        print(f"  {i}. {u}")

    try:
        idx = int(input("\nDestinatário: ").strip()) - 1
        if not (0 <= idx < len(outros)):
            print("Escolha inválida.")
            return
        destinatario = outros[idx]
        mensagem = input(f"Mensagem para {destinatario}: ").strip()
        if not mensagem:
            print("Mensagem vazia.")
            return

        chave_publica_path = f"keys/{destinatario}/publica.pem"
        chave_publica = RSAManager.carregar_chave_publica(chave_publica_path)

        mgr = IDEAManager()
        
        packet, cek_b64 = mgr.cifrar_para_chat(
            mensagem, usuario_atual, destinatario, chave_publica
        )

        crypto_logger.log_envio_mensagem(
            remetente=usuario_atual,
            destinatario=destinatario,
            mensagem_original=mensagem,
            chave_sessao_hex=mgr.get_chave_sessao_hex() or "",
            chave_sessao_criptografada=cek_b64,
            mensagem_criptografada=packet,
            chave_publica_destinatario=chave_publica,
        )

        print("\n==== Copie e envie ao destinatário ====")
        print(f"Mensagem criptografada : {packet}")
        print(f"Chave de sessão Criptografada (RSA b64): {cek_b64}")
        print("=======================================")

    except ValueError:
        print("Entrada inválida.")
    except Exception as e:
        crypto_logger.log_erro("ENVIO_MENSAGEM", str(e))
        print(f"Erro: {e}")

def receber_mensagem(usuario_atual: str):
    try:
        packet = input("Mensagem criptografada: ").strip()
        cek_b64 = input("Chave de sessão criptografada (RSA b64): ").strip()
        if not packet or not cek_b64:
            print("Valores obrigatórios não informados.")
            return

        chave_privada_path = f"keys/{usuario_atual}/privada.pem"
        chave_privada = RSAManager.carregar_chave_privada(chave_privada_path)

        mgr = IDEAManager()
        
        texto = mgr.decifrar_do_chat(
            packet, cek_b64, usuario_atual, chave_privada
        )

        crypto_logger.log_recebimento_mensagem(
            destinatario=usuario_atual,
            remetente="Desconhecido",
            mensagem_criptografada=packet,
            chave_sessao_criptografada=cek_b64,
            chave_sessao_decifrada=mgr.get_chave_sessao_hex() or "",
            mensagem_decifrada=texto,
            chave_privada_destinatario=chave_privada,
        )

        print("\n==== Mensagem recebida ====")
        print(f"Texto: {texto}")
        print("===========================")

    except Exception as e:
        crypto_logger.log_erro("RECEBIMENTO_MENSAGEM", str(e))
        print(f"Erro: {e}")
def ver_historico_individual(usuario_atual: str):
    """Ver histórico de conversas individuais - VERSÃO AUTOMÁTICA COM VERIFICAÇÃO DE ACESSO"""
    usuarios = listar_usuarios()
    outros = [u for u in usuarios if u != usuario_atual]

    if not outros:
        print("Crie outros usuários primeiro.")
        return

    print("\nVer histórico com:")
    for i, u in enumerate(outros, 1):
        print(f"  {i}. {u}")

    try:
        idx = int(input("\nEscolha: ").strip()) - 1
        if not (0 <= idx < len(outros)):
            print("Escolha inválida.")
            return
        outro_usuario = outros[idx]
        
        mgr = IDEAManager()
        historico = mgr.ver_historico_individual(usuario_atual, outro_usuario)
        
        if not historico:
            print(f"\nNenhuma mensagem trocada com {outro_usuario}.")
        else:
            print(f"\n=== Histórico com {outro_usuario} ({len(historico)} mensagens) ===")
            
            # Carregar chave privada do usuário atual uma única vez
            chave_privada_path = f"keys/{usuario_atual}/privada.pem"
            chave_privada = RSAManager.carregar_chave_privada(chave_privada_path)
            
            for i, msg in enumerate(historico, 1):
                print(f"\n--- Mensagem {i} ---")
                print(f"De: {msg['remetente']} -> Para: {msg['destinatario']}")
                print(f"Data: {msg['timestamp']}")
                print(f"Tipo: {msg['tipo'].upper()}")
                
                # VERIFICAÇÃO AUTOMÁTICA DE ACESSO
                pode_decifrar = False
                texto_decifrado = None
                
                # Verificar se o usuário atual tem acesso a esta mensagem
                if (msg['destinatario'] == usuario_atual or msg['remetente'] == usuario_atual):
                    if 'chave_rsa_criptografada' in msg:
                        try:
                            # Tentar descriptografar automaticamente
                            texto_decifrado = mgr.decifrar_do_historico(msg, chave_privada, usuario_atual)
                            pode_decifrar = True
                            print("✅ ACESSO PERMITIDO - Mensagem decifrada com sucesso!")
                            print(f"📝 Mensagem: {texto_decifrado}")
                        except Exception as e:
                            print(f"❌ ACESSO NEGADO - Não foi possível decifrar: {e}")
                    else:
                        print("⚠️  Mensagem antiga - sem chave RSA disponível")
                else:
                    print("❌ ACESSO NEGADO - Esta mensagem não é para você")
                
                # Mostrar detalhes técnicos
                print(f"Chave IDEA: {msg['chave_sessao_utilizada']}")
                if 'chave_rsa_criptografada' in msg:
                    print(f"Chave RSA: {msg['chave_rsa_criptografada'][:50]}...")
                print(f"Mensagem Criptografada: {msg['mensagem_criptografada'][:60]}...")
                print("-" * 50)
            
            print("=" * 50)
            
    except Exception as e:
        crypto_logger.log_erro("HISTORICO_INDIVIDUAL", str(e))
        print(f"Erro: {e}")

def menu_grupos(usuario_atual: str):
    gm = GroupManager()

    while True:
        print("\n=== Grupos ===")
        print("1. Criar grupo (admin)")
        print("2. Adicionar membro (admin)")
        print("3. Remover membro / Sair do grupo")
        print("4. Listar meus grupos")
        print("5. Enviar mensagem ao grupo")
        print("6. Receber mensagem do grupo")
        print("7. Ver histórico do grupo")
        print("0. Voltar")
        op = input("Opção: ").strip()

        try:
            if op == "1":
                nome = input("Nome do grupo: ").strip()
                if not nome:
                    print("Nome inválido.")
                    continue
                chave_grupo = gm.criar_grupo(nome, admin=usuario_atual)
                print(f"Grupo '{nome}' criado. Você é o admin.")
                print(f"Chave do grupo: {chave_grupo}")

            elif op == "2":
                nome = input("Nome do grupo: ").strip()
                novo = input("Novo membro (username): ").strip()
                chave_hex, chaves_cripto = gm.adicionar_membro(nome, admin=usuario_atual, novo_membro=novo)
                print(f"Membro '{novo}' adicionado. Nova chave do grupo: {chave_hex}")
                print(f"Chaves RSA geradas para {len(chaves_cripto)} membros")
                print(f"Nova chave foi criptografada via RSA para TODOS os membros (antigos + novo)")

            elif op == "3":
                nome = input("Nome do grupo: ").strip()
                membro_remover = input("Membro a remover (deixe vazio para sair): ").strip()
                
                if not membro_remover:
                    membro_remover = usuario_atual
                    admin_remocao = usuario_atual
                else:
                    admin_remocao = usuario_atual
                
                chave_restante, chaves_cripto = gm.remover_membro(
                    nome_grupo=nome, 
                    usuario=membro_remover, 
                    admin_remocao=admin_remocao
                )
                
                if chave_restante is None:
                    print("Grupo removido (último membro saiu).")
                else:
                    if chave_restante:
                        print(f"Remoção concluída. Nova chave gerada: {chave_restante}")
                        print(f"Chaves RSA redistribuídas para {len(chaves_cripto)} membros")
                        print(f"Chave antiga é invalidada e Nova chave é criptografada via RSA para MEMBROS RESTANTES")
                    else:
                        print("Remoção concluída.")

            elif op == "4":
                grupos = gm.listar_grupos_usuario(usuario_atual)
                if not grupos:
                    print("Você não participa de nenhum grupo.")
                else:
                    print("\nSeus grupos:")
                    for g in grupos:
                        print(f"- {g['nome']} (admin: {g['admin']}) membros: {', '.join(g['membros'])}")

            elif op == "5":
                nome = input("Nome do grupo: ").strip()
                msg = input("Mensagem: ").strip()
                if not msg:
                    print("Mensagem vazia.")
                    continue
                mensagem_cifrada, chaves_cifradas = gm.cifrar_mensagem_grupo(
                    nome_grupo=nome, mensagem=msg, remetente=usuario_atual
                )
                print("\n==== Conteúdo para enviar aos membros ====")
                print(f"Mensagem (IDEA-CBC): {mensagem_cifrada}")
                print("Cada membro usa sua própria chave RSA b64 apropriada (gerada pelo servidor/gestão).")
                print(f"Resumo: {len(chaves_cifradas)} chaves RSA geradas para membros.")
                print("==========================================")

            elif op == "6":
                nome = input("Nome do grupo: ").strip()
                msg_cifrada = input("Mensagem criptografada (IDEA-CBC): ").strip()
                texto = gm.decifrar_mensagem_grupo(
                    nome_grupo=nome,
                    mensagem_cifrada=msg_cifrada,
                    destinatario=usuario_atual,
                    chave_privada_pem=None 
                )
                print("\n==== Mensagem de grupo ====")
                print(f"Texto: {texto}")
                print("===========================")

            elif op == "7":
                nome = input("Nome do grupo: ").strip()
                historico = gm.ver_historico_grupo(nome, usuario_atual)
                if not historico:
                    print("Nenhuma mensagem no histórico.")
                else:
                    print(f"\n=== Histórico do Grupo '{nome}' ({len(historico)} mensagens) ===")
                for i, msg in enumerate(historico, 1):
                    print(f"\n--- Mensagem {i} ---")
                    print(f"De: {msg['remetente']}")
                    print(f"Data: {msg['timestamp']}")
                    print(f"Chave IDEA usada: {msg['chave_utilizada']}")
                    
                    # Verificação automática de acesso
                    if msg.get('acesso_permitido', False):
                        print(" ACESSO PERMITIDO - Mensagem decifrada com sucesso!")
                        print(f"Mensagem: {msg['mensagem_decifrada']}")
                    else:
                        print("❌ ACESSO NEGADO - Não foi possível decifrar")
                        if 'erro' in msg:
                            print(f"   Erro: {msg['erro']}")
                    
                    print(f"Mensagem criptografada: {msg['mensagem_cripto'][:80]}...")
                print("=" * 50)


            elif op == "0":
                return
            else:
                print("Opção inválida.")
        except Exception as e:
            crypto_logger.log_erro("MENU_GRUPOS", str(e))
            print(f"Erro: {e}")

def main():
    print("CHAT SEGURO")
    print("=" * 20)

    usuarios_padrao = ["Fernando", "Ana", "Juliana", "Marcelo"]
    for u in usuarios_padrao:
        if criar_usuario(u):
            print(f"  {u}")

    usuario_atual = None

    while True:
        if usuario_atual is None:
            print("\nSELECIONAR USUÁRIO")
            usuarios = listar_usuarios()
            if not usuarios:
                print("Nenhum usuário encontrado.")
                return

            print("\nUsuários disponíveis:")
            for i, u in enumerate(usuarios, 1):
                print(f"  {i}. {u}")
            print("  +. Criar novo usuário")

            escolha = input("\nEscolha: ").strip()
            if escolha == "+":
                novo = input("Nome do novo usuário: ").strip()
                if novo:
                    criar_usuario(novo)
                    print(f"Usuário {novo} criado!")
                continue

            try:
                idx = int(escolha) - 1
                if 0 <= idx < len(usuarios):
                    usuario_atual = usuarios[idx]
                    print(f"Usuário atual: {usuario_atual}")
                    crypto_logger.log_usuario_selecionado(usuario_atual)
                else:
                    print("Escolha inválida.")
            except ValueError:
                print("Digite um número ou '+'.")
            continue

        print(f"\nUsuário: {usuario_atual}")
        print("1. Enviar mensagem (1:1)")
        print("2. Receber mensagem (1:1)")
        print("3. Ver histórico individual (1:1)")
        print("4. Gerenciar grupos")
        print("5. Trocar usuário")
        print("6. Criar novo usuário")
        print("0. Sair")

        op = input("\nOpção: ").strip()

        if op == "1":
            enviar_mensagem(usuario_atual)
        elif op == "2":
            receber_mensagem(usuario_atual)
        elif op == "3":
            ver_historico_individual(usuario_atual)
        elif op == "4":
            menu_grupos(usuario_atual)
        elif op == "5":
            crypto_logger.log_troca_usuario(usuario_atual)
            usuario_atual = None
            print("Trocando usuário...")
        elif op == "6":
            novo = input("Novo usuário: ").strip()
            if novo:
                criar_usuario(novo)
                print(f"Usuário {novo} criado!")
        elif op == "0":
            crypto_logger.log_saida_sistema(usuario_atual)
            print("Até logo!")
            break
        else:
            print("Opção inválida.")
            crypto_logger.log_erro("OPCAO_INVALIDA", f"Opção selecionada: {op}")

if __name__ == "__main__":
    main()