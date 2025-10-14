from backend.crypto.idea_manager import IDEAManager
from backend.crypto.rsa_manager import RSAManager
import os

def criar_usuario(nome):
    pasta = f"keys/{nome}"
    if not os.path.exists(pasta):
        os.makedirs(pasta)
    
    privada_path = f"{pasta}/privada.pem"
    publica_path = f"{pasta}/publica.pem"
    
    if not os.path.exists(privada_path):
        print(f"Gerando chaves para {nome}...")
        privada_pem, publica_pem = RSAManager.gerar_par_chaves()
        with open(privada_path, 'w') as f:
            f.write(privada_pem)
        with open(publica_path, 'w') as f:
            f.write(publica_pem)
        return True
    return False

def listar_usuarios():
    if not os.path.exists("keys"):
        return []
    
    usuarios = []
    for item in os.listdir("keys"):
        if os.path.isdir(f"keys/{item}") and os.path.exists(f"keys/{item}/publica.pem"):
            usuarios.append(item)
    return usuarios

def main():
    print("CHAT SEGURO")
    print("=" * 20)
    
    usuarios_padrao = ["Fernando", "Ana", "Juliana", "Marcelo"]
    print("Criando usuarios...")
    for usuario in usuarios_padrao:
        if criar_usuario(usuario):
            print(f"  {usuario}")
    
    usuario_atual = None
    
    while True:
        if usuario_atual is None:
            print("\nSELECIONAR USUARIO")
            usuarios = listar_usuarios()
            
            if not usuarios:
                print("Nenhum usuario encontrado")
                return
                
            print("\nUsuarios disponiveis:")
            for i, usuario in enumerate(usuarios, 1):
                print(f"  {i}. {usuario}")
            print("  +. Criar novo usuario")
            
            escolha = input("\nEscolha: ").strip()
            
            if escolha == '+':
                novo_nome = input("Nome do novo usuario: ").strip()
                if novo_nome:
                    criar_usuario(novo_nome)
                    print(f"Usuario {novo_nome} criado!")
                continue
                
            try:
                idx = int(escolha) - 1
                if 0 <= idx < len(usuarios):
                    usuario_atual = usuarios[idx]
                    print(f"Usuario: {usuario_atual}")
                else:
                    print("Escolha invalida")
            except ValueError:
                print("Digite um numero ou '+'")
            continue
        
        print(f"\nUsuario: {usuario_atual}")
        print("1. Enviar mensagem")
        print("2. Receber mensagem") 
        print("3. Trocar usuario")
        print("4. Criar novo usuario")
        print("5. Sair")
        
        op = input("\nOpcao: ").strip()
        
        if op == "1":
            usuarios = listar_usuarios()
            outros_usuarios = [u for u in usuarios if u != usuario_atual]
            
            if not outros_usuarios:
                print("Crie outros usuarios primeiro")
                continue
                
            print("\nEnviar para:")
            for i, usuario in enumerate(outros_usuarios, 1):
                print(f"  {i}. {usuario}")
            
            try:
                escolha = int(input("\nDestinatario: ")) - 1
                if 0 <= escolha < len(outros_usuarios):
                    destinatario = outros_usuarios[escolha]
                    mensagem = input(f"Mensagem para {destinatario}: ").strip()
                    
                    if mensagem:
                        chave_publica = RSAManager.carregar_chave_publica(f"keys/{destinatario}/publica.pem")
                        mgr = IDEAManager()
                        mensagem_cripto, chave_sessao_cripto = mgr.cifrar_para_chat(mensagem, chave_publica)
                        
                        print(f"\nPara {destinatario}:")
                        print(f"Mensagem criptografada: {mensagem_cripto}")
                        print(f"Chave de sessao criptografada: {chave_sessao_cripto}")
                    else:
                        print("Mensagem vazia")
                else:
                    print("Escolha invalida")
                    
            except ValueError:
                print("Numero invalido")
            except Exception as e:
                print(f"Erro: {e}")
        
        elif op == "2":
            mensagem_cripto = input("Mensagem criptografada: ").strip()
            chave_sessao_cripto = input("Chave de sessao criptografada: ").strip()
            
            try:
                chave_privada = RSAManager.carregar_chave_privada(f"keys/{usuario_atual}/privada.pem")
                mgr = IDEAManager()
                texto = mgr.decifrar_do_chat(mensagem_cripto, chave_sessao_cripto, chave_privada)
                print(f"\nMensagem: {texto}")
                
            except Exception as e:
                print(f"Erro: {e}")
        
        elif op == "3":
            usuario_atual = None
        
        elif op == "4":
            novo_nome = input("Novo usuario: ").strip()
            if novo_nome:
                criar_usuario(novo_nome)
                print(f"Usuario {novo_nome} criado!")
        
        elif op == "5":
            print("Ate logo!")
            break
        
        else:
            print("Opcao invalida")

if __name__ == "__main__":
    main()