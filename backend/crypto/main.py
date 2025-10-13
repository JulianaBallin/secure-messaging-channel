from .idea_manager import IDEAManager


def banner():
    print("=" * 70)
    print("           SISTEMA IDEA - CHAVE DE SESSÃO AUTOMÁTICA")
    print("=" * 70)
    print("Gera chave IDEA aleatória para cada cifração 🔐")
    print("Modo CBC + Padding PKCS7")
    print("=" * 70)

def main():
    banner()
    mgr = IDEAManager()

    op = input("\n[C]ifrar ou [D]ecifrar? (c/d)\t").strip().lower()

    if op == "c":
        texto = input("Digite o texto plano (ASCII):\t\t")
        
        try:
            pacote_cifrado, chave_sessao = mgr.cifrar_texto(texto)
            
            print("\n" + "=" * 70)
            print("TEXTO CIFRADO COM SUCESSO!")
            print("=" * 70)
            print("PACOTE COMPLETO (guarde tudo):")
            print(f"Mensagem cifrada: {pacote_cifrado}")
            print(f"Chave de sessão: {chave_sessao}")
            
            print("\nINSTRUÇÕES PARA DECIFRAR:")
            print("1. Mensagem cifrada: copie TODA a string acima de 'Mensagem cifrada'")
            print("2. Chave de sessão: copie a string hexadecimal acima de 'Chave de sessão'") 
            print("3. Use ambas no modo decifrar")
            print("=" * 70)
            
        except Exception as e:
            print(f"Erro na cifração: {e}")

    elif op == "d":
        pacote_cifrado = input("Cole a mensagem cifrada:\t").strip()
        chave_sessao = input("Cole a chave de sessão:\t").strip()
        
        try:
            texto_original = mgr.decifrar_texto_com_chave(pacote_cifrado, chave_sessao)
            
            print("\n" + "=" * 70)
            print("MENSAGEM DECIFRADA COM SUCESSO!")
            print("=" * 70)
            print(f"📝 Texto original: {texto_original}")
            print("=" * 70)
            
        except Exception as e:
            print(f"Erro na decifração: {e}")
            print("\n Verificar se:")
            print("   - A mensagem cifrada está completa (formato: hex:hex)")
            print("   - A chave de sessão está correta (32 caracteres hex)")
            print("   - Ambos foram copiados integralmente")

    else:
        print("Opção inválida! Use 'c' para cifrar ou 'd' para decifrar.")

if __name__ == "__main__":
    main()