"""
main.py
--------

Interface principal do sistema de comunicação segura CipherTalk.
Apenas importa e executa funções já existentes dos módulos de banco e criptografia.
"""

import os
import sys

# 🔧 Ajusta caminho para o backend
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))
sys.path.insert(0, PROJECT_ROOT)

from backend.database.connection import SessionLocal
from backend.database.run_inserts import criar_usuario
from backend.database.run_queries import listar_usuarios, enviar_mensagem_segura, receber_mensagens_seguras

# Sessão de banco
db = SessionLocal()


def main():
    print("\n💬 CHAT SEGURO — IDEA + RSA + SQLITE")
    print("=" * 45)

    while True:
        print("\n1️⃣  - Criar novo usuário")
        print("2️⃣  - Selecionar usuário")
        print("3️⃣  - Sair")

        opcao = input("\nEscolha: ").strip()

        if opcao == "1":
            criar_usuario()
        elif opcao == "2":
            usuarios = [u.username for u in db.query(listar_usuarios.__globals__["User"]).all()]
            if not usuarios:
                print("⚠️ Nenhum usuário cadastrado.")
                continue

            for i, nome in enumerate(usuarios, 1):
                print(f"{i}. {nome}")
            try:
                idx = int(input("\nEscolha o usuário: ")) - 1
                if idx < 0 or idx >= len(usuarios):
                    print("❌ Escolha inválida.")
                    continue

                usuario = usuarios[idx]
                print(f"🔐 Usuário ativo: {usuario}")

                while True:
                    print(f"\nUsuário: {usuario}")
                    print("1️⃣  - Enviar mensagem")
                    print("2️⃣  - Receber mensagens")
                    print("3️⃣  - Trocar usuário")
                    print("4️⃣  - Sair")

                    sub = input("\nEscolha: ").strip()
                    if sub == "1":
                        enviar_mensagem_segura(db, usuario)
                    elif sub == "2":
                        receber_mensagens_seguras(db, usuario)
                    elif sub == "3":
                        break
                    elif sub == "4":
                        db.close()
                        print("👋 Encerrando sistema.")
                        return
                    else:
                        print("❌ Opção inválida.")
            except ValueError:
                print("❌ Entrada inválida.")
        elif opcao == "3":
            print("👋 Até logo!")
            break
        else:
            print("❌ Opção inválida.")


if __name__ == "__main__":
    main()
