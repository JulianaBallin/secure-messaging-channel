import argon2

# Argon2
ph = argon2.PasswordHasher(
    time_cost=3,           # Número de iterações
    memory_cost=65536,     # Memória em KiB (64MB)
    parallelism=4,         # Paralelismo
    hash_len=32,           # Tamanho do hash
    salt_len=16            # Tamanho do salt
)

def hash_senha(senha: str) -> str:
    try:
        return ph.hash(senha)
    except Exception as e:
        raise ValueError(f"Erro ao gerar hash: {e}")

def verificar_senha(senha: str, hash_salvo: str) -> bool:
    #Verifica se uma senha corresponde ao hash salvo
    try:
        return ph.verify(hash_salvo, senha)
    except argon2.exceptions.VerifyMismatchError:
        return False
    except argon2.exceptions.VerificationError:
        # Hash corrompido ou formato inválido
        return False
    except Exception as e:
        print(f"⚠️ Erro na verificação: {e}")
        return False

def precisa_rehash(hash_salvo: str) -> bool:
    #Verifica se o hash precisa ser atualizado (se parâmetros mudaram)
    return ph.check_needs_rehash(hash_salvo)

if __name__ == "__main__":
    print("🔐 TESTE DE HASH DE SENHAS (ARGON2ID)")
    print("=" * 50)
    
    # Teste 1: Senha normal
    senha_teste = "minha_senha_secreta_123"
    
    print(f"Senha original: {senha_teste}")
    
    # Gera hash
    hash_gerado = hash_senha(senha_teste)
    print(f"Hash gerado: {hash_gerado}")
    print(f"Tamanho do hash: {len(hash_gerado)} caracteres")
    
    senha_correta = verificar_senha("minha_senha_secreta_123", hash_gerado)
    print(f"Senha correta funciona: {senha_correta}")
    
    senha_errada = verificar_senha("senha_errada", hash_gerado)
    print(f" Senha errada rejeitada: {senha_errada}")
    
    # Verifica se precisa de rehash
    precisa = precisa_rehash(hash_gerado)
    print(f"🔁 Precisa de rehash: {precisa}")
    
    print("\n" + "=" * 50)
    
    # Teste 2: Mesma senha, hash diferente
    hash_2 = hash_senha(senha_teste)
    print(f"Hash 1: {hash_gerado[:50]}...")
    print(f"Hash 2: {hash_2[:50]}...")
    print(f"✓ Hashes são diferentes: {hash_gerado != hash_2}")
    print(f"✓ Senha ainda funciona com hash 2: {verificar_senha(senha_teste, hash_2)}")
    
    print("\n" + "=" * 50)
    
    # Teste 3: Senha com caracteres especiais
    senha_especial = "Senh@ComÇaractèresEspéciais123!"
    hash_especial = hash_senha(senha_especial)
    print(f"Senha especial: {senha_especial}")
    print(f"Hash especial funciona: {verificar_senha(senha_especial, hash_especial)}")
    
    print("\n" + "=" * 50)
    
    # Teste 4: Performance e segurança
    print("⏱️  Teste de performance (pode demorar alguns segundos):")
    import time
    
    start = time.time()
    hash_perf = hash_senha("senha_teste_performance")
    end = time.time()
    
    print(f"Tempo para gerar hash: {end - start:.2f} segundos")
    print("Argon2 é lento de propósito para dificultar ataques!")