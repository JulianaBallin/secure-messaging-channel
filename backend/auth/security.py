import argon2
from backend.utils.logger_config import autenticidade_logger
import secrets
from datetime import datetime, timedelta, timezone
from backend.database.connection import SessionLocal
from backend.auth.models import User
import smtplib
from email.mime.text import MIMEText
from sqlalchemy.orm import Session, object_session
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os


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
        hash_final = ph.hash(senha)

        autenticidade_logger.info(
            f"[ARGON2_HASH_OK] Hash gerado com sucesso.\n"
            f" • Senha original: {senha}\n"
            f" • Hash Argon2ID: {hash_final}\n"
            f" • PasswordHasher_ID: {id(ph)}"
        )

        return hash_final

    except Exception as e:
        autenticidade_logger.error(
            f"[ARGON2_HASH_ERRO] Falha ao gerar hash.\n"
            f" • Senha original: {senha}\n"
            f" • Erro: {e}"
        )
        raise ValueError(f"Erro ao gerar hash: {e}")


def verificar_senha(senha: str, hash_salvo: str) -> bool:
    try:
        resultado = ph.verify(hash_salvo, senha)

        autenticidade_logger.info(
            f"[ARGON2_VERIFY_OK] Senha verificada com sucesso.\n"
            f" • Senha recebida: {senha}\n"
            f" • Hash salvo: {hash_salvo}\n"
            f" • Resultado: {resultado}\n"
            f" • PasswordHasher_ID: {id(ph)}"
        )

        return True

    except argon2.exceptions.VerifyMismatchError:
        autenticidade_logger.info(
            f"[ARGON2_VERIFY_INVALIDA] Senha incorreta.\n"
            f" • Senha recebida: {senha}\n"
            f" • Hash salvo: {hash_salvo}"
        )
        return False

    except argon2.exceptions.VerificationError:
        autenticidade_logger.error(
            f"[ARGON2_VERIFY_CORROMPIDO] Hash corrompido ou inválido.\n"
            f" • Hash salvo: {hash_salvo}"
        )
        return False

    except Exception as e:
        autenticidade_logger.error(
            f"[ARGON2_VERIFY_ERRO] Erro inesperado ao verificar senha.\n"
            f" • Senha recebida: {senha}\n"
            f" • Hash salvo: {hash_salvo}\n"
            f" • Erro: {e}"
        )
        return False


def precisa_rehash(hash_salvo: str) -> bool:
    precisa = ph.check_needs_rehash(hash_salvo)

    autenticidade_logger.info(
        f"[ARGON2_REHASH_CHECK] Verificação de necessidade de rehash.\n"
        f" • Hash salvo: {hash_salvo}\n"
        f" • Precisa rehash? {precisa}\n"
        f" • PasswordHasher_ID: {id(ph)}"
    )

    return precisa

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
    

# 2FA - AUTENTICAÇÃO EM DOIS FATORES

# Gera código aleatório (6 dígitos)
def generate_2fa_code() -> str:
    """Gera código random de 6 dígitos."""
    code = f"{secrets.randbelow(999999):06d}"
    autenticidade_logger.info(
        f"[2FA_CODE_CREATED] Código 2FA gerado (não armazenado texto puro)."
    )
    return code


# Cria hash do código 2FA e salva no banco (usando a MESMA sessão db!)
def create_and_store_2fa(db: Session, user: User) -> str:
    """
    Gera o código 2FA, salva APENAS o hash + expiração na MESMA sessão do login.
    Retorna o código real (plaintext) para envio por e-mail.
    """

    # 🔐 1) Gera o código real (não salvo)
    code = generate_2fa_code()

    # 🔑 2) Hash seguro do código
    code_hash = ph.hash(code)

    # ⏳ 3) Expira em 5 minutos
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)

    # 📝 4) Persistir dentro da MESMA sessão db
    user.twofa_hash = code_hash
    user.twofa_expires_at = expires_at
    user.twofa_verified = False

    db.commit()

    # 🔎 Logs de autenticidade
    autenticidade_logger.info(
        f"[2FA_HASH_STORED] Hash do código 2FA armazenado. "
        f"Expiração: {expires_at.isoformat()} | User: '{user.username}'. "
        f"Código REAL **não armazenado**."
    )

    return code  # este é o código que será enviado por e-mail



# VERIFICA CÓDIGO 2FA INFORMADO
def verify_2fa_code(user: User, provided_code: str) -> bool:
    """
    Verifica se o código está correto e dentro da validade.
    """
    if not user.twofa_hash or not user.twofa_expires_at:
        autenticidade_logger.warning(
            f"[2FA_INVALID_STATE] Usuário '{user.username}' tentou validar 2FA sem haver código ativo."
        )
        return False

    # 🔧 Corrige datetime naive → timezone-aware
    expires_at = user.twofa_expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) > expires_at:
        autenticidade_logger.warning(
            f"[2FA_EXPIRED] Código 2FA expirado para usuário '{user.username}'."
        )
        return False

    try:
        ph.verify(user.twofa_hash, provided_code)
    except Exception:
        autenticidade_logger.warning(
            f"[2FA_MISMATCH] Código incorreto para usuário '{user.username}'."
        )
        return False

    # Se o código confere
    autenticidade_logger.info(
        f"[2FA_VERIFIED] Código 2FA validado com sucesso para '{user.username}'."
    )

    db = object_session(user)
    user.twofa_verified = True
    db.commit()

    return True



def send_2fa_email(to_email: str, code: str):
    """
    Envia o código 2FA via SMTP usando Mailtrap.
    Funciona no modo sandbox (não envia para inbox real, só aparece no Mailtrap).
    """

    host = os.getenv("MAIL_HOST")
    port = int(os.getenv("MAIL_PORT", 587))
    user = os.getenv("MAIL_USER")
    passwd = os.getenv("MAIL_PASS")
    mail_from = os.getenv("MAIL_FROM", "CipherTalk <no-reply@ciphertalk.test>")

    try:
        msg = MIMEMultipart()
        msg["From"] = mail_from
        msg["To"] = to_email
        msg["Subject"] = "Seu código 2FA - CipherTalk"

        body = f"""
        <h2>🔐 Autenticação em Duas Etapas</h2>
        <p>Seu código de autenticação é:</p>
        <h1 style="font-size:32px;">{code}</h1>
        <p>Ele expira em 5 minutos.</p>
        """

        msg.attach(MIMEText(body, "html"))

        with smtplib.SMTP(host, port) as server:
            server.starttls()
            server.login(user, passwd)
            server.sendmail(mail_from, to_email, msg.as_string())

        autenticidade_logger.info(f"[2FA_EMAIL_OK] Código enviado para {to_email}")

    except Exception as e:
        autenticidade_logger.error(
            f"[2FA_EMAIL_ERROR] Falha ao enviar 2FA para '{to_email}': {e}"
        )
