import asyncio
import json
import datetime
import base64
import os
from typing import Dict
from sqlalchemy.orm import Session

from backend.auth.models import User, Message, Group, GroupMember
from backend.auth.auth_jwt import create_access_token, verify_access_token
from backend.utils.logger_config import server_logger as log, individual_chat_logger, group_chat_logger
from backend.auth.security import hash_senha as hash_password, verificar_senha as verify_password
from backend.crypto.rsa_manager import RSAManager
from backend.crypto.idea_manager import IDEAManager
from backend.utils.log_formatter import format_box
from backend.database.connection import SessionLocal

# ======================================================
# LOCK GLOBAL DE USUÁRIOS
# ======================================================
USERS_LOCK = asyncio.Lock()

# CADASTRO
async def handle_register(db: Session, writer, creds: dict) -> None:
    username = creds.get("username")
    password = creds.get("password")

    if not username or not password:
        writer.write("❌ Dados incompletos.\n".encode())
        await writer.drain()
        log.warning(f"[REGISTER_FAIL] Campos ausentes para cadastro de {username}")
        return

    async with USERS_LOCK:
        if db.query(User).filter(User.username == username).first():
            writer.write("❌ Usuário já existe.\n".encode())
            await writer.drain()
            log.warning(f"[REGISTER_DUPLICATE] Tentativa duplicada de {username}")
            return

        private_key_pem, public_key_pem = RSAManager.gerar_par_chaves()
        hashed_password = hash_password(password)

        # 🔑 Salvar chaves em backend/keys/{username}/
        # handlers.py está em backend/server/, então sobe 2 níveis para chegar em backend/
        BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        user_keys_dir = os.path.join(BACKEND_DIR, "keys", username)
        os.makedirs(user_keys_dir, exist_ok=True)
        
        private_key_path = os.path.join(user_keys_dir, f"{username}_private.pem")
        public_key_path = os.path.join(user_keys_dir, f"{username}_public.pem")
        
        log.info(f"[KEY_SAVE] Tentando salvar chaves de {username} em: {user_keys_dir}")
        
        try:
            # Salvar chave privada
            with open(private_key_path, "w", encoding="utf-8") as key_file:
                key_file.write(private_key_pem)
            log.info(f"[KEY_SAVED] ✅ Chave privada de {username} salva em: {private_key_path}")
            
            # Salvar chave pública
            with open(public_key_path, "w", encoding="utf-8") as key_file:
                key_file.write(public_key_pem)
            log.info(f"[KEY_SAVED] ✅ Chave pública de {username} salva em: {public_key_path}")
            
        except Exception as e:
            log.error(f"[KEY_SAVE_ERROR] ❌ Erro ao salvar chaves de {username}: {e}")
        
        try:
            os.chmod(private_key_path, 0o600)  
            os.chmod(public_key_path, 0o644)
        except Exception:
            pass  # No Windows pode não funcionar, mas não é crítico  

        new_user = User(
            username=username,
            password_hash=hashed_password,
            public_key=public_key_pem.encode(),
        )
        db.add(new_user)
        db.commit()

    writer.write(
        json.dumps(
            {
                "status": "success",
                "message": f"Usuário '{username}' criado com sucesso.",
                "private_key": private_key_pem,
            }
        ).encode()
        + b"\n"
    )
    await writer.drain()
    log.info(f"[REGISTER_OK] Novo usuário registrado: {username}")


async def handle_login(db: Session, writer, creds: dict, online_users: Dict[str, asyncio.StreamWriter]):
    username = creds.get("username")
    password = creds.get("password")

    if not username or not password:
        writer.write("❌ Credenciais incompletas.\n".encode())
        await writer.drain()
        return None, None

    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        writer.write("AUTH_FAILED\n".encode())
        await writer.drain()
        return None, None

    token = create_access_token(username)
    async with USERS_LOCK:
        online_users[username] = writer

    writer.write((json.dumps({"token": token}) + "\n").encode())
    await writer.drain()
    log.info(f"[LOGIN_OK] {username} autenticado e online.")

    return username, token

async def handle_resume_session(db: Session, writer, message: dict, online_users: Dict[str, asyncio.StreamWriter]):
    """Reanexa o socket TLS do usuário logado ao dicionário online_users."""
    try:
        token = message.get("token")
        username = verify_access_token(token)
        if not username:
            writer.write((json.dumps({"status": "error", "reason": "invalid_token"}) + "\n").encode())
            await writer.drain()
            return

        async with USERS_LOCK:
            online_users[username] = writer

        writer.write((json.dumps({"status": "ok", "action": "resume_session_ack", "user": username}) + "\n").encode())
        await writer.drain()
        log.info(f"[RESUME_OK] {username} reanexado a online_users via TLS.")
    except Exception as e:
        log.error(f"[RESUME_FAIL] {e}")
        try:
            writer.write((json.dumps({"status": "error", "reason": "exception"}) + "\n").encode())
            await writer.drain()
        except Exception:
            pass

# ======================================================
# LIST USERS
# ======================================================
async def handle_list_users(db: Session, writer, message: dict, online_users: Dict[str, asyncio.StreamWriter]):
    try:
        token = message.get("token")
        requester = verify_access_token(token)
        users = db.query(User).all()

        users_info = [
            {
                "username": u.username,
                "online": u.username in online_users,
                "public_key": u.public_key.decode() if u.public_key else None,
            }
            for u in users
        ]
        writer.write((json.dumps({"users": users_info}) + "\n").encode())
        await writer.drain()
        log.info(f"[LIST_OK] {requester} requisitou a lista de usuários ({len(users)} registros).")
    except Exception as e:
        log.error(f"[LIST_FAIL] Erro ao listar usuários: {e}")
        writer.write("❌ Falha ao obter lista de usuários.\n".encode())
        await writer.drain()


async def handle_send_message(db: Session, message: dict, online_users: Dict[str, asyncio.StreamWriter]):
    try:
        token = message.get("token")
        sender = verify_access_token(token)
        receiver = message.get("to")
        encrypted_content = message.get("content_encrypted")
        encrypted_key = message.get("key_encrypted")
        signature_b64 = message.get("signature")
        content_hash = message.get("content_hash")

        if not all([sender, receiver, encrypted_content, encrypted_key]):
            log.warning(f"[SEND_FAIL] Campos ausentes em mensagem de {sender}")
            return

        sender_user = db.query(User).filter(User.username == sender).first()
        receiver_user = db.query(User).filter(User.username == receiver).first()
        if not receiver_user:
            log.error(f"[SEND_FAIL] Destinatário {receiver} não encontrado.")
            return

        if content_hash:
            existing = (
                db.query(Message)
                .filter(
                    Message.sender_id == sender_user.id,
                    Message.receiver_id == receiver_user.id,
                    Message.content_hash == content_hash
                )
                .first()
            )
            if not existing:
                msg = Message(
                    sender_id=sender_user.id,
                    receiver_id=receiver_user.id,
                    content_encrypted=encrypted_content,
                    key_encrypted=encrypted_key,
                    content_hash=content_hash,
                    signature=(base64.b64decode(signature_b64) if signature_b64 else None),
                )
                db.add(msg)
                db.commit()
        else:
            msg = Message(
                sender_id=sender_user.id,
                receiver_id=receiver_user.id,
                content_encrypted=encrypted_content,
                key_encrypted=encrypted_key,
                content_hash=content_hash,
                signature=(base64.b64decode(signature_b64) if signature_b64 else None),
            )
            db.add(msg)
            db.commit()

        payload = {
            "from": sender,
            "to": receiver,
            "content_encrypted": encrypted_content,
            "key_encrypted": encrypted_key,
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }
        if signature_b64:
            payload["signature"] = signature_b64
        if content_hash:
            payload["content_hash"] = content_hash

        sender_id = sender_user.id
        receiver_id = receiver_user.id
        
        async with USERS_LOCK:
            dest_writer = online_users.get(receiver)
            online_list = list(online_users.keys())

        if dest_writer:
            async def _deliver(w: asyncio.StreamWriter):
                db_bg = SessionLocal()
                try:
                    w.write((json.dumps(payload) + "\n").encode())
                    await w.drain()
                    log.info(f"[DELIVERED] {sender} → {receiver}")
                    
                    try:
                        # 🔑 Ler chave privada de backend/keys/{username}/
                        BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                        user_keys_dir = os.path.join(BACKEND_DIR, "keys", receiver)
                        priv_path = os.path.join(user_keys_dir, f"{receiver}_private.pem")
                        try:
                            with open(priv_path, "r") as f:
                                private_key_pem = f.read()
                            
                            idea = IDEAManager()
                            step_counter = [1]
                            
                            content_plain = idea.decifrar_do_chat(
                                packet=encrypted_content,
                                cek_b64=encrypted_key,
                                destinatario=receiver,
                                chave_privada_pem=private_key_pem,
                                is_group=False,
                                log_enabled=True,
                                step_counter=step_counter,
                                sender=sender,
                            ) or ""
                            
                            individual_chat_logger.info(
                                format_box(
                                    title=f"✅ RECEBIMENTO CONCLUÍDO: {receiver} recebeu mensagem de {sender}",
                                    content=[f"💬 Mensagem: '{content_plain}'"],
                                    width=70,
                                    char="=",
                                )
                            )
                            individual_chat_logger.info("\n")
                            
                            # Marca mensagem como lida (usa nova sessão)
                            if content_hash:
                                msg_read = (
                                    db_bg.query(Message)
                                    .filter(
                                        Message.sender_id == sender_id,
                                        Message.receiver_id == receiver_id,
                                        Message.content_hash == content_hash
                                    )
                                    .first()
                                )
                                if msg_read:
                                    msg_read.is_read = True
                                    db_bg.commit()
                        except FileNotFoundError:
                            log.warning(f"[RECEIVE_LOG_ERR] Chave privada não encontrada para {receiver}")
                        except Exception as e:
                            log.warning(f"[RECEIVE_LOG_ERR] Erro ao gerar logs de recebimento: {e}")
                    except Exception as e:
                        log.warning(f"[RECEIVE_LOG_ERR] Erro ao processar logs de recebimento: {e}")
                except (BrokenPipeError, ConnectionResetError, OSError) as e:
                    log.warning(f"[CONNECTION_ERROR] {receiver}: {e}")
                    async with USERS_LOCK:
                        online_users.pop(receiver, None)
                except Exception as e:
                    log.error(f"[SEND_ERROR] {receiver}: {e}")
                    async with USERS_LOCK:
                        online_users.pop(receiver, None)
                finally:
                    db_bg.close()

            asyncio.create_task(_deliver(dest_writer))
        else:
            log.info(f"[STORED_ONLY] {receiver} offline. Mensagem armazenada. Online: {', '.join(online_list) if online_list else 'nenhum'}")

    except Exception as e:
        log.error(f"[SEND_ERROR] Falha ao enviar mensagem privada: {e}")


async def handle_send_group_message(db: Session, message: dict, online_users: Dict[str, asyncio.StreamWriter]):
    try:
        token = message.get("token")
        sender = verify_access_token(token)
        group_name = message.get("group")
        encrypted_content = message.get("content_encrypted")
        keys_map = message.get("keys_encrypted", {})

        group = db.query(Group).filter(Group.name == group_name).first()
        if not group:
            log.error(f"[GROUP_SEND_FAIL] Grupo '{group_name}' não encontrado.")
            return

        members = (
            db.query(User.username)
            .join(GroupMember, GroupMember.user_id == User.id)
            .filter(GroupMember.group_id == group.id)
            .all()
        )

        sender_user = db.query(User).filter(User.username == sender).first()
        sender_id = sender_user.id
        group_id = group.id
        
        for (username,) in members:
            if username == sender:
                continue

            # Captura dados do membro antes de passar para função assíncrona
            receiver_user = db.query(User).filter(User.username == username).first()
            if not receiver_user:
                continue
            receiver_id = receiver_user.id
            encrypted_key_user = keys_map.get(username)

            payload = {
                "from": sender,
                "group": group_name,
                "content_encrypted": encrypted_content,
                "key_encrypted": encrypted_key_user,
                "timestamp": datetime.datetime.utcnow().isoformat(),
            }

            async with USERS_LOCK:
                dest_writer = online_users.get(username)

            if dest_writer:
                async def _deliver_group(w: asyncio.StreamWriter, pl: dict, user: str, user_id: int, key_enc: str, sender_name: str, g_name: str, enc_content: str):
                    db_bg = SessionLocal()
                    try:
                        # Envia mensagem via TLS
                        w.write((json.dumps(pl) + "\n").encode())
                        await w.drain()
                        log.info(f"[GROUP_DELIVERED] {sender_name} → {user} ({g_name})")
                        
                        #  logs de recebimento detalhados (tempo real)
                        try:
                            # 🔑 Ler chave privada de backend/keys/{username}/
                            BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                            user_keys_dir = os.path.join(BACKEND_DIR, "keys", user)
                            priv_path = os.path.join(user_keys_dir, f"{user}_private.pem")
                            try:
                                with open(priv_path, "r") as f:
                                    private_key_pem = f.read()
                                
                                idea = IDEAManager()
                                step_counter = [1]
                                
                                # Gera logs de recebimento detalhados
                                content_plain = idea.decifrar_do_chat(
                                    packet=enc_content,
                                    cek_b64=key_enc,
                                    destinatario=user,
                                    chave_privada_pem=private_key_pem,
                                    is_group=True,
                                    log_enabled=True,
                                    step_counter=step_counter,
                                    sender=sender_name,
                                    group_name=g_name,
                                ) or ""
                                
                                group_chat_logger.info(
                                    format_box(
                                        title=f"✅ RECEBIMENTO CONCLUÍDO: {user} recebeu mensagem de {sender_name} (Grupo: {g_name})",
                                        content=[f"💬 Mensagem: '{content_plain}'"],
                                        width=70,
                                        char="=",
                                    )
                                )
                                group_chat_logger.info("\n")
                                
                            except FileNotFoundError:
                                log.warning(f"[GROUP_RECEIVE_LOG_ERR] Chave privada não encontrada para {user}")
                            except Exception as e:
                                log.warning(f"[GROUP_RECEIVE_LOG_ERR] Erro ao gerar logs de recebimento: {e}")
                        except Exception as e:
                            log.warning(f"[GROUP_RECEIVE_LOG_ERR] Erro ao processar logs de recebimento: {e}")
                    except Exception as e:
                        log.warning(f"[GROUP_DELIVER_ERR] {user}: {e}")
                        async with USERS_LOCK:
                            online_users.pop(user, None)
                    finally:
                        db_bg.close()

                asyncio.create_task(_deliver_group(dest_writer, payload, username, receiver_id, encrypted_key_user, sender, group_name, encrypted_content))
            else:
                # Usuário offline - salva mensagem no banco
                msg = Message(
                    sender_id=sender_user.id,
                    receiver_id=receiver_id,
                    group_id=group.id,
                    content_encrypted=encrypted_content,
                    key_encrypted=encrypted_key_user,
                )
                db.add(msg)
                db.commit()
                log.info(f"[GROUP_STORE] {username} offline. Mensagem salva (grupo {group_name}).")

        log.info(f"[GROUP_SEND_OK] {sender} enviou mensagem ao grupo {group_name}")

    except Exception as e:
        log.error(f"[GROUP_SEND_ERROR] Erro ao enviar mensagem em grupo: {e}")
