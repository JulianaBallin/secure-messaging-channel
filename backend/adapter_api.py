import asyncio
import os
import ssl
import json
import time
from hashlib import sha256
from typing import Dict, TypedDict, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.database.connection import SessionLocal
from backend.server.handlers_rest import handle_register_rest, handle_login_rest
from backend.auth.models import User, Message, Group, GroupMember
from backend.auth.auth_jwt import verify_access_token

# Crypto/Logs
from backend.crypto.idea_manager import IDEAManager
from backend.crypto.rsa_manager import RSAManager
from backend.utils.log_formatter import format_box, truncate_hex
from backend.utils.logger_config import (
    individual_chat_logger,
    group_chat_logger,
)

# ======================================================
# 🔐 CONFIGURAÇÃO DE REDE (TLS)
# ======================================================
TCP_HOST = "127.0.0.1"
TCP_PORT = 8888
SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE


class TLSConn(TypedDict, total=False):
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    ready: asyncio.Event  # setado quando receber resume_session_ack


TLS_CONNECTIONS: Dict[str, TLSConn] = {}
TLS_CONNECT_TASKS: Dict[str, asyncio.Task] = {}


async def ensure_tls_connection(username: str, token: str) -> TLSConn:
    """
    Abre/retoma uma conexão TLS persistente com o servidor TCP e envia resume_session.
    Aguarda o ACK através de um asyncio.Event (sem leituras duplicadas do StreamReader).
    """
    conn = TLS_CONNECTIONS.get(username)
    if conn:
        w = conn.get("writer")
        if isinstance(w, asyncio.StreamWriter) and not w.is_closing():
            return conn

    reader, writer = await asyncio.open_connection(TCP_HOST, TCP_PORT, ssl=SSL_CONTEXT)
    ready_evt = asyncio.Event()
    TLS_CONNECTIONS[username] = {"reader": reader, "writer": writer, "ready": ready_evt}
    print(f"[TLS] 🔗 Conexão TLS aberta para {username}")

    # Envia resume_session e faz drain (garante flush)
    writer.write(json.dumps({"action": "resume_session", "token": token}).encode() + b"\n")
    await writer.drain()

    async def listen():
        try:
            while not reader.at_eof():
                data = await reader.readline()
                if not data:
                    break
                line = data.decode().strip()
                print(f"[TLS][{username}] {line}")
                # Marca 'ready' ao receber ACK
                try:
                    msg = json.loads(line)
                    if msg.get("action") == "resume_session_ack" and msg.get("status") == "ok":
                        evt = TLS_CONNECTIONS.get(username, {}).get("ready")
                        if isinstance(evt, asyncio.Event):
                            evt.set()
                except Exception:
                    pass
        except Exception as e:
            print(f"[TLS_READ_ERR][{username}] {e}")
        finally:
            TLS_CONNECTIONS.pop(username, None)

    asyncio.create_task(listen())

    # Espera rápida pelo ACK via Event
    try:
        await asyncio.wait_for(ready_evt.wait(), timeout=1.0)
    except asyncio.TimeoutError:
        pass

    return TLS_CONNECTIONS[username]


def ensure_tls_connection_bg(username: str, token: str) -> None:
    """Dispara a conexão TLS em background (debounced)."""
    t = TLS_CONNECT_TASKS.get(username)
    if t and not t.done():
        return
    TLS_CONNECT_TASKS[username] = asyncio.create_task(ensure_tls_connection(username, token))


# ======================================================
# 🫀 KEEP-ALIVE (leve)
# ======================================================
async def start_keepalive():
    while True:
        await asyncio.sleep(120)
        for user, conn in list(TLS_CONNECTIONS.items()):
            writer = conn.get("writer")
            if not isinstance(writer, asyncio.StreamWriter) or writer.is_closing():
                TLS_CONNECTIONS.pop(user, None)
                continue
            try:
                writer.write(b'{"action":"ping"}\n')
                await writer.drain()
            except Exception:
                TLS_CONNECTIONS.pop(user, None)


# ======================================================
# 🚀 FASTAPI
# ======================================================
app = FastAPI(title="CipherTalk Adapter API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def _startup():
    asyncio.create_task(start_keepalive())


# ======================================================
# 📦 MODELOS
# ======================================================
class AuthRequest(BaseModel):
    username: str
    password: str


class CreateGroupReq(BaseModel):
    token: str
    name: str


class AddMemberReq(BaseModel):
    token: str
    group: str
    username: str


class RemoveMemberReq(BaseModel):
    token: str
    group: str
    username: str


# ======================================================
# 👤 REGISTRO E LOGIN
# ======================================================
@app.post("/api/register")
async def api_register(req: AuthRequest):
    db = SessionLocal()
    try:
        return await handle_register_rest(db, req.dict())
    finally:
        db.close()


@app.post("/api/login")
async def api_login(req: AuthRequest):
    db = SessionLocal()
    try:
        result, token = await handle_login_rest(db, req.dict())
        if result.get("status") == "error":
            raise HTTPException(status_code=401, detail=result.get("message"))

        # 🔌 sobe a TLS em background para já marcar como ONLINE no servidor TCP
        if result.get("status") == "ok" and token:
            username = result.get("username") or req.username
            ensure_tls_connection_bg(username, token)

        return result
    finally:
        db.close()


@app.post("/api/connect")
async def api_connect(req: Request):
    """(Re)estabelece a conexão TLS quando o frontend monta a tela de chat."""
    body = await req.json()
    token = body.get("token")
    username = body.get("username")
    if not token or not username:
        raise HTTPException(status_code=400, detail="Token e username são obrigatórios")

    verified = verify_access_token(token)
    if verified != username:
        raise HTTPException(status_code=401, detail="Token inválido")

    ensure_tls_connection_bg(username, token)
    return {"status": "ok", "message": f"TLS em background para {username}"}


# ======================================================
# 💬 MENSAGENS - HISTÓRICO PRIVADO
# ======================================================
@app.get("/api/messages/inbox/{username}")
async def api_inbox(username: str):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail=f"Usuário '{username}' não encontrado.")

        # 🔑 Ler chave privada de backend/keys/{username}/
        BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
        user_keys_dir = os.path.join(BACKEND_DIR, "keys", username)
        priv_path = os.path.join(user_keys_dir, f"{username}_private.pem")
        try:
            with open(priv_path, "r") as f:
                private_key_pem = f.read()
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail=f"Chave privada de '{username}' não encontrada em {priv_path}")

        messages = (
            db.query(Message)
            .filter(
                ((Message.sender_id == user.id) | (Message.receiver_id == user.id))
                & (Message.group_id == None)
            )
            .order_by(Message.timestamp.asc())
            .all()
        )

        formatted = []
        idea = IDEAManager()
        for msg in messages:
            sender_user = db.query(User).get(msg.sender_id)
            receiver_user = db.query(User).get(msg.receiver_id)
            is_outgoing = sender_user and sender_user.username == username
            content_plain: Optional[str] = None

            if not is_outgoing:
                try:
                    content_plain = idea.decifrar_do_chat(
                        packet=msg.content_encrypted,
                        cek_b64=msg.key_encrypted,
                        destinatario=username,
                        chave_privada_pem=private_key_pem,
                    )
                except Exception as e:
                    print(f"[DECRYPT_FAIL] {msg.id} → {e}")
                    content_plain = "(erro ao decifrar)"
            else:
                content_plain = None

            formatted.append(
                {
                    "id": msg.id,
                    "sender": sender_user.username if sender_user else "Desconhecido",
                    "receiver": receiver_user.username if receiver_user else "Desconhecido",
                    "content": content_plain,
                    "content_encrypted": msg.content_encrypted,
                    "key_encrypted": msg.key_encrypted,
                    "outgoing": is_outgoing,
                    "timestamp": str(msg.timestamp),
                }
            )

        return {"messages": formatted}
    finally:
        db.close()


@app.get("/api/messages/inbox/{username}/{contact}")
async def api_inbox_contact(username: str, contact: str):
    """Retorna apenas mensagens entre o usuário e o contato especificado, evitando duplicatas."""
    db = SessionLocal()
    try:
        user = db.query(User).filter_by(username=username).first()
        contact_user = db.query(User).filter_by(username=contact).first()
        if not user or not contact_user:
            raise HTTPException(status_code=404, detail="Usuário ou contato não encontrado.")

        # 🔑 Ler chave privada de backend/keys/{username}/
        BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
        user_keys_dir = os.path.join(BACKEND_DIR, "keys", username)
        priv_path = os.path.join(user_keys_dir, f"{username}_private.pem")
        try:
            with open(priv_path, "r") as f:
                private_key_pem = f.read()
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail=f"Chave privada não encontrada para {username}")

        # hashes únicos (sem self-copies)
        unique_hashes = (
            db.query(Message.content_hash)
            .filter(
                ((Message.sender_id == user.id) & (Message.receiver_id == contact_user.id))
                | ((Message.sender_id == contact_user.id) & (Message.receiver_id == user.id))
            )
            .filter(Message.group_id == None)
            .filter(Message.sender_id != Message.receiver_id)
            .filter(Message.content_hash.isnot(None))
            .distinct()
            .all()
        )
        unique_hashes = [h[0] for h in unique_hashes if h[0]]

        # pega a mais recente por hash
        msgs = []
        for content_hash in unique_hashes:
            msg = (
                db.query(Message)
                .filter(
                    ((Message.sender_id == user.id) & (Message.receiver_id == contact_user.id))
                    | ((Message.sender_id == contact_user.id) & (Message.receiver_id == user.id)),
                    Message.content_hash == content_hash,
                    Message.group_id == None,
                    Message.sender_id != Message.receiver_id,
                )
                .order_by(Message.timestamp.desc())
                .first()
            )
            if msg:
                msgs.append(msg)
        msgs.sort(key=lambda x: x.timestamp)

        # mapa de self-copies das mensagens enviadas
        idea = IDEAManager()
        self_copy_map: Dict[str, Message] = {}
        msg_hashes = [m.content_hash for m in msgs if m.sender_id == user.id and m.content_hash]
        if msg_hashes:
            self_copies = (
                db.query(Message)
                .filter(
                    Message.sender_id == user.id,
                    Message.receiver_id == user.id,
                    Message.content_hash.in_(msg_hashes),
                )
                .all()
            )
            self_copy_map = {sc.content_hash: sc for sc in self_copies}

        formatted = []
        ids_para_marcar_lidas = []

        for msg in msgs:
            sender = db.query(User).get(msg.sender_id)
            is_outgoing = sender.username == username
            content_plain = ""

            try:
                if not is_outgoing:
                    # Verifica se deve logar (mensagem não lida)
                    should_log = not msg.is_read
                    step_counter = [1] if should_log else None

                    content_plain = idea.decifrar_do_chat(
                        packet=msg.content_encrypted,
                        cek_b64=msg.key_encrypted,
                        destinatario=username,
                        chave_privada_pem=private_key_pem,
                        is_group=False,
                        log_enabled=should_log,
                        step_counter=step_counter,
                        sender=sender.username,
                    ) or ""

                    # Adiciona log de recebimento concluído
                    if should_log:
                        individual_chat_logger.info(
                            format_box(
                                title=f"RECEBIMENTO CONCLUÍDO: {username} recebeu mensagem de {sender.username}",
                                content=[f"Mensagem: '{content_plain}'"],
                                width=70,
                                char="=",
                            )
                        )
                        individual_chat_logger.info("\n")
                        ids_para_marcar_lidas.append(msg.id)
                else:
                    sc = self_copy_map.get(msg.content_hash) if msg.content_hash else None
                    if sc:
                        content_plain = idea.decifrar_do_chat(
                            packet=sc.content_encrypted,
                            cek_b64=sc.key_encrypted,
                            destinatario=username,
                            chave_privada_pem=private_key_pem,
                            is_group=False,
                            log_enabled=False,
                        ) or ""
            except Exception:
                content_plain = content_plain or "(erro ao decifrar)"

            formatted.append(
                {
                    "id": msg.id,
                    "sender": sender.username,
                    "receiver": contact,
                    "content": content_plain,
                    "outgoing": is_outgoing,
                    "timestamp": str(msg.timestamp),
                }
            )

        # Marca mensagens como lidas em batch
        if ids_para_marcar_lidas:
            db.query(Message).filter(Message.id.in_(ids_para_marcar_lidas)).update({"is_read": True}, synchronize_session=False)
            db.commit()

        return {"messages": formatted}
    finally:
        db.close()


# ======================================================
# 💌 ENVIO PRIVADO (retorno imediato; entrega TLS em background)
# ======================================================
@app.post("/api/messages/send")
async def api_send_message(req: Request):
    db = SessionLocal()
    try:
        data = await req.json()
        token = data.get("token")
        to = data.get("to")
        content = data.get("content", "")
        if not token or not to or not content:
            raise HTTPException(status_code=400, detail="Campos obrigatórios ausentes.")

        sender = verify_access_token(token)
        if not sender:
            raise HTTPException(status_code=401, detail="❌ Token inválido.")

        receiver = db.query(User).filter(User.username == to).first()
        if not receiver or not receiver.public_key:
            raise HTTPException(status_code=404, detail=f"Destinatário '{to}' não encontrado ou sem chave pública.")
        pubkey_pem = receiver.public_key.decode("utf-8", errors="ignore")

        # hash do conteúdo
        content_hash = sha256(content.encode("utf-8")).hexdigest()

        # 🔑 Criptografia principal (mantém síncrono - crítico para resposta)
        idea = IDEAManager()
        step_counter = [1]
        content_encrypted_b64, cek_rsa_b64 = idea.cifrar_para_chat(
            texto_plano=content,
            remetente=sender,
            destinatario=to,
            chave_publica_destinatario_pem=pubkey_pem,
            step_counter=step_counter,
        )

        sender_user = db.query(User).filter(User.username == sender).first()
        if not sender_user:
            raise HTTPException(status_code=404, detail="Remetente não encontrado.")

        # 💾 Mensagem principal (mantém síncrono - crítico para resposta)
        message_to_receiver = Message(
            sender_id=sender_user.id,
            receiver_id=receiver.id,
            content_encrypted=content_encrypted_b64,
            key_encrypted=cek_rsa_b64,
            content_hash=content_hash,
        )
        db.add(message_to_receiver)
        db.commit()
        
        # 🚀 Retorna resposta imediatamente (libera botão "Enviando...")
        message_id = message_to_receiver.id
        
        # 📦 Prepara dados para operações em background
        cek_hex_for_log = idea.get_chave_sessao_hex()
        sender_id = sender_user.id
        has_public_key = sender_user.public_key is not None

        # 🔄 Operações em background (self-copy + log final + TLS)
        async def background_tasks():
            db_bg = SessionLocal()
            try:
                # 1️⃣ Self-copy (não crítico - pode ser feito em background)
                if has_public_key:
                    try:
                        sender_user_bg = db_bg.query(User).filter(User.id == sender_id).first()
                        if sender_user_bg and sender_user_bg.public_key:
                            pubkey_sender_pem = sender_user_bg.public_key.decode("utf-8", errors="ignore")
                            idea_bg = IDEAManager()
                            content_encrypted_self_b64, cek_rsa_self_b64 = idea_bg.cifrar_para_chat(
                                texto_plano=content,
                                remetente=sender,
                                destinatario=sender,
                                chave_publica_destinatario_pem=pubkey_sender_pem,
                                log_enabled=False,
                            )
                            message_to_self = Message(
                                sender_id=sender_user_bg.id,
                                receiver_id=sender_user_bg.id,
                                content_encrypted=content_encrypted_self_b64,
                                key_encrypted=cek_rsa_self_b64,
                                content_hash=content_hash,
                            )
                            db_bg.add(message_to_self)
                            db_bg.commit()
                    except Exception as e:
                        print(f"[BG_SELF_COPY_ERR] {e}")

                # 2️⃣ Log final "ENVIO CONCLUÍDO" (não crítico - pode ser feito em background)
                try:
                    ciphertext_hex, iv_hex = content_encrypted_b64.split(":")
                    ciphertext_truncado = truncate_hex(ciphertext_hex, 8, 8)
                    iv_truncado = truncate_hex(iv_hex, 8, 8)
                    cek_truncada = truncate_hex(cek_hex_for_log, 8, 8)
                    cek_enc_truncado = truncate_hex(cek_rsa_b64, 12, 12)

                    individual_chat_logger.info(
                        format_box(
                            title=f"ENVIO CONCLUÍDO: Mensagem enviada para {to}",
                            content=[
                                f"Remetente: {sender}",
                                f"Destinatário: {to}",
                                f"CEK ID: {cek_truncada}",
                                f"Ciphertext: {ciphertext_truncado}",
                                f"IV: {iv_truncado}",
                                f"CEK wrapada (RSA): {cek_enc_truncado}",
                            ],
                            width=70,
                            char="=",
                        )
                    )
                    individual_chat_logger.info("\n")
                except Exception as e:
                    print(f"[BG_LOG_ERR] {e}")

                # 3️⃣ Entrega TLS (já estava em background)
                try:
                    ensure_tls_connection_bg(sender, token)
                    conn = TLS_CONNECTIONS.get(sender)
                    if conn and isinstance(conn.get("ready"), asyncio.Event):
                        try:
                            await asyncio.wait_for(conn["ready"].wait(), timeout=0.6)
                        except asyncio.TimeoutError:
                            pass

                    conn = TLS_CONNECTIONS.get(sender)
                    w = conn.get("writer") if conn else None
                    if isinstance(w, asyncio.StreamWriter) and not w.is_closing():
                        tls_message = {
                            "action": "send_message",
                            "token": token,
                            "to": to,
                            "content_encrypted": content_encrypted_b64,
                            "key_encrypted": cek_rsa_b64,
                            "content_hash": content_hash,
                        }
                        w.write(json.dumps(tls_message).encode() + b"\n")
                        await w.drain()
                        print(f"📡 [TLS] Transmitido em background: {sender} → {to}")
                except Exception as e:
                    print(f"[TLS_DELIVERY_BG_ERR] {e}")
            finally:
                db_bg.close()

        asyncio.create_task(background_tasks())

        return {
            "status": "success",
            "message": f"Mensagem enviada de {sender} para {to}.",
            "debug": {"main_message_id": message_id, "hash": content_hash[:16] + "..."},
        }
    finally:
        db.close()

# ======================================================
# 👥 GRUPOS  (mantidos com melhorias internas)
# ======================================================
@app.post("/api/groups/create")
async def api_groups_create(req: CreateGroupReq):
    from backend.database.queries.groups import create_group
    db = SessionLocal()
    try:
        creator = verify_access_token(req.token)
        if not creator:
            raise HTTPException(status_code=401, detail="Token inválido.")
        g = create_group(db, name=req.name, admin_username=creator)
        return {"status": "ok", "group": {"id": g.id, "name": g.name}}
    finally:
        db.close()


@app.post("/api/groups/add_member")
async def api_groups_add_member(req: AddMemberReq):
    from backend.database.queries.members import add_member

    db = SessionLocal()
    try:
        requester = verify_access_token(req.token)
        if not requester:
            raise HTTPException(status_code=401, detail="Token inválido.")

        group = db.query(Group).filter_by(name=req.group).first()
        if not group:
            raise HTTPException(status_code=404, detail="Grupo não encontrado.")

        admin = db.query(User).get(group.admin_id)
        if not admin or admin.username != requester:
            raise HTTPException(status_code=403, detail="Apenas o admin pode adicionar membros.")

        add_member(db, req.username, req.group)

        return {
            "status": "ok",
            "message": f"{req.username} adicionado ao grupo {req.group}. Nova chave IDEA distribuída.",
        }
    finally:
        db.close()


@app.get("/api/groups/my")
async def api_groups_my(token: str):
    db = SessionLocal()
    try:
        username = verify_access_token(token)
        if not username:
            raise HTTPException(status_code=401, detail="Token inválido.")
        user = db.query(User).filter_by(username=username).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuário não encontrado.")

        groups = (
            db.query(Group)
            .join(GroupMember, Group.id == GroupMember.group_id)
            .filter(GroupMember.user_id == user.id)
            .all()
        )
        result = []
        for g in groups:
            is_admin = g.admin_id == user.id
            result.append({"id": g.id, "name": g.name, "is_admin": is_admin})
        return {"groups": result}
    finally:
        db.close()


@app.post("/api/groups/remove_member")
async def api_groups_remove_member(req: RemoveMemberReq):
    from backend.database.queries.members import remove_member
    from backend.utils.log_formatter import format_box
    from backend.utils.logger_config import group_chat_logger

    db = SessionLocal()
    try:
        requester = verify_access_token(req.token)
        if not requester:
            raise HTTPException(status_code=401, detail="Token inválido.")

        group = db.query(Group).filter_by(name=req.group).first()
        if not group:
            raise HTTPException(status_code=404, detail="Grupo não encontrado.")

        admin = db.query(User).get(group.admin_id)
        if not admin or admin.username != requester:
            raise HTTPException(status_code=403, detail="Apenas o admin pode remover membros.")

        # Log: Admin removendo membro
        group_chat_logger.info("\n")
        group_chat_logger.info(
            format_box(
                title=f"➖ ADMIN REMOVENDO MEMBRO: {requester} (admin) está removendo {req.username} do grupo {req.group}",
                content=[],
                width=70,
                char="=",
            )
        )

        remove_member(db, req.username, req.group)

        return {"status": "ok", "message": f"{req.username} removido de {req.group}. Nova chave IDEA distribuída."}
    finally:
        db.close()


@app.post("/api/groups/send")
async def api_groups_send(req: Request):
    db = SessionLocal()
    try:
        data = await req.json()
        token = data.get("token")
        group_name = data.get("group")
        content = data.get("content")

        sender_name = verify_access_token(token)
        user_sender = db.query(User).filter_by(username=sender_name).first()
        group = db.query(Group).filter_by(name=group_name).first()

        if not (group and user_sender):
            raise HTTPException(status_code=404, detail="Grupo ou remetente inválido.")

        members = db.query(GroupMember).filter_by(group_id=group.id).all()
        if not members:
            raise HTTPException(status_code=404, detail="Grupo sem membros.")

        # PASSO 1 — CEK + IV e criptografia UMA VEZ
        group_chat_logger.info(
            format_box(
                title=f"ENVIANDO MENSAGEM PARA GRUPO: {sender_name} → Grupo {group_name}",
                content=[],
                width=70,
                char="=",
            )
        )

        first_member_user = db.query(User).get(members[0].user_id)
        if not first_member_user or not first_member_user.public_key:
            raise HTTPException(status_code=404, detail="Grupo sem membros válidos.")
        idea = IDEAManager()
        step_counter = [1]
        cipher, _ = idea.cifrar_para_chat(
            texto_plano=content,
            remetente=sender_name,
            destinatario=group_name,
            chave_publica_destinatario_pem=first_member_user.public_key.decode(),
            is_group=True,
            log_enabled=True,
            step_counter=step_counter,
        )
        cek_bytes = bytes.fromhex(idea.get_chave_sessao_hex())
        cek_hex = cek_bytes.hex().upper()
        cek_truncada = truncate_hex(cek_hex, 8, 8)

        ciphertext_hex, iv_hex = cipher.split(":")
        ciphertext_truncado = truncate_hex(ciphertext_hex, 8, 8)
        iv_truncado = truncate_hex(iv_hex, 8, 8)

        group_chat_logger.info(f"{'='*70}")

        # PASSO 2 — Obter chaves públicas dos membros
        group_chat_logger.info(
            format_box(
                title=f"OBTENDO CHAVES PÚBLICAS: {sender_name} → {len(members)} membros do grupo {group_name}",
                content=[],
                width=70,
                char="=",
            )
        )

        membros_info = []
        for m in members:
            user = db.query(User).get(m.user_id)
            if not user or not user.public_key:
                continue

            pub = user.public_key.decode()
            pubkey_fingerprint = truncate_hex(sha256(pub.encode()).hexdigest(), 8, 8)
            group_chat_logger.info(
                f"[{step_counter[0]}] {sender_name} obteve chave pública RSA de {user.username} (Fingerprint: {pubkey_fingerprint})"
            )
            step_counter[0] += 1
            membros_info.append({"user": user, "pub": pub, "pubkey_fingerprint": pubkey_fingerprint})

        group_chat_logger.info(f"{sender_name} obteve chaves públicas de {len(membros_info)} membros")
        group_chat_logger.info(f"{'='*70}")

        # PASSO 3 — Wrap da CEK para cada membro + persistência
        membros_com_chave = []
        group_chat_logger.info(
            format_box(
                title=f"WRAP DA CEK: Distribuindo para {len(membros_info)} membros (Grupo: {group_name})",
                content=[f"CEK ID: {cek_truncada}", f"Ciphertext: {ciphertext_truncado}", f"IV: {iv_truncado}"],
                width=70,
                char="=",
            )
        )

        for info in membros_info:
            user = info["user"]
            pub = info["pub"]
            pubkey_fingerprint = info["pubkey_fingerprint"]

            group_chat_logger.info(
                format_box(
                    title=f"WRAP CEK: {sender_name} → {user.username}",
                    content=[
                        f"[{step_counter[0]}] CEK a ser wrapada: {cek_truncada}",
                        f"[{step_counter[0] + 1}] Chave pública RSA de {user.username} (Fingerprint: {pubkey_fingerprint})",
                    ],
                    width=70,
                    char="-",
                )
            )
            step_counter[0] += 2

            cek_enc = RSAManager.cifrar_chave_sessao(cek_bytes, pub)
            cek_enc_truncado = truncate_hex(cek_enc, 12, 12)

            group_chat_logger.info(f"[{step_counter[0]}] CEK wrapada (RSA) para {user.username}: {cek_enc_truncado}")
            step_counter[0] += 1
            group_chat_logger.info(f"[{step_counter[0]}] {user.username} receberá:")
            step_counter[0] += 1
            group_chat_logger.info(f"     └─ Ciphertext: {ciphertext_truncado}")
            group_chat_logger.info(f"     └─ IV: {iv_truncado}")
            group_chat_logger.info(f"     └─ CEK wrapada: {cek_enc_truncado}")
            group_chat_logger.info(f"{'-'*70}")

            msg = Message(
                sender_id=user_sender.id,
                receiver_id=user.id,
                group_id=group.id,
                content_encrypted=cipher,
                key_encrypted=cek_enc,
            )
            db.add(msg)
            membros_com_chave.append(user.username)

        db.commit()

        # 🚀 Retorna resposta imediatamente (libera botão "Enviando...")
        # 📦 Prepara dados para log final em background
        membros_list = membros_com_chave.copy()
        cek_truncada_log = cek_truncada
        ciphertext_truncado_log = ciphertext_truncado
        iv_truncado_log = iv_truncado

        # 🔄 Log final em background (não crítico)
        async def background_log():
            try:
                group_chat_logger.info(
                    format_box(
                        title=f"ENVIO CONCLUÍDO: Mensagem enviada para {len(membros_list)} membros",
                        content=[
                            f"Remetente: {sender_name}",
                            f"Grupo: {group_name}",
                            f"Membros: {', '.join(membros_list)}",
                            f"CEK ID: {cek_truncada_log}",
                            f"Ciphertext: {ciphertext_truncado_log}",
                            f"IV: {iv_truncado_log}",
                        ],
                        width=70,
                        char="=",
                    )
                )
                group_chat_logger.info("\n")
            except Exception as e:
                print(f"[BG_LOG_ERR] {e}")

        asyncio.create_task(background_log())

        return {"status": "success"}
    finally:
        db.close()


@app.post("/api/groups/regenerate_key")
async def api_groups_regenerate_key(req: Request):
    from hashlib import sha256 as _sha256
    from datetime import datetime, timezone, timedelta
    import base64
    from backend.crypto.idea_manager import IDEAManager
    from backend.crypto.rsa_manager import RSAManager
    from backend.utils.log_formatter import format_box, truncate_hex
    from backend.auth.models import SessionKey

    db = SessionLocal()
    manaus_tz = timezone(timedelta(hours=-4))
    try:
        data = await req.json()
        token = data.get("token")
        group_name = data.get("group")

        if not token or not group_name:
            raise HTTPException(status_code=400, detail="Campos obrigatórios ausentes.")

        requester = verify_access_token(token)
        if not requester:
            raise HTTPException(status_code=401, detail="Token inválido.")

        group = db.query(Group).filter_by(name=group_name).first()
        if not group:
            raise HTTPException(status_code=404, detail="Grupo não encontrado.")

        admin = db.query(User).get(group.admin_id)
        if not admin or admin.username != requester:
            raise HTTPException(status_code=403, detail="Apenas o admin pode regenerar a chave.")

        # Busca chave antiga
        # 🔑 Ler chave privada de backend/keys/{username}/
        BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
        admin_keys_dir = os.path.join(BACKEND_DIR, "keys", admin.username)
        admin_priv_path = os.path.join(admin_keys_dir, f"{admin.username}_private.pem")
        with open(admin_priv_path, "r") as f:
            admin_priv_key = f.read()

        admin_msg_antiga = (
            db.query(Message)
            .filter_by(group_id=group.id, receiver_id=admin.id)
            .filter(Message.key_encrypted.isnot(None))
            .order_by(Message.timestamp.desc())
            .first()
        )

        chave_antiga_hex = None
        if admin_msg_antiga:
            try:
                cek_antiga_bytes = RSAManager.decifrar_chave_sessao(admin_msg_antiga.key_encrypted, admin_priv_key)
                chave_antiga_hex = cek_antiga_bytes.hex().upper()
            except Exception:
                pass

        group_chat_logger.info("\n")
        group_chat_logger.info(
            format_box(
                title=f"🔄 REGENERANDO CHAVE DE SESSÃO: Grupo {group_name} | Admin: {requester}",
                content=[],
                width=70,
                char="=",
            )
        )

        group_chat_logger.info(
            format_box(
                title=f"ROTAÇÃO DE CHAVE DE SESSÃO: Grupo {group_name}",
                content=[],
                width=70,
                char="=",
            )
        )

        idea = IDEAManager()
        nova_cek_bytes = bytes.fromhex(idea.get_chave_sessao_hex())
        nova_cek_hex = nova_cek_bytes.hex().upper()
        nova_cek_truncada = truncate_hex(nova_cek_hex, 8, 8)

        if chave_antiga_hex:
            chave_antiga_truncada = truncate_hex(chave_antiga_hex, 8, 8)
            group_chat_logger.info(f"[CHAVE_ANTIGA] Chave de sessão anterior: {chave_antiga_truncada}")
            group_chat_logger.info(f"ROTAÇÃO: Chave antiga → Nova chave gerada")
        else:
            group_chat_logger.info(f"[CHAVE_ANTIGA] Não foi possível recuperar")
        
        group_chat_logger.info(f"[CHAVE_NOVA] Chave de sessão gerada (atual): {nova_cek_truncada}")
        group_chat_logger.info(f"{'='*70}")

        membros = db.query(GroupMember).filter_by(group_id=group.id).all()
        
        group_chat_logger.info(
            format_box(
                title=f"DISTRIBUINDO NOVA CEK: Grupo {group_name} → {len(membros)} membros",
                content=[f"CEK ID: {nova_cek_truncada}"],
                width=70,
                char="=",
            )
        )

        cek_fingerprint = _sha256(nova_cek_bytes).hexdigest()

        for m in membros:
            membro_user = db.query(User).get(m.user_id)
            if membro_user and membro_user.public_key:
                pubkey_pem = membro_user.public_key.decode()
                pubkey_fingerprint_full = _sha256(pubkey_pem.encode()).hexdigest()
                pubkey_fingerprint = truncate_hex(pubkey_fingerprint_full, 8, 8)

                group_chat_logger.info(
                    format_box(
                        title=f"WRAP CEK: Grupo {group_name} → {membro_user.username}",
                        content=[
                            f"[1] CEK a ser wrapada: {nova_cek_truncada}",
                            f"[2] Chave pública RSA de {membro_user.username} (Fingerprint: {pubkey_fingerprint})",
                        ],
                        width=70,
                        char="-",
                    )
                )

                cek_enc_b64 = RSAManager.cifrar_chave_sessao(nova_cek_bytes, pubkey_pem)
                cek_enc_truncada = truncate_hex(cek_enc_b64, 12, 12)

                group_chat_logger.info(f"[3] CEK wrapada (RSA) para {membro_user.username}: {cek_enc_truncada}")
                group_chat_logger.info(f"[4] {membro_user.username} receberá CEK wrapada com sua chave pública RSA")
                group_chat_logger.info(f"{'-'*70}")

                # Converte Base64 → bytes se necessário
                if isinstance(cek_enc_b64, str):
                    cek_enc_bytes = base64.b64decode(cek_enc_b64)
                else:
                    cek_enc_bytes = cek_enc_b64

                # Atualiza SessionKey
                from sqlalchemy import text
                db.execute(
                    text("INSERT OR REPLACE INTO session_keys (entity_type, entity_id, cek_encrypted, cek_fingerprint, created_at) VALUES (:entity_type, :entity_id, :cek_encrypted, :cek_fingerprint, :created_at)"),
                    {
                        "entity_type": "group",
                        "entity_id": group.id,
                        "cek_encrypted": cek_enc_bytes,
                        "cek_fingerprint": cek_fingerprint,
                        "created_at": datetime.now(manaus_tz),
                    },
                )

                db.add(
                    Message(
                        sender_id=admin.id,
                        receiver_id=membro_user.id,
                        group_id=group.id,
                        content_encrypted="(chave IDEA regenerada manualmente pelo admin)",
                        key_encrypted=cek_enc_b64,
                    )
                )

        db.commit()

        group_chat_logger.info(
            format_box(
                title=f"Redistribuição concluída: {len(membros)} membros receberam a nova CEK",
                content=[f"CEK ID: {nova_cek_truncada}"],
                width=70,
                char="=",
            )
        )
        group_chat_logger.info("\n")

        return {
            "status": "ok",
            "message": f"Nova chave IDEA regenerada para o grupo '{group_name}' e distribuída a todos os membros.",
        }
    finally:
        db.close()


@app.get("/api/groups/{group_name}/messages")
async def api_groups_messages(group_name: str, token: str):
    db = SessionLocal()
    try:
        user_name = verify_access_token(token)
        user = db.query(User).filter_by(username=user_name).first()
        group = db.query(Group).filter_by(name=group_name).first()
        if not group or not user:
            raise HTTPException(status_code=404, detail="Grupo ou usuário inválido.")

        msgs = (
            db.query(Message)
            .filter(Message.group_id == group.id, Message.receiver_id == user.id)
            .order_by(Message.timestamp.asc())
            .all()
        )

        # 🔑 Ler chave privada de backend/keys/{username}/
        BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
        user_keys_dir = os.path.join(BACKEND_DIR, "keys", user_name)
        priv_path = os.path.join(user_keys_dir, f"{user_name}_private.pem")
        with open(priv_path, "r") as f:
            private_key_pem = f.read()

        formatted = []
        ids_para_marcar_lidas = []

        for msg in msgs:
            sender = db.query(User).get(msg.sender_id)
            sender_name = sender.username if sender else "Desconhecido"

            try:
                if msg.content_encrypted.startswith("("):
                    plain = "🔑 Atualização de segurança no grupo"
                else:
                    should_log = not msg.is_read
                    step_counter = [1] if should_log else None

                    plain = IDEAManager().decifrar_do_chat(
                        packet=msg.content_encrypted,
                        cek_b64=msg.key_encrypted,
                        destinatario=user_name,
                        chave_privada_pem=private_key_pem,
                        is_group=True,
                        log_enabled=should_log,
                        step_counter=step_counter,
                        sender=sender_name,
                        group_name=group_name,
                    )

                    if should_log:
                        group_chat_logger.info(
                            format_box(
                                title=f"RECEBIMENTO CONCLUÍDO: {user_name} recebeu mensagem de {sender_name}",
                                content=[f"Grupo: {group_name}", f"Mensagem: '{plain}'"],
                                width=70,
                                char="=",
                            )
                        )
                        group_chat_logger.info("\n")
                        ids_para_marcar_lidas.append(msg.id)

            except Exception as e:
                print(f"[GROUP_DEC_ERR] {e}")
                plain = "(erro ao decifrar)"

            formatted.append({"id": msg.id, "from": sender_name, "content": plain, "timestamp": str(msg.timestamp)})

        # Marca mensagens como lidas em batch
        if ids_para_marcar_lidas:
            db.query(Message).filter(Message.id.in_(ids_para_marcar_lidas)).update({"is_read": True}, synchronize_session=False)
            db.commit()

        return {"messages": formatted}
    finally:
        db.close()


@app.get("/api/users/all")
async def api_users_all():
    db = SessionLocal()
    try:
        users = db.query(User).all()
        return {"users": [u.username for u in users]}
    finally:
        db.close()


@app.get("/api/groups/{group_name}/members")
async def api_group_members(group_name: str, token: str):
    db = SessionLocal()
    try:
        requester = verify_access_token(token)
        if not requester:
            raise HTTPException(status_code=401, detail="Token inválido.")
        group = db.query(Group).filter_by(name=group_name).first()
        if not group:
            raise HTTPException(status_code=404, detail="Grupo não encontrado.")
        admin = db.query(User).get(group.admin_id)
        members = db.query(GroupMember).filter_by(group_id=group.id).all()
        member_list = []
        for m in members:
            user = db.query(User).get(m.user_id)
            member_list.append(user.username)
        return {"group": group_name, "admin": admin.username if admin else None, "members": member_list}
    finally:
        db.close()


@app.post("/api/groups/leave")
async def api_groups_leave(req: Request):
    from backend.database.queries.members import remove_member
    from backend.auth.models import Group, User, GroupMember
    from backend.utils.log_formatter import format_box
    from backend.utils.logger_config import group_chat_logger

    db = SessionLocal()
    try:
        data = await req.json()
        token = data.get("token")
        group_name = data.get("group")
        requester = verify_access_token(token)
        if not requester:
            raise HTTPException(status_code=401, detail="Token inválido.")

        group = db.query(Group).filter_by(name=group_name).first()
        user = db.query(User).filter_by(username=requester).first()
        if not group or not user:
            raise HTTPException(status_code=404, detail="Grupo ou usuário não encontrado.")

        is_admin = group.admin_id == user.id
        membros_antes = db.query(GroupMember).filter_by(group_id=group.id).count()

        # Log: Membro saindo do grupo
        group_chat_logger.info("\n")
        if is_admin:
            group_chat_logger.info(
                format_box(
                    title=f"👋 ADMIN SAINDO DO GRUPO: {requester} está saindo do grupo {group_name}",
                    content=[f"👑 {requester} é o admin do grupo {group_name}"],
                    width=70,
                    char="=",
                )
            )
        else:
            group_chat_logger.info(
                format_box(
                    title=f"👋 MEMBRO SAINDO DO GRUPO: {requester} está saindo do grupo {group_name}",
                    content=[],
                    width=70,
                    char="=",
                )
            )

        # Marca para não duplicar o log de "REMOVENDO MEMBRO"
        from backend.database.queries import members
        members.remove_member._skip_remove_log = True
        try:
            remove_member(db, requester, group_name)
        except ValueError as e:
            # Se o membro ou grupo não foi encontrado, retorna erro
            members.remove_member._skip_remove_log = False
            raise HTTPException(status_code=404, detail=str(e))
        except Exception as e:
            # Captura outros erros e retorna mensagem genérica
            members.remove_member._skip_remove_log = False
            group_chat_logger.error(f"❌ Erro ao remover membro {requester} do grupo {group_name}: {e}")
            raise HTTPException(status_code=500, detail=f"Erro ao sair do grupo: {str(e)}")
        finally:
            members.remove_member._skip_remove_log = False

        # Verifica o estado do grupo após a remoção
        group_check = db.query(Group).filter_by(name=group_name).first()
        
        if not group_check:
            msg = f"🗑️ Você saiu do grupo {group_name} e o grupo foi excluído (sem membros restantes)."
        elif membros_antes == 1:
            msg = f"🗑️ Você saiu do grupo {group_name} e o grupo foi excluído (sem membros restantes)."
        elif is_admin:
            new_admin = db.query(User).get(group_check.admin_id)
            if new_admin and new_admin.id != user.id:
                msg = f"👋 Você saiu do grupo {group_name}. 👑 {new_admin.username} agora é o novo admin."
            else:
                msg = f"👋 Você saiu do grupo {group_name}."
        else:
            msg = f"👋 Você saiu do grupo {group_name}."

        return {"status": "ok", "message": msg}
    except HTTPException:
        # Re-lança HTTPException para manter o código de status correto
        raise
    except Exception as e:
        # Captura qualquer outro erro não esperado
        group_chat_logger.error(f"❌ Erro inesperado ao processar saída do grupo: {e}")
        raise HTTPException(status_code=500, detail="Erro ao processar saída do grupo.")
    finally:
        db.close()