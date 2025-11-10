import asyncio
from hashlib import sha256

import ssl
import json
from typing import Dict
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from base64 import b64encode

from backend.database.connection import SessionLocal
from backend.server.handlers_rest import handle_register_rest, handle_login_rest
from backend.auth.models import User, Message, Group, GroupMember
from backend.auth.auth_jwt import verify_access_token
from backend.auth.security import hash_senha as hash_password
from backend.crypto.rsa_manager import RSAManager
# from backend.utils.logger_config import log_event
# ======================================================
# 🔐 CONFIGURAÇÃO DE REDE (TLS)
# ======================================================
TCP_HOST = "127.0.0.1"
TCP_PORT = 8888
SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE

TLS_CONNECTIONS: Dict[str, Dict[str, asyncio.StreamWriter]] = {}


async def ensure_tls_connection(username: str, token: str):
    conn = TLS_CONNECTIONS.get(username)
    if conn and not conn["writer"].is_closing():
        return conn

    reader, writer = await asyncio.open_connection(TCP_HOST, TCP_PORT, ssl=SSL_CONTEXT)
    TLS_CONNECTIONS[username] = {"reader": reader, "writer": writer}
    print(f"[TLS] 🔗 Conexão TLS aberta para {username}")

    writer.write(json.dumps({"action": "resume_session", "token": token}).encode() + b"\n")
    await writer.drain()

    async def listen():
        try:
            while not reader.at_eof():
                data = await reader.readline()
                if not data:
                    break
                print(f"[TLS][{username}] {data.decode().strip()}")
        except Exception as e:
            print(f"[TLS_READ_ERR][{username}] {e}")

    asyncio.create_task(listen())
    return TLS_CONNECTIONS[username]


# ======================================================
# 🫀 KEEP-ALIVE
# ======================================================
async def start_keepalive():
    while True:
        await asyncio.sleep(30)
        for user, conn in list(TLS_CONNECTIONS.items()):
            writer = conn.get("writer")
            if writer and not writer.is_closing():
                try:
                    writer.write(json.dumps({"action": "ping"}).encode() + b"\n")
                    await writer.drain()
                except Exception as e:
                    print(f"[PING_FAIL][{user}] {e}")


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
        privada_pem_str, publica_pem_str = RSAManager.gerar_par_chaves()

        private_path = f"keys/{req.dict().get("username")}_private.pem"
        with open(private_path, "w", encoding="utf-8") as f:
            f.write(privada_pem_str)
        print(f"🔑 Chave privada salva em: {private_path}")

        public_key_b64 = b64encode(publica_pem_str.encode("utf-8")).decode("utf-8")

        hashed_password = hash_password(req.dict().get("password"))

        user_data = {
            "username": req.username,
            "password": hashed_password,
            "public_key": publica_pem_str
        }

        return await handle_register_rest(db, user_data)
    finally:
        db.close()


@app.post("/api/login")
async def api_login(req: AuthRequest):
    db = SessionLocal()
    try:
        result, token = await handle_login_rest(db, req.dict())
        if result.get("status") == "error":
            raise HTTPException(status_code=401, detail=result.get("message"))
        return result
    finally:
        db.close()


# ======================================================
# 💬 MENSAGENS - HISTÓRICO PRIVADO
# ======================================================
@app.get("/api/messages/inbox/{username}")
async def api_inbox(username: str):
    from backend.crypto.idea_manager import IDEAManager

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail=f"Usuário '{username}' não encontrado.")

        priv_path = f"keys/{username}_private.pem"
        try:
            with open(priv_path, "r") as f:
                private_key_pem = f.read()
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail=f"Chave privada de '{username}' não encontrada em {priv_path}")

        messages = (
            db.query(Message)
            .filter(
                ((Message.sender_id == user.id) | (Message.receiver_id == user.id)) &
                (Message.group_id == None)
            )
            .order_by(Message.timestamp.asc())
            .all()
        )

        formatted = []
        for msg in messages:
            sender_user = db.query(User).get(msg.sender_id)
            receiver_user = db.query(User).get(msg.receiver_id)
            is_outgoing = sender_user and sender_user.username == username
            content_plain = None

            if not is_outgoing:
                try:
                    content_plain = IDEAManager().decifrar_do_chat(
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

            formatted.append({
                "id": msg.id,
                "sender": sender_user.username if sender_user else "Desconhecido",
                "receiver": receiver_user.username if receiver_user else "Desconhecido",
                "content": content_plain,
                "content_encrypted": msg.content_encrypted,
                "key_encrypted": msg.key_encrypted,
                "outgoing": is_outgoing,
                "timestamp": str(msg.timestamp),
            })

        return {"messages": formatted}
    finally:
        db.close()

@app.get("/api/messages/inbox/{username}/{contact}")
async def api_inbox_contact(username: str, contact: str):
    from backend.crypto.idea_manager import IDEAManager
    db = SessionLocal()
    try:
        user = db.query(User).filter_by(username=username).first()
        contact_user = db.query(User).filter_by(username=contact).first()
        if not user or not contact_user:
            raise HTTPException(status_code=404, detail="Usuário ou contato não encontrado.")

        priv_path = f"keys/{username}_private.pem"
        try:
            with open(priv_path, "r") as f:
                private_key_pem = f.read()
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail=f"Chave privada não encontrada para {username}")

        # 🔥 CORREÇÃO RADICAL: Busca APENAS mensagens ÚNICAS
        # Usa DISTINCT no content_hash para evitar duplicação
        from sqlalchemy import distinct
        
        # Primeiro busca os content_hash únicos
        unique_hashes = (
            db.query(Message.content_hash)
            .filter(
                ((Message.sender_id == user.id) & (Message.receiver_id == contact_user.id)) |
                ((Message.sender_id == contact_user.id) & (Message.receiver_id == user.id))
            )
            .filter(Message.group_id == None)
            .filter(Message.content_hash.isnot(None))
            .distinct()
            .all()
        )
        
        unique_hashes = [h[0] for h in unique_hashes if h[0]]
        
        # Agora busca uma mensagem por hash (priorizando as mais recentes)
        msgs = []
        for content_hash in unique_hashes:
            msg = (
                db.query(Message)
                .filter(
                    ((Message.sender_id == user.id) & (Message.receiver_id == contact_user.id)) |
                    ((Message.sender_id == contact_user.id) & (Message.receiver_id == user.id)),
                    Message.content_hash == content_hash,
                    Message.group_id == None
                )
                .order_by(Message.timestamp.desc())  # Pega a mais recente
                .first()
            )
            if msg:
                msgs.append(msg)
        
        # Ordena por timestamp
        msgs.sort(key=lambda x: x.timestamp)

        formatted = []
        for msg in msgs:
            sender = db.query(User).get(msg.sender_id)
            is_outgoing = sender.username == username

            # 🔥 CORREÇÃO FINAL: Lógica de decifração priorizando conteúdo real
            plain_content = None
            decryption_attempted = False

            # Para mensagens ENVIADAS: PRIMEIRO tenta a cópia self (que sempre deve funcionar)
            if is_outgoing and msg.content_hash:
                try:
                    self_copy = (
                        db.query(Message)
                        .filter(
                            Message.sender_id == user.id,
                            Message.receiver_id == user.id,  # Self copy
                            Message.content_hash == msg.content_hash
                        )
                        .first()
                    )
                    if self_copy:
                        plain_content = IDEAManager().decifrar_do_chat(
                            packet=self_copy.content_encrypted,
                            cek_b64=self_copy.key_encrypted,
                            destinatario=username,
                            chave_privada_pem=private_key_pem,
                        )
                        decryption_attempted = True
                        print(f"✅ [OUTGOING_DECRYPTED] Mensagem {msg.id} via cópia self: '{plain_content}'")
                except Exception as e:
                    print(f"[SELF_COPY_FAIL] {e}")

            # Para mensagens RECEBIDAS: tenta decifrar normalmente
            if not decryption_attempted and not is_outgoing:
                try:
                    plain_content = IDEAManager().decifrar_do_chat(
                        packet=msg.content_encrypted,
                        cek_b64=msg.key_encrypted,
                        destinatario=username,
                        chave_privada_pem=private_key_pem,
                    )
                    decryption_attempted = True
                    print(f"✅ [INCOMING_DECRYPTED] Mensagem {msg.id} recebida: '{plain_content}'")
                except Exception as e:
                    print(f"[INCOMING_DECRYPT_FAIL] Message {msg.id}: {e}")

            # Fallback final - NUNCA mostra "(mensagem enviada)" ou texto confuso
            if not decryption_attempted or not plain_content:
                if is_outgoing:
                    # Se é mensagem enviada e não conseguiu decifrar, tenta uma última abordagem
                    # Busca qualquer mensagem com mesmo hash que possa funcionar
                    try:
                        alternative_msg = (
                            db.query(Message)
                            .filter(
                                Message.content_hash == msg.content_hash,
                                Message.group_id == None
                            )
                            .first()
                        )
                        if alternative_msg:
                            plain_content = IDEAManager().decifrar_do_chat(
                                packet=alternative_msg.content_encrypted,
                                cek_b64=alternative_msg.key_encrypted,
                                destinatario=username,
                                chave_privada_pem=private_key_pem,
                            )
                        else:
                            plain_content = "📝"  # Ícone indicando mensagem enviada
                    except Exception:
                        plain_content = "📝"  # Ícone indicando mensagem enviada
                else:
                    plain_content = "🔒"  # Ícone indicando mensagem não decifrada

            # Garante que o conteúdo nunca seja nulo
            if not plain_content:
                plain_content = "💬"  # Fallback absoluto

            formatted.append({
                "id": msg.id,
                "sender": sender.username,
                "receiver": contact,
                "content": plain_content,
                "outgoing": is_outgoing,
                "timestamp": str(msg.timestamp),
                "content_hash": msg.content_hash[:16] + "..." if msg.content_hash else None
            })

        print(f"📨 [INBOX_CLEAN] {username} ↔ {contact}: {len(msgs)} mensagens únicas")
        return {"messages": formatted}
    finally:
        db.close()
        
# ======================================================
# 💌 ENVIO PRIVADO - VERSÃO CORRIGIDA
# ======================================================
@app.post("/api/messages/send")
async def api_send_message(req: Request):
    from backend.crypto.idea_manager import IDEAManager
    db = SessionLocal()
    try:
        data = await req.json()
        token = data.get("token")
        to = data.get("to")
        content = data.get("content", "").strip()
        
        if not token or not to or not content:
            raise HTTPException(status_code=400, detail="Campos obrigatórios ausentes.")
        
        sender = verify_access_token(token)
        if not sender:
            raise HTTPException(status_code=401, detail="❌ Token inválido.")

        receiver = db.query(User).filter(User.username == to).first()
        if not receiver or not receiver.public_key:
            raise HTTPException(status_code=404, detail=f"Destinatário '{to}' não encontrado ou sem chave pública.")
        
        sender_user = db.query(User).filter(User.username == sender).first()
        if not sender_user:
            raise HTTPException(status_code=404, detail="Remetente não encontrado.")

        # 🔐 cifra conteúdo para o destinatário
        pubkey_pem = receiver.public_key.decode("utf-8", errors="ignore")
        idea = IDEAManager()
        cipher_b64, cek_b64 = idea.cifrar_para_chat(
            texto_plano=content,
            remetente=sender,
            destinatario=to,
            chave_publica_destinatario_pem=pubkey_pem,
        )

        # ✅ hash do plaintext para vincular cópia do remetente
        content_hash = sha256(content.encode("utf-8")).hexdigest()

        # 🔥 CORREÇÃO RADICAL: VERIFICA SE JÁ EXISTE MENSAGEM IDÊNTICA
        existing_message = (
            db.query(Message)
            .filter(
                Message.sender_id == sender_user.id,
                Message.receiver_id == receiver.id,
                Message.content_hash == content_hash
            )
            .first()
        )
        
        if existing_message:
            print(f"🚫 [DUPLICATE_BLOCKED] Mensagem duplicada detectada e bloqueada")
            return {
                "status": "error", 
                "message": "Mensagem duplicada detectada.",
                "debug": {"duplicate_blocked": True}
            }

        # 🔥 CORREÇÃO: CRIA APENAS 1 MENSAGEM REAL (sender -> receiver)
        message_to_receiver = Message(
            sender_id=sender_user.id,
            receiver_id=receiver.id,
            content_encrypted=cipher_b64,
            key_encrypted=cek_b64,
            content_hash=content_hash,
        )
        db.add(message_to_receiver)
        db.flush()  # Gera ID

        print(f"✅ [SEND_SINGLE] {sender} → {to} | Conteúdo: '{content}'")
        print(f"   📦 Única mensagem criada: ID {message_to_receiver.id}")

        # 🔥 CORREÇÃO: CÓPIA SELF APENAS SE POSSÍVEL E NECESSÁRIO
        if sender_user.public_key:
            try:
                pubkey_sender_pem = sender_user.public_key.decode("utf-8", errors="ignore")
                cipher_self_b64, cek_self_b64 = idea.cifrar_para_chat(
                    texto_plano=content,
                    remetente=sender,
                    destinatario=sender,
                    chave_publica_destinatario_pem=pubkey_sender_pem,
                )
                
                message_to_self = Message(
                    sender_id=sender_user.id,
                    receiver_id=sender_user.id,
                    content_encrypted=cipher_self_b64,
                    key_encrypted=cek_self_b64,
                    content_hash=content_hash,
                )
                db.add(message_to_self)
                print(f"   💾 Cópia self criada: ID {message_to_self.id}")
            except Exception as e:
                print(f"   ⚠️  Falha ao criar cópia self: {e}")
        
        db.commit()

        # 🔄 Transmissão via TLS (APENAS UMA VEZ)
        try:
            await ensure_tls_connection(sender, token)
            writer = TLS_CONNECTIONS[sender]["writer"]
            if not writer.is_closing():
                tls_message = {
                    "action": "send_message",
                    "token": token,
                    "to": to,
                    "content_encrypted": cipher_b64,
                    "key_encrypted": cek_b64,
                }
                writer.write(json.dumps(tls_message).encode() + b"\n")
                await writer.drain()
                print(f"   📡 Transmitido via TLS: 1 mensagem")
        except Exception as e:
            print(f"   ⚠️  Falha TLS: {e}")

        return {
            "status": "success", 
            "message": f"Mensagem enviada para {to}.",
            "debug": {
                "content": content,
                "main_message_id": message_to_receiver.id,
                "hash": content_hash[:16] + "..."
            }
        }
        
    except Exception as e:
        db.rollback()
        print(f"❌ [SEND_ERROR] {e}")
        raise HTTPException(status_code=500, detail=f"Erro ao enviar mensagem: {str(e)}")
    finally:
        db.close()
        
# ======================================================
# TESTE DEBUG
# ======================================================

@app.get("/api/debug/messages/{username}")
async def debug_user_messages(username: str):
    """Endpoint para debug - mostra todas as mensagens de um usuário"""
    db = SessionLocal()
    try:
        user = db.query(User).filter_by(username=username).first()
        if not user:
            return {"error": "Usuário não encontrado"}
        
        messages = db.query(Message).filter(
            (Message.sender_id == user.id) | (Message.receiver_id == user.id)
        ).order_by(Message.timestamp.asc()).all()
        
        result = []
        for msg in messages:
            sender = db.query(User).get(msg.sender_id)
            receiver = db.query(User).get(msg.receiver_id)
            result.append({
                "id": msg.id,
                "sender": sender.username if sender else "?",
                "receiver": receiver.username if receiver else "?",
                "content_hash": msg.content_hash,
                "is_self_copy": msg.sender_id == msg.receiver_id,
                "has_content": bool(msg.content_encrypted),
                "has_key": bool(msg.key_encrypted),
                "timestamp": str(msg.timestamp)
            })
        
        return {"user": username, "total_messages": len(result), "messages": result}
    finally:
        db.close()
# ======================================================
# 👥 GRUPOS
# ======================================================
from backend.crypto.rsa_manager import RSAManager
from backend.crypto.idea_manager import IDEAManager


@app.post("/api/groups/create")
async def api_groups_create(req: CreateGroupReq):
    """Cria um novo grupo e define o criador como admin."""
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
    """
    Adiciona um novo membro e recriptografa a chave IDEA atual do grupo
    para todos os membros (inclusive o novo).
    """
    from backend.crypto.idea_manager import IDEAManager
    from backend.crypto.rsa_manager import RSAManager

    db = SessionLocal()
    try:
        requester = verify_access_token(req.token)
        if not requester:
            raise HTTPException(status_code=401, detail="Token inválido.")

        group = db.query(Group).filter_by(name=req.group).first()
        user = db.query(User).filter_by(username=req.username).first()
        if not (group and user):
            raise HTTPException(status_code=404, detail="Grupo ou usuário não encontrado.")

        # 🔐 verifica admin
        admin = db.query(User).get(group.admin_id)
        if not admin or admin.username != requester:
            # log_event("ACCESS_DENIED", requester, f"Tentativa de adicionar membro ao grupo {req.group} sem ser admin.")

            raise HTTPException(status_code=403, detail="Apenas o admin pode adicionar membros.")

        # evita duplicação
        exists = db.query(GroupMember).filter_by(group_id=group.id, user_id=user.id).first()
        if exists:
            return {"status": "ok", "message": "Usuário já é membro."}

        # adiciona novo membro
        db.add(GroupMember(group_id=group.id, user_id=user.id))
        db.commit()

        # 🔄 gera nova chave IDEA e recriptografa
        idea = IDEAManager()
        nova_cek_bytes = bytes.fromhex(idea.get_chave_sessao_hex())

        membros = db.query(GroupMember).filter_by(group_id=group.id).all()
        for m in membros:
            membro_user = db.query(User).get(m.user_id)
            if membro_user and membro_user.public_key:
                cek_enc_b64 = RSAManager.cifrar_chave_sessao(
                    nova_cek_bytes, membro_user.public_key.decode()
                )
                # salva registro simbólico para histórico
                db.add(Message(
                    sender_id=admin.id,
                    receiver_id=membro_user.id,
                    group_id=group.id,
                    content_encrypted="(nova chave IDEA gerada)",
                    key_encrypted=cek_enc_b64,
                ))
        db.commit()

        return {
            "status": "ok",
            "message": f"{req.username} adicionado ao grupo {req.group}. Nova chave IDEA distribuída.",
        }
    finally:
        db.close()

# ======================================================
# 📋 LISTAR GRUPOS DO USUÁRIO
# ======================================================
@app.get("/api/groups/my")
async def api_groups_my(token: str):
    """Lista todos os grupos dos quais o usuário é membro."""
    db = SessionLocal()
    try:
        username = verify_access_token(token)
        if not username:
            raise HTTPException(status_code=401, detail="Token inválido.")

        user = db.query(User).filter_by(username=username).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuário não encontrado.")

        # junta Group com GroupMember pra listar todos os grupos do usuário
        groups = (
            db.query(Group)
            .join(GroupMember, Group.id == GroupMember.group_id)
            .filter(GroupMember.user_id == user.id)
            .all()
        )

        result = []
        for g in groups:
            is_admin = g.admin_id == user.id
            result.append({
                "id": g.id,
                "name": g.name,
                "is_admin": is_admin,
            })

        return {"groups": result}

    finally:
        db.close()


@app.post("/api/groups/remove_member")
async def api_groups_remove_member(req: RemoveMemberReq):
    """
    Remove um membro e gera uma nova chave IDEA para os membros restantes.
    """
    from backend.crypto.idea_manager import IDEAManager
    from backend.crypto.rsa_manager import RSAManager

    db = SessionLocal()
    try:
        requester = verify_access_token(req.token)
        if not requester:
            raise HTTPException(status_code=401, detail="Token inválido.")

        group = db.query(Group).filter_by(name=req.group).first()
        user = db.query(User).filter_by(username=req.username).first()
        if not (group and user):
            raise HTTPException(status_code=404, detail="Grupo ou usuário não encontrado.")

        # 🔐 apenas admin pode remover
        admin = db.query(User).get(group.admin_id)
        if not admin or admin.username != requester:
            raise HTTPException(status_code=403, detail="Apenas o admin pode remover membros.")

        gm = db.query(GroupMember).filter_by(group_id=group.id, user_id=user.id).first()
        if not gm:
            raise HTTPException(status_code=404, detail="Usuário não é membro do grupo.")

        db.delete(gm)
        db.commit()

        # 🔄 gera nova chave IDEA
        idea = IDEAManager()
        nova_cek_bytes = bytes.fromhex(idea.get_chave_sessao_hex())

        # 🔁 recriptografa a nova chave IDEA pra todos os membros restantes
        membros_restantes = db.query(GroupMember).filter_by(group_id=group.id).all()
        for m in membros_restantes:
            membro_user = db.query(User).get(m.user_id)
            if membro_user and membro_user.public_key:
                cek_enc_b64 = RSAManager.cifrar_chave_sessao(
                    nova_cek_bytes, membro_user.public_key.decode()
                )
                db.add(Message(
                    sender_id=admin.id,
                    receiver_id=membro_user.id,
                    group_id=group.id,
                    content_encrypted="(chave IDEA atualizada após remoção)",
                    key_encrypted=cek_enc_b64,
                ))
        db.commit()

        return {
            "status": "ok",
            "message": f"{req.username} removido de {req.group}. Nova chave IDEA distribuída.",
        }
    finally:
        db.close()


@app.post("/api/groups/send")
async def api_groups_send(req: Request):
    """Envia uma mensagem cifrada para todos os membros de um grupo."""
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
        idea = IDEAManager()

        # 🔐 Cifra a mensagem uma vez (para cada membro, cifra apenas o CEK com a pubkey dele)
        sample_user = db.query(User).first()
        cipher, _ = idea.cifrar_para_chat(
            texto_plano=content,
            remetente=sender_name,
            destinatario="grupo",
            chave_publica_destinatario_pem=sample_user.public_key.decode()
        )
        cek_bytes = bytes.fromhex(idea.get_chave_sessao_hex())

        for m in members:
            user = db.query(User).get(m.user_id)
            if not user or not user.public_key:
                continue
            pub = user.public_key.decode()
            cek_enc = RSAManager.cifrar_chave_sessao(cek_bytes, pub)

            msg = Message(
                sender_id=user_sender.id,
                receiver_id=user.id,
                group_id=group.id,
                content_encrypted=cipher,
                key_encrypted=cek_enc,
            )
            db.add(msg)

        db.commit()
        return {"status": "success"}
    finally:
        db.close()

@app.post("/api/groups/regenerate_key")
async def api_groups_regenerate_key(req: Request):
    """
    Regenera a chave IDEA do grupo (manual key rotation).
    Apenas o admin pode chamar.
    """
    from backend.crypto.idea_manager import IDEAManager
    from backend.crypto.rsa_manager import RSAManager

    db = SessionLocal()
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

        # 🔄 gera nova chave IDEA (nova CEK)
        idea = IDEAManager()
        nova_cek_bytes = bytes.fromhex(idea.get_chave_sessao_hex())

        membros = db.query(GroupMember).filter_by(group_id=group.id).all()
        for m in membros:
            membro_user = db.query(User).get(m.user_id)
            if membro_user and membro_user.public_key:
                cek_enc_b64 = RSAManager.cifrar_chave_sessao(
                    nova_cek_bytes, membro_user.public_key.decode()
                )
                db.add(Message(
                    sender_id=admin.id,
                    receiver_id=membro_user.id,
                    group_id=group.id,
                    content_encrypted="(chave IDEA regenerada manualmente pelo admin)",
                    key_encrypted=cek_enc_b64,
                ))

        db.commit()
        return {
            "status": "ok",
            "message": f"Nova chave IDEA regenerada para o grupo '{group_name}' e distribuída a todos os membros.",
        }

    finally:
        db.close()

@app.get("/api/groups/{group_name}/messages")
async def api_groups_messages(group_name: str, token: str):
    """Retorna as mensagens de um grupo decifradas para o usuário autenticado."""
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

        priv_path = f"keys/{user_name}_private.pem"
        with open(priv_path, "r") as f:
            private_key_pem = f.read()

        formatted = []
        for msg in msgs:
            sender = db.query(User).get(msg.sender_id)
            try:
                # ⚙️ Detecta mensagens administrativas e mostra texto fixo
                if msg.content_encrypted.startswith("("):
                    plain = "🔑 Atualização de segurança no grupo"
                else:
                    plain = IDEAManager().decifrar_do_chat(
                        packet=msg.content_encrypted,
                        cek_b64=msg.key_encrypted,
                        destinatario=user_name,
                        chave_privada_pem=private_key_pem,
                    )
            except Exception as e:
                print(f"[GROUP_DEC_ERR] {e}")
                plain = "(erro ao decifrar)"

            formatted.append({
                "id": msg.id,
                "from": sender.username if sender else "Desconhecido",
                "content": plain,
                "timestamp": str(msg.timestamp),
            })

        return {"messages": formatted}
    finally:
        db.close()

# ======================================================
# 📇 LISTAGEM DE USUÁRIOS E MEMBROS DE GRUPO
# ======================================================

@app.get("/api/users/all")
async def api_users_all():
    """Retorna todos os usuários cadastrados."""
    db = SessionLocal()
    try:
        users = db.query(User).all()
        return {"users": [u.username for u in users]}
    finally:
        db.close()


@app.get("/api/groups/{group_name}/members")
async def api_group_members(group_name: str, token: str):
    """Retorna os membros de um grupo e o admin."""
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

        return {
            "group": group_name,
            "admin": admin.username if admin else None,
            "members": member_list,
        }
    finally:
        db.close()

@app.post("/api/groups/leave")
async def api_groups_leave(req: Request):
    """
    Permite que um membro (inclusive o admin) saia do grupo.
    Se o admin sair, o cargo é transferido automaticamente
    para o membro mais antigo do grupo.
    """
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

        # verifica se é membro
        membership = db.query(GroupMember).filter_by(group_id=group.id, user_id=user.id).first()
        if not membership:
            raise HTTPException(status_code=404, detail="Usuário não é membro deste grupo.")

        # remove o membro
        db.delete(membership)
        db.commit()

        # caso o admin saia, transfere a liderança
        if group.admin_id == user.id:
            next_member = (
                db.query(GroupMember)
                .filter(GroupMember.group_id == group.id)
                .order_by(GroupMember.id.asc())  # mais antigo (menor ID)
                .first()
            )
            if next_member:
                group.admin_id = next_member.user_id
                db.commit()
                new_admin = db.query(User).get(next_member.user_id)
                msg = f"👑 {new_admin.username} agora é o novo admin de {group.name}."
            else:
                # se o último sair, apaga o grupo
                db.delete(group)
                db.commit()
                msg = f"🗑️ O grupo {group.name} foi excluído (sem membros restantes)."
        else:
            msg = f"✅ {user.username} saiu do grupo {group.name}."

        return {"status": "ok", "message": msg}

    finally:
        db.close()