"""
members.py — CRUD e controle de membros de grupos
-------------------------------------------------
Inclui:
- Distribuição de CEKs existentes a novos membros
- Rotação automática de CEKs ao remover membros
- Auditoria criptográfica com fingerprint SHA256 das CEKs
"""

import os
import base64
from datetime import datetime, timezone, timedelta
from hashlib import sha256
from sqlalchemy import text
from backend.auth.models import GroupMember, User, Group, SessionKey, Message
from backend.utils.logger_config import database_logger as dblog, group_chat_logger
from backend.utils.db_utils import safe_db_operation
from backend.crypto.idea_manager import IDEAManager
from backend.crypto.rsa_manager import RSAManager
from backend.utils.logger_config import log_event
from backend.utils.log_formatter import format_box, truncate_hex

manaus_tz = timezone(timedelta(hours=-4))

# ======================================================
# ➕ Adicionar membro e distribuir CEK existente
# ======================================================
@safe_db_operation
def add_member(db, username: str, group_name: str):
    """Adiciona usuário ao grupo e distribui CEK existente (com fingerprint de auditoria)."""
    user = db.query(User).filter_by(username=username).first()
    group = db.query(Group).filter_by(name=group_name).first()
    if not user or not group:
        raise ValueError("Usuário ou grupo não encontrado.")

    # Log: Adicionando membro
    group_chat_logger.info("\n")
    group_chat_logger.info(
        format_box(
            title=f"➕ ADICIONANDO MEMBRO: {username} → Grupo: {group_name}",
            content=[f"📝 {username} só verá mensagens enviadas APÓS {datetime.now(manaus_tz)}"],
            width=70,
            char="=",
        )
    )

    # 1️⃣ Cria vínculo de membro
    member = GroupMember(user_id=user.id, group_id=group.id)
    db.add(member)
    db.commit()
    dblog.info(f"[ADD_MEMBER] {username} → {group_name}")

    # 2️⃣ Busca CEK atual (última session_key) - para mostrar chave antiga
    session_entry = (
        db.query(SessionKey)
        .filter_by(entity_type="group", entity_id=group.id)
        .order_by(SessionKey.created_at.desc())
        .first()
    )

    # Busca chave antiga (se existir) através de uma mensagem do admin
    admin_user = db.query(User).get(group.admin_id)
    chave_antiga_hex = None
    if admin_user:
        try:
            # 🔑 Ler chave privada de backend/keys/{username}/
            BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            admin_keys_dir = os.path.join(BACKEND_DIR, "keys", admin_user.username)
            admin_priv_path = os.path.join(admin_keys_dir, f"{admin_user.username}_private.pem")
            with open(admin_priv_path, "r") as f:
                admin_priv_key = f.read()

            admin_msg_antiga = (
                db.query(Message)
                .filter_by(group_id=group.id, receiver_id=admin_user.id)
                .filter(Message.key_encrypted.isnot(None))
                .order_by(Message.timestamp.desc())
                .first()
            )

            if admin_msg_antiga:
                try:
                    cek_antiga_bytes = RSAManager.decifrar_chave_sessao(admin_msg_antiga.key_encrypted, admin_priv_key)
                    chave_antiga_hex = cek_antiga_bytes.hex().upper()
                except Exception:
                    pass
        except Exception:
            pass

    # 3️⃣ Gera nova CEK (rotação de chave ao adicionar membro)
    group_chat_logger.info(
        format_box(
            title=f"🔑 ROTAÇÃO DE CHAVE DE SESSÃO: Grupo {group_name}",
            content=[],
            width=70,
            char="=",
        )
    )

    nova_cek = IDEAManager.gerar_chave()
    nova_cek_hex = nova_cek.hex().upper() if isinstance(nova_cek, bytes) else bytes.fromhex(nova_cek).hex().upper()
    nova_cek_truncada = truncate_hex(nova_cek_hex, 8, 8)

    if chave_antiga_hex:
        chave_antiga_truncada = truncate_hex(chave_antiga_hex, 8, 8)
        group_chat_logger.info(f"🔑 [CHAVE_ANTIGA] Chave de sessão anterior: {chave_antiga_truncada}")
        group_chat_logger.info(f"🔄 ROTAÇÃO: Chave antiga → Nova chave gerada")
    else:
        group_chat_logger.info(f"🔑 [CHAVE_ANTIGA] Nenhuma (primeira chave do grupo)")
    
    group_chat_logger.info(f"🔑 [CHAVE_NOVA] Chave de sessão gerada (atual): {nova_cek_truncada}")
    group_chat_logger.info(f"{'='*70}")

    # 4️⃣ Fingerprint SHA256 da CEK (antes de cifrar)
    cek_fingerprint = sha256(nova_cek if isinstance(nova_cek, bytes) else nova_cek.encode()).hexdigest()
    dblog.info(f"[CEK_FINGERPRINT] Grupo={group_name} | SHA256={cek_fingerprint}")

    # 5️⃣ Distribui nova CEK para todos os membros (incluindo o novo)
    membros = db.query(GroupMember).filter_by(group_id=group.id).all()
    
    group_chat_logger.info(
        format_box(
            title=f"🔄 DISTRIBUINDO NOVA CEK: Grupo {group_name} → {len(membros)} membros",
            content=[f"🔑 CEK ID: {nova_cek_truncada}"],
            width=70,
            char="=",
        )
    )

    for m in membros:
        membro_user = db.query(User).get(m.user_id)
        if not membro_user or not membro_user.public_key:
            continue

        public_key_dest = (
            membro_user.public_key.decode() if isinstance(membro_user.public_key, bytes) else membro_user.public_key
        )
        
        chave_publica_fingerprint_full = sha256(public_key_dest.encode() if isinstance(public_key_dest, str) else public_key_dest).hexdigest()
        chave_publica_fingerprint = truncate_hex(chave_publica_fingerprint_full, 8, 8)
        
        group_chat_logger.info(
            format_box(
                title=f"📦 WRAP CEK: Grupo {group_name} → {membro_user.username}",
                content=[
                    f"🔑 [1] CEK a ser wrapada: {nova_cek_truncada}",
                    f"🔐 [2] Chave pública RSA de {membro_user.username} (Fingerprint: {chave_publica_fingerprint})",
                ],
                width=70,
                char="-",
            )
        )
        
        cek_cifrada = RSAManager.cifrar_chave_sessao(nova_cek, public_key_dest)
        cek_cifrada_full = cek_cifrada if isinstance(cek_cifrada, str) else base64.b64encode(cek_cifrada).decode()
        cek_enc_truncada = truncate_hex(cek_cifrada_full, 12, 12)
        
        group_chat_logger.info(f"🔒 [3] CEK wrapada (RSA) para {membro_user.username}: {cek_enc_truncada}")
        group_chat_logger.info(f"📨 [4] {membro_user.username} receberá CEK wrapada com sua chave pública RSA")
        group_chat_logger.info(f"{'-'*70}")

        # 🔒 Converte Base64 → bytes se necessário
        if isinstance(cek_cifrada, str):
            cek_cifrada_bytes = base64.b64decode(cek_cifrada)
        else:
            cek_cifrada_bytes = cek_cifrada

        # Armazena CEK cifrada + fingerprint
        db.execute(
            text("INSERT OR REPLACE INTO session_keys (entity_type, entity_id, cek_encrypted, cek_fingerprint, created_at) VALUES (:entity_type, :entity_id, :cek_encrypted, :cek_fingerprint, :created_at)"),
            {
                "entity_type": "group",
                "entity_id": group.id,
                "cek_encrypted": cek_cifrada_bytes,
                "cek_fingerprint": cek_fingerprint,
                "created_at": datetime.now(manaus_tz),
            },
        )

        # Cria mensagem de atualização de chave
        db.add(
            Message(
                sender_id=admin_user.id if admin_user else None,
                receiver_id=membro_user.id,
                group_id=group.id,
                content_encrypted="(nova chave IDEA gerada)",
                key_encrypted=cek_cifrada_full,
            )
        )

    db.commit()

    group_chat_logger.info(
        format_box(
            title=f"✅ Distribuição concluída: {len(membros)} membros receberam a nova CEK",
            content=[f"🔑 CEK ID: {nova_cek_truncada}"],
            width=70,
            char="=",
        )
    )
    group_chat_logger.info("\n")
    dblog.info(f"[GROUP_CEK_SHARE] CEK do grupo {group_name} distribuída a {username}.")
    return member


# ======================================================
# ➖ Remover membro e rotacionar CEK
# ======================================================
@safe_db_operation
def remove_member(db, username: str, group_name: str):
    """Remove membro do grupo, transfere admin se necessário e rotaciona CEK."""
    # 🔍 Localiza membro e grupo
    member = (
        db.query(GroupMember)
        .join(Group)
        .filter(Group.name == group_name, GroupMember.user.has(username=username))
        .first()
    )
    if not member:
        raise ValueError("Membro ou grupo não encontrado.")

    group = db.query(Group).filter_by(name=group_name).first()
    if not group:
        raise ValueError("Grupo não encontrado.")

    # Verifica se é admin ANTES de remover
    user_removido = db.query(User).filter_by(username=username).first()
    is_admin = user_removido and group.admin_id == user_removido.id

    # Log: Removendo membro (só aparece se não foi chamado via leave)
    if not getattr(remove_member, '_skip_remove_log', False):
        group_chat_logger.info("\n")
        group_chat_logger.info(
            format_box(
                title=f"➖ REMOVENDO MEMBRO: {username} foi removido do Grupo: {group_name}",
                content=[],
                width=70,
                char="=",
            )
        )

    # Busca chave antiga antes de remover (usa admin atual)
    admin_user = db.query(User).get(group.admin_id)
    chave_antiga_hex = None
    if admin_user:
        try:
            # 🔑 Ler chave privada de backend/keys/{username}/
            BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            admin_keys_dir = os.path.join(BACKEND_DIR, "keys", admin_user.username)
            admin_priv_path = os.path.join(admin_keys_dir, f"{admin_user.username}_private.pem")
            with open(admin_priv_path, "r") as f:
                admin_priv_key = f.read()

            admin_msg_antiga = (
                db.query(Message)
                .filter_by(group_id=group.id, receiver_id=admin_user.id)
                .filter(Message.key_encrypted.isnot(None))
                .order_by(Message.timestamp.desc())
                .first()
            )

            if admin_msg_antiga:
                try:
                    cek_antiga_bytes = RSAManager.decifrar_chave_sessao(admin_msg_antiga.key_encrypted, admin_priv_key)
                    chave_antiga_hex = cek_antiga_bytes.hex().upper()
                except Exception:
                    pass
        except Exception:
            pass

    # ⚙️ Remove o membro
    db.delete(member)
    db.commit()

    # Remove mensagens do membro removido
    if user_removido:
        db.query(Message).filter_by(group_id=group.id, receiver_id=user_removido.id).delete()
        db.query(Message).filter_by(group_id=group.id, sender_id=user_removido.id).delete()
        db.commit()

    dblog.info(f"[REMOVE_MEMBER] {username} removido do grupo {group_name}")

    # 🔄 Recarrega o grupo para obter dados atualizados
    db.refresh(group)
    
    # 🔎 Lista membros ativos APÓS a remoção (faz nova query para garantir dados atualizados)
    membros_ativos_query = (
        db.query(User)
        .join(GroupMember, GroupMember.user_id == User.id)
        .filter(GroupMember.group_id == group.id)
        .all()
    )
    
    if not membros_ativos_query:
        group_chat_logger.info(
            format_box(
                title=f"🗑️ GRUPO VAZIO: Grupo {group_name} será deletado (sem membros restantes)",
                content=[],
                width=70,
                char="=",
            )
        )
        group_chat_logger.info("\n")
        db.delete(group)
        db.commit()
        dblog.warning(f"[ROTATION_ABORT] Grupo {group_name} sem membros ativos - grupo deletado.")
        return

    # 👑 Se o admin atual foi removido, transfere para o membro mais antigo
    novo_admin = None
    if is_admin:
        group_chat_logger.info(
            format_box(
                title=f"👑 ADMIN REMOVIDO: {username} era admin do grupo {group_name}",
                content=[],
                width=70,
                char="=",
            )
        )

        novo_admin_entry = (
            db.query(GroupMember)
            .filter_by(group_id=group.id)
            .order_by(GroupMember.joined_at.asc())
            .first()
        )

        if novo_admin_entry:
            novo_admin = db.query(User).get(novo_admin_entry.user_id)
            if novo_admin:
                group.admin_id = novo_admin.id
                db.commit()
                # Recarrega o grupo após atualizar admin_id
                db.refresh(group)
                group_chat_logger.info(f"✅ Novo admin: {novo_admin.username} promovido a admin do grupo {group_name}")
                log_event("ADMIN_CHANGE", novo_admin.username, f"Promovido a admin do grupo {group_name}")
            else:
                group_chat_logger.warning(f"⚠️ Não foi possível encontrar o novo admin para o grupo {group_name}.")
                dblog.warning(f"[NO_ADMIN_CANDIDATE] Grupo {group_name} ficou sem admin válido.")
        else:
            group_chat_logger.warning(f"⚠️ Grupo {group_name} ficou sem membros elegíveis para admin.")
            dblog.warning(f"[NO_ADMIN_CANDIDATE] Grupo {group_name} ficou sem membros elegíveis para admin.")
        
        group_chat_logger.info(f"{'='*70}")
        
        # Atualiza admin_user para o novo admin (ou mantém o atual se não houver novo)
        admin_user = novo_admin if novo_admin else admin_user

    # Se não há admin_user válido, não pode continuar com a rotação
    if not admin_user:
        group_chat_logger.error(f"❌ Erro: Grupo {group_name} não tem admin válido. Não é possível rotacionar CEK.")
        dblog.error(f"[ROTATION_FAIL] Grupo {group_name} sem admin válido após remoção.")
        return

    # 🔁 Rotaciona CEK para os membros restantes
    group_chat_logger.info(
        format_box(
            title=f"🔑 ROTAÇÃO DE CHAVE DE SESSÃO: Grupo {group_name}",
            content=[],
            width=70,
            char="=",
        )
    )

    nova_cek = IDEAManager.gerar_chave()
    nova_cek_hex = nova_cek.hex().upper() if isinstance(nova_cek, bytes) else bytes.fromhex(nova_cek).hex().upper()
    nova_cek_truncada = truncate_hex(nova_cek_hex, 8, 8)

    if chave_antiga_hex:
        chave_antiga_truncada = truncate_hex(chave_antiga_hex, 8, 8)
        group_chat_logger.info(f"🔑 [CHAVE_ANTIGA] Chave de sessão anterior: {chave_antiga_truncada}")
        group_chat_logger.info(f"🔄 ROTAÇÃO: Chave antiga → Nova chave gerada")
    else:
        group_chat_logger.info(f"🔑 [CHAVE_ANTIGA] Não foi possível recuperar")
    
    group_chat_logger.info(f"🔑 [CHAVE_NOVA] Chave de sessão gerada (atual): {nova_cek_truncada}")
    group_chat_logger.info(f"{'='*70}")

    cek_fingerprint = sha256(
        nova_cek if isinstance(nova_cek, bytes) else nova_cek.encode()
    ).hexdigest()
    log_event("CEK_ROTATION", admin_user.username,
          f"Grupo={group_name} | SHA256={cek_fingerprint}")

    group_chat_logger.info(
        format_box(
            title=f"🔄 DISTRIBUINDO NOVA CEK: Grupo {group_name} → {len(membros_ativos_query)} membros restantes",
            content=[f"🔑 CEK ID: {nova_cek_truncada}"],
            width=70,
            char="=",
        )
    )

    for membro in membros_ativos_query:
        if not membro.public_key:
            continue
            
        public_key_dest = (
            membro.public_key.decode() if isinstance(membro.public_key, bytes) else membro.public_key
        )
        
        chave_publica_fingerprint_full = sha256(public_key_dest.encode() if isinstance(public_key_dest, str) else public_key_dest).hexdigest()
        chave_publica_fingerprint = truncate_hex(chave_publica_fingerprint_full, 8, 8)
        
        group_chat_logger.info(
            format_box(
                title=f"📦 WRAP CEK: Grupo {group_name} → {membro.username}",
                content=[
                    f"🔑 [1] CEK a ser wrapada: {nova_cek_truncada}",
                    f"🔐 [2] Chave pública RSA de {membro.username} (Fingerprint: {chave_publica_fingerprint})",
                ],
                width=70,
                char="-",
            )
        )
        
        cek_cifrada = RSAManager.cifrar_chave_sessao(nova_cek, public_key_dest)
        cek_cifrada_full = cek_cifrada if isinstance(cek_cifrada, str) else base64.b64encode(cek_cifrada).decode()
        cek_enc_truncada = truncate_hex(cek_cifrada_full, 12, 12)
        
        group_chat_logger.info(f"🔒 [3] CEK wrapada (RSA) para {membro.username}: {cek_enc_truncada}")
        group_chat_logger.info(f"📨 [4] {membro.username} receberá CEK wrapada com sua chave pública RSA")
        group_chat_logger.info(f"{'-'*70}")

        if isinstance(cek_cifrada, str):
            cek_cifrada_bytes = base64.b64decode(cek_cifrada)
        else:
            cek_cifrada_bytes = cek_cifrada

        db.execute(
            text("INSERT OR REPLACE INTO session_keys (entity_type, entity_id, cek_encrypted, cek_fingerprint, created_at) VALUES (:entity_type, :entity_id, :cek_encrypted, :cek_fingerprint, :created_at)"),
            {
                "entity_type": "group",
                "entity_id": group.id,
                "cek_encrypted": cek_cifrada_bytes,
                "cek_fingerprint": cek_fingerprint,
                "created_at": datetime.now(manaus_tz),
            },
        )

        # Cria mensagem de atualização de chave
        db.add(
            Message(
                sender_id=admin_user.id,
                receiver_id=membro.id,
                group_id=group.id,
                content_encrypted="(nova chave IDEA gerada após remoção)",
                key_encrypted=cek_cifrada_full,
            )
        )

    db.commit()

    group_chat_logger.info(
        format_box(
            title=f"✅ Redistribuição concluída: {len(membros_ativos_query)} membros receberam a nova CEK",
            content=[f"🔑 CEK ID: {nova_cek_truncada}"],
            width=70,
            char="=",
        )
    )
    group_chat_logger.info("\n")
    dblog.info(f"[GROUP_CEK_ROTATION_DONE] CEK rotacionada e distribuída após remoção de {username}.")


# ======================================================
# 👥 Listar membros
# ======================================================
def list_members(db, group_name: str):
    """Retorna lista dos nomes dos membros de um grupo."""
    group = db.query(Group).filter_by(name=group_name).first()
    if not group:
        return []
    members = db.query(GroupMember).filter_by(group_id=group.id).all()
    return [db.query(User).get(m.user_id).username for m in members]
