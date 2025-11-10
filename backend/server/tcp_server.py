import asyncio
import json
from contextlib import asynccontextmanager
from typing import Dict, Optional

from backend.database.connection import SessionLocal
from backend.utils.logger_config import server_logger as log
from backend.server.handlers import (
    handle_register,
    handle_login,
    handle_list_users,
    handle_send_message,
    handle_send_group_message,
    handle_resume_session,
    USERS_LOCK,
)

# Mapa global de usuários online -> writer do socket (1 conexão por usuário)
ONLINE_USERS: Dict[str, asyncio.StreamWriter] = {}

# Limites defensivos para o framing por linha (JSON por linha)
MAX_LINE_BYTES = 1 << 16   # 64 KiB por linha
READ_TIMEOUT = 0           # 0 = sem timeout; ajuste se quiser expulsar conexões ociosas


@asynccontextmanager
async def db_session():
    """Cria/fecha uma sessão do banco para cada processamento de mensagem."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def _readline(reader: asyncio.StreamReader) -> Optional[bytes]:
    """Lê uma linha do socket com limites defensivos opcionais."""
    if READ_TIMEOUT > 0:
        line = await asyncio.wait_for(reader.readline(), timeout=READ_TIMEOUT)
    else:
        line = await reader.readline()

    if not line:
        return None
    if len(line) > MAX_LINE_BYTES:
        # descarta para evitar flood / mensagens malformadas gigantes
        return None
    return line


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """
    Loop principal por conexão TCP/TLS.
    Recebe um JSON por linha, roteia pelo 'action' e mantém ONLINE_USERS atualizado.
    """
    peer = writer.get_extra_info("peername")
    log.info(f"[TCP] Nova conexão {peer}")
    username_bound: Optional[str] = None

    try:
        while True:
            line = await _readline(reader)
            if not line:
                break

            # Decodifica JSON de uma linha (protocolo line-delimited JSON)
            try:
                message = json.loads(line.decode(errors="ignore").strip())
            except Exception:
                log.warning(f"[TCP] JSON inválido de {peer}: {line!r}")
                continue

            action = message.get("action")

            # Ações leves, sem DB
            if action == "ping":
                try:
                    writer.write(b'{"action":"pong"}\n')
                    await writer.drain()
                except Exception:
                    break
                continue

            async with db_session() as db:
                if action == "register":
                    await handle_register(db, writer, message)

                elif action == "login":
                    username, _token = await handle_login(db, writer, message, ONLINE_USERS)
                    if username:
                        username_bound = username  # vincula para cleanup

                elif action == "list_users":
                    await handle_list_users(db, writer, message, ONLINE_USERS)

                elif action == "send_message":
                    await handle_send_message(db, message, ONLINE_USERS)

                elif action == "send_group_message":
                    await handle_send_group_message(db, message, ONLINE_USERS)

                elif action == "resume_session":
                    # Reanexa o writer do socket ao usuário autenticado (ACK é enviado no handler)
                    await handle_resume_session(db, writer, message, ONLINE_USERS)
                    # vincula username à conexão para cleanup automático
                    try:
                        from backend.auth.auth_jwt import verify_access_token
                        username_bound = verify_access_token(message.get("token"))
                    except Exception:
                        pass

                else:
                    writer.write(b'{"status":"error","reason":"unknown_action"}\n')
                    await writer.drain()

    except asyncio.CancelledError:
        # encerramento normal do servidor
        pass
    except Exception as e:
        log.error(f"[TCP_ERR] {peer}: {e}")
    finally:
        # cleanup de ONLINE_USERS quando o socket cai
        if username_bound:
            async with USERS_LOCK:
                curr = ONLINE_USERS.get(username_bound)
                if curr is writer:
                    ONLINE_USERS.pop(username_bound, None)
                    log.info(f"[TCP] {username_bound} desconectado (cleanup).")

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def main(host: str = "0.0.0.0", port: int = 8888, ssl_context=None):
    """
    Sobe o servidor TCP. Passe um ssl.SSLContext válido para TLS.
    Ex.: asyncio.run(main(ssl_context=meu_contexto_tls))
    """
    server = await asyncio.start_server(handle_client, host, port, ssl=ssl_context)
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    log.info(f"[TCP] Servidor escutando em {addrs}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass