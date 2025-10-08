"""
listener.py
-----------

Ouvinte assíncrono persistente para recepção de mensagens em tempo real no CipherTalk.
- Mantém um canal seguro TLS aberto com o servidor
- Usa `resume_session` para reautenticação JWT
- Salva localmente todas as mensagens recebidas como JSON
"""

import asyncio
import json
import os
import ssl
from datetime import datetime

os.makedirs("messages", exist_ok=True)


async def start_listener(username: str, token: str, host: str, port: int):
    """Mantém conexão segura para receber mensagens em tempo real."""
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    print(f"📡 Aguardando novas mensagens para {username}...\n")

    try:
        reader, writer = await asyncio.open_connection(host, port, ssl=ssl_context)

        # Sessão persistente via JWT
        init_payload = {"action": "resume_session", "token": token}
        writer.write((json.dumps(init_payload) + "\n").encode("utf-8"))
        await writer.drain()

        while True:
            data = await reader.readline()
            if not data:
                await asyncio.sleep(0.5)
                continue

            try:
                msg = json.loads(data.decode().strip())

                if not isinstance(msg, dict) or "from" not in msg:
                    continue

                sender = msg.get("from", "?")
                timestamp = msg.get("timestamp", datetime.utcnow().isoformat())

                filename = f"messages/{username}_{sender}_{timestamp.replace(':', '-')}.json"
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(msg, f, indent=4)

                print(f"📩 Nova mensagem recebida de {sender} ({timestamp})")

            except json.JSONDecodeError:
                print(f"⚠️ Pacote recebido inválido (não é JSON).")

    except Exception as e:
        print(f"💥 Listener encerrado: {e}")
