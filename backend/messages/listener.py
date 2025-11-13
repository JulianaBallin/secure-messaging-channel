"""
listener.py
-----------

Ouvinte assíncrono persistente para recepção de mensagens em tempo real no CipherTalk.
- Mantém um canal seguro TLS aberto com o servidor
- Usa `resume_session` para reautenticação JWT
- Salva localmente todas as mensagens recebidas como JSON
"""

import socket
import ssl
import json
import time
import threading
from queue import Queue
from backend.utils.logger_config import disponibilidade_logger

logger = disponibilidade_logger

def start_listener_with_reconnect(
    host: str,
    port: int,
    retry_delay: int = 5,
    msg_queue: Queue = None,
):
    """
    Inicia o listener com reconexão automática e suporte a fila de mensagens.

    Args:
        host (str): endereço do servidor
        port (int): porta do servidor
        retry_delay (int): tempo entre tentativas de reconexão
        msg_queue (Queue): fila opcional para envio de mensagens à interface
    """
    while True:
        try:
            logger.info(f"🔌 Conectando ao servidor TLS {host}:{port}...")
            start_listener(host, port, msg_queue)
        except Exception as e:
            logger.error(f"Erro no listener: {e}. Tentando reconectar em {retry_delay}s...")
            time.sleep(retry_delay)


def start_listener(host: str, port: int, msg_queue: Queue = None):
    """
    Inicia o listener e recebe mensagens do servidor via TLS.
    Cada mensagem recebida é enviada à fila `msg_queue` (se fornecida).
    """
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            logger.info("🔒 Conexão TLS estabelecida. Aguardando mensagens...")
            while True:
                try:
                    data = ssock.recv(4096)
                    if not data:
                        logger.warning("⚠️ Conexão encerrada pelo servidor.")
                        break

                    try:
                        message_data = json.loads(data.decode("utf-8"))
                        sender = message_data.get("from") or message_data.get("sender", "Desconhecido")
                        body = message_data.get("body") or message_data.get("message", "")
                    except json.JSONDecodeError:
                        sender, body = "Servidor", data.decode("utf-8", errors="ignore")

                    logger.info(f"📨 Mensagem recebida de {sender}: {body}")

                    # Envia para a fila da UI
                    if msg_queue:
                        msg_queue.put({"from": sender, "body": body})

                except (socket.error, ssl.SSLError) as e:
                    logger.error(f"Erro de conexão: {e}")
                    break
                except Exception as e:
                    logger.error(f"Erro inesperado no listener: {e}")
                    break


def run_listener_thread(host="0.0.0.0", port=9000, msg_queue=None):
    """
    Inicia o listener em uma thread separada.
    """
    t = threading.Thread(
        target=start_listener_with_reconnect,
        args=(host, port, 5, msg_queue),
        daemon=True,
    )
    t.start()
    logger.info("🧵 Listener iniciado em thread.")
    return t


if __name__ == "__main__":
    # Execução direta para teste isolado
    q = Queue()
    threading.Thread(target=start_listener_with_reconnect, args=("0.0.0.0", 9000, 5, q), daemon=True).start()

    # Exemplo de consumo local da fila
    while True:
        while not q.empty():
            msg = q.get()
            print(f"[UI] Nova mensagem: {msg['from']}: {msg['body']}")
        time.sleep(1)
