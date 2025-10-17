from backend.crypto.idea import IDEA
from backend.crypto.rsa_manager import RSAManager
from backend.utils.logger_config import crypto_logger

class IDEAManager:
    def __init__(self):
        self.idea = IDEA()
    
    def cifrar_para_chat(self, texto_plano: str, remetente: str, destinatario: str, chave_publica_destinatario_pem: str):
        """Cifra uma mensagem para o chat usando IDEA + RSA"""
        
        # LOG: Início do processo de envio
        crypto_logger.logger.info("=== INICIO PROCESSO DE ENVIO ===")
        crypto_logger.logger.info(f"Remetente: {remetente}")
        crypto_logger.logger.info(f"Destinatario: {destinatario}")
        crypto_logger.logger.info(f"Mensagem Original: {texto_plano}")
        
        # A chave de sessão já foi gerada automaticamente no __init__ do IDEA
        chave_sessao_hex = self.idea.get_chave_sessao_hex()
        crypto_logger.logger.info(f"Chave de Sessao IDEA: {chave_sessao_hex}")
        
        # Cifrar a mensagem com IDEA
        resultado = self.idea.cifrar_cbc(texto_plano)
        crypto_logger.logger.info(f"Mensagem Criptografada (IDEA-CBC): {resultado}")
        
        # Converter chave de sessão para bytes
        chave_sessao_bytes = bytes.fromhex(chave_sessao_hex)
        
        # Cifrar a chave de sessão com RSA
        chave_sessao_cripto_b64 = RSAManager.cifrar_chave_sessao(chave_sessao_bytes, chave_publica_destinatario_pem)
        crypto_logger.logger.info(f"Chave de Sessao Criptografada (RSA): {chave_sessao_cripto_b64[:50]}...")
        
        crypto_logger.logger.info("=== FIM PROCESSO DE ENVIO ===")
        
        return resultado, chave_sessao_cripto_b64
    
    def decifrar_do_chat(self, packet: str, cek_b64: str, destinatario: str, chave_privada_pem: str):
        #Decifra uma mensagem do chat usando IDEA + RSA
        
        crypto_logger.logger.info("=== INICIO PROCESSO DE RECEBIMENTO ===")
        crypto_logger.logger.info(f"Destinatario: {destinatario}")
        crypto_logger.logger.info(f"Mensagem Criptografada Recebida: {packet}")
        crypto_logger.logger.info(f"Chave de Sessao Criptografada Recebida: {cek_b64[:50]}...")
        
        # Decifrar a chave de sessão com RSA
        chave_sessao_bytes = RSAManager.decifrar_chave_sessao(cek_b64, chave_privada_pem)
        chave_sessao_hex = chave_sessao_bytes.hex().upper()
        crypto_logger.logger.info(f"Chave de Sessao Decifrada (RSA): {chave_sessao_hex}")
        
        # Configurar IDEA com a chave de sessão decifrada
        chave_sessao_int = int.from_bytes(chave_sessao_bytes, 'big')
        self.idea = IDEA(chave_sessao_int)
        
        # Decifrar a mensagem com IDEA
        texto_decifrado = self.idea.decifrar_cbc(packet)
        crypto_logger.logger.info(f"Mensagem Decifrada: {texto_decifrado}")
        
        crypto_logger.logger.info("=== FIM PROCESSO DE RECEBIMENTO ===")
        
        return texto_decifrado
    
    def get_chave_sessao_hex(self):
        #Retorna a chave de sessão atual em hexadecimal
        return self.idea.get_chave_sessao_hex()


    @staticmethod
    def gerar_chave() -> bytes:
        """Gera chave IDEA de 128 bits e loga fingerprint SHA256."""
        import os
        key_bytes = os.urandom(16)
        from hashlib import sha256
        from backend.utils.logger_config import database_logger as dblog

        fingerprint = sha256(key_bytes).hexdigest()
        dblog.info(f"[GENERATE_IDEA_KEY] Chave IDEA gerada | SHA256={fingerprint}")
        return key_bytes

