import logging
import datetime
import os
from typing import Optional

class CryptoLogger:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(CryptoLogger, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if not self._initialized:
            self.logger = logging.getLogger('crypto_chat')
            self.logger.setLevel(logging.INFO)
            
            if not os.path.exists('logs'):
                os.makedirs('logs')
            
            # File handler
            fh = logging.FileHandler(f'logs/crypto_chat_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
            fh.setLevel(logging.INFO)
            
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)
            
            formatter = logging.Formatter('%(asctime)s - %(message)s')
            fh.setFormatter(formatter)
            ch.setFormatter(formatter)
            
            self.logger.addHandler(fh)
            self.logger.addHandler(ch)
            self._initialized = True
    
    def log_usuario_criado(self, nome: str, chave_publica: str, chave_privada: str):
    #Log quando um usuário é criado
        self.logger.info("=== NOVO USUARIO CRIADO ===")
        self.logger.info(f"Usuario: {nome}")
        self.logger.info(f"Chave Publica (RSA): {chave_publica[:50]}...")
        self.logger.info(f"Chave Privada (RSA): {chave_privada[:50]}...")
        self.logger.info("=" * 50)
    
    def log_envio_mensagem(self, remetente: str, destinatario: str, mensagem_original: str, 
                          chave_sessao_hex: str, chave_sessao_criptografada: str,
                          mensagem_criptografada: str, chave_publica_destinatario: str):
    #Log quando uma mensagem é enviada
        self.logger.info("=== ENVIO DE MENSAGEM ===")
        self.logger.info(f"De: {remetente} | Para: {destinatario}")
        self.logger.info(f"Mensagem Original: {mensagem_original}")
        self.logger.info(f"Chave de Sessao (IDEA): {chave_sessao_hex}")
        self.logger.info(f"Chave de Sessao Criptografada: {chave_sessao_criptografada[:50]}...")
        self.logger.info(f"Mensagem Criptografada: {mensagem_criptografada}")
        self.logger.info("=" * 50)
    
    def log_recebimento_mensagem(self, destinatario: str, remetente: str,
                                mensagem_criptografada: str, chave_sessao_criptografada: str,
                                chave_sessao_decifrada: str, mensagem_decifrada: str,
                                chave_privada_destinatario: str):
        #Log quando uma mensagem é recebida
        self.logger.info("=== RECEBIMENTO DE MENSAGEM ===")
        self.logger.info(f"Para: {destinatario} | De: {remetente}")
        self.logger.info(f"Mensagem Criptografada: {mensagem_criptografada}")
        self.logger.info(f"Chave de Sessao Criptografada: {chave_sessao_criptografada[:50]}...")
        self.logger.info(f"Chave de Sessao Decifrada: {chave_sessao_decifrada}")
        self.logger.info(f"Mensagem Decifrada: {mensagem_decifrada}")
        self.logger.info("=" * 50)
    
    def log_operacao_idea(self, operacao: str, chave_sessao: str, iv: Optional[str] = None,
                         bloco_entrada: Optional[str] = None, bloco_saida: Optional[str] = None):
        #Log de operações IDEA internas
        self.logger.info(f"IDEA {operacao.upper()}")
        self.logger.info(f"Chave de Sessao: {chave_sessao}")
        if iv:
            self.logger.info(f"IV: {iv}")
        if bloco_entrada:
            self.logger.info(f"Bloco Entrada: {bloco_entrada}")
        if bloco_saida:
            self.logger.info(f"Bloco Saida: {bloco_saida}")
        self.logger.info("-" * 30)

crypto_logger = CryptoLogger()