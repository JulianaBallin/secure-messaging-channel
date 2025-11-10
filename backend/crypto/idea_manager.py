from backend.crypto.idea import IDEA
from backend.crypto.rsa_manager import RSAManager
from backend.utils.logger_config import crypto_logger, individual_chat_logger, group_chat_logger
from backend.utils.log_formatter import format_box, truncate_hex
from hashlib import sha256

class IDEAManager:
    def __init__(self):
        self.idea = IDEA()
    
    def cifrar_para_chat(self, texto_plano: str, remetente: str, destinatario: str, chave_publica_destinatario_pem: str, is_group: bool = False, log_enabled: bool = True, step_counter: list = None):
        """Cifra uma mensagem para o chat usando IDEA + RSA"""
        
        logger = group_chat_logger if is_group else individual_chat_logger
        
        # Inicializa contador se não fornecido (numeração linear contínua)
        if step_counter is None:
            step_counter = [1]
        
        if log_enabled:
            if not is_group:
                # Para chat individual, cria box de envio aqui
                logger.info(format_box(
                    title=f"ENVIANDO MENSAGEM: {remetente} → {destinatario}",
                    content=[],
                    width=70,
                    char="="
                ))
            # Para grupos, o box é criado no adapter_api antes de chamar esta função
        
        # 1. Gerar CEK + IV
        chave_sessao_hex = self.idea.get_chave_sessao_hex()
        if log_enabled:
            cek_truncada = truncate_hex(chave_sessao_hex, 8, 8)
            logger.info(f"[{step_counter[0]}] Gerando CEK + IV (CEK ID: {cek_truncada})")
            step_counter[0] += 1
        
        # 2. Mostrar mensagem original
        if log_enabled:
            logger.info(f"[{step_counter[0]}] Mensagem original: '{texto_plano}'")
            step_counter[0] += 1
        
        # 3. Criptografar mensagem UMA ÚNICA VEZ (IDEA/CBC)
        resultado = self.idea.cifrar_cbc(texto_plano)
        mensagem_cifrada_hex, iv_hex = resultado.split(':')
        if log_enabled:
            # Mensagem criptografada: truncada para reduzir exposição
            cipher_truncado = truncate_hex(mensagem_cifrada_hex, 8, 8)
            iv_truncado = truncate_hex(iv_hex, 8, 8)
            logger.info(f"[{step_counter[0]}] Mensagem criptografada (IDEA/CBC) - Ciphertext: {cipher_truncado}, IV: {iv_truncado}")
            step_counter[0] += 1
            if is_group:
                logger.info(f"[{step_counter[0]}] Mensagem criptografada UMA VEZ (será distribuída para todos os membros)")
                step_counter[0] += 1
        
        # 4. Log de obtenção de chave pública (para chat individual apenas)
        # Para grupos, o log de obtenção de chaves públicas é feito no adapter_api DEPOIS da criptografia
        if not is_group and log_enabled:
            chave_publica_fingerprint = truncate_hex(sha256(chave_publica_destinatario_pem.encode()).hexdigest(), 8, 8)
            logger.info(f"[{step_counter[0]}] {remetente} obteve chave pública RSA de {destinatario} (Fingerprint: {chave_publica_fingerprint})")
            step_counter[0] += 1
        
        # 5. Converter chave de sessão para bytes e criptografar com RSA (wrap da CEK)
        chave_sessao_bytes = bytes.fromhex(chave_sessao_hex)
        chave_sessao_cripto_b64 = RSAManager.cifrar_chave_sessao(chave_sessao_bytes, chave_publica_destinatario_pem)
        if log_enabled:
            if not is_group:
                # Para chat individual, mostra wrap da CEK
                cek_enc_truncado = truncate_hex(chave_sessao_cripto_b64, 12, 12)
                logger.info(f"[{step_counter[0]}] CEK wrapada (RSA) para {destinatario}: {cek_enc_truncado}")
                step_counter[0] += 1
            elif is_group:
                # Para grupos, não mostra wrap aqui (será mostrado no adapter_api para cada membro)
                pass
        
        if log_enabled and not is_group:
            logger.info(f"{'='*70}\n")
        
        return resultado, chave_sessao_cripto_b64
    
    def decifrar_do_chat(self, packet: str, cek_b64: str, destinatario: str, chave_privada_pem: str, is_group: bool = False, log_enabled: bool = True, step_counter: list = None, sender: str = None, group_name: str = None):
        """Decifra uma mensagem do chat usando IDEA + RSA"""
        
        logger = group_chat_logger if is_group else individual_chat_logger
        
        # Inicializa contador se não fornecido (numeração linear contínua)
        if step_counter is None:
            step_counter = [1]
        
        # Cria box de recebimento
        if log_enabled:
            if is_group:
                # Para grupos, mostra remetente e grupo
                content_lines = []
                if sender:
                    content_lines.append(f"Remetente: {sender}")
                if group_name:
                    content_lines.append(f"Grupo: {group_name}")
                logger.info(format_box(
                    title=f"RECEBIMENTO: {destinatario} (Grupo: {group_name})",
                    content=content_lines,
                    width=70,
                    char="="
                ))
            else:
                # Para chat individual, mostra remetente se disponível
                content_lines = []
                if sender:
                    content_lines.append(f"Remetente: {sender}")
                logger.info(format_box(
                    title=f"RECEBIMENTO: {destinatario}",
                    content=content_lines,
                    width=70,
                    char="="
                ))
        
        # ============================================================
        # FLUXO DE RECEBIMENTO: PASSO 1 - Recebe ciphertext, IV, cek_wrapped[me], metadados
        # ============================================================
        mensagem_cifrada_hex, iv_hex = packet.split(':')
        if log_enabled:
            # Recebe dados criptografados
            cek_enc_truncado = truncate_hex(cek_b64, 12, 12)
            cipher_truncado = truncate_hex(mensagem_cifrada_hex, 8, 8)
            iv_truncado = truncate_hex(iv_hex, 8, 8)
            logger.info(f"[{step_counter[0]}] {destinatario} recebeu:")
            step_counter[0] += 1
            logger.info(f"     └─ Ciphertext: {cipher_truncado}")
            logger.info(f"     └─ IV: {iv_truncado}")
            logger.info(f"     └─ CEK wrapada (RSA): {cek_enc_truncado}")
        
        # ============================================================
        # FLUXO DE RECEBIMENTO: PASSO 2 - Desembrulha CEK: CEK = RSA_Decrypt(priv_me, cek_wrapped)
        # ============================================================
        chave_sessao_bytes = RSAManager.decifrar_chave_sessao(cek_b64, chave_privada_pem)
        chave_sessao_hex = chave_sessao_bytes.hex().upper()
        if log_enabled:
            cek_truncada = truncate_hex(chave_sessao_hex, 8, 8)
            logger.info(f"[{step_counter[0]}] Desembrulhando CEK: RSA_Decrypt(priv_{destinatario}, cek_wrapped)")
            step_counter[0] += 1
            logger.info(f"[{step_counter[0]}] CEK desembrulhada (CEK ID: {cek_truncada})")
            step_counter[0] += 1
        
        # ============================================================
        # FLUXO DE RECEBIMENTO: PASSO 3 - Decifra corpo: msg = SymDec(CEK, IV, ciphertext)
        # ============================================================
        chave_sessao_int = int.from_bytes(chave_sessao_bytes, 'big')
        self.idea = IDEA(chave_sessao_int)
        texto_decifrado = self.idea.decifrar_cbc(packet)
        if log_enabled:
            logger.info(f"[{step_counter[0]}] Decifrando corpo: SymDec(CEK, IV, ciphertext)")
            step_counter[0] += 1
            logger.info(f"[{step_counter[0]}] Mensagem descriptografada: '{texto_decifrado}'")
            step_counter[0] += 1
            logger.info(f"{'='*70}\n")
        
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

