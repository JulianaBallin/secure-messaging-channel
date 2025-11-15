from backend.crypto.idea import IDEA
from backend.crypto.rsa_manager import RSAManager
from backend.utils.logger_config import (
    individual_chat_logger, 
    group_chat_logger, 
    confidencialidade_logger,
    confidencialidade_chat_individual_logger,
    confidencialidade_chat_grupo_logger
)
from backend.utils.log_formatter import format_box, truncate_hex
from hashlib import sha256
import os
import base64
from Crypto.PublicKey import RSA

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
        chave_sessao_bytes = bytes.fromhex(chave_sessao_hex)
        cek_fingerprint = sha256(chave_sessao_bytes).hexdigest()
        
        if log_enabled:
            cek_truncada = truncate_hex(chave_sessao_hex, 8, 8)
            cek_fp_truncado = truncate_hex(cek_fingerprint, 8, 8)
            logger.info(f"[{step_counter[0]}] Gerando CEK + IV (CEK ID: {cek_truncada})")
            step_counter[0] += 1
            
            # Log de confidencialidade: Geração de chave (usar logger específico por tipo)
            confidencialidade_chat_logger = confidencialidade_chat_grupo_logger if is_group else confidencialidade_chat_individual_logger
            contexto = "Grupo" if is_group else "Individual"
            confidencialidade_chat_logger.info(
                format_box(
                    title=f"CRIPTOGRAFIA {contexto.upper()}: {remetente} → {destinatario if not is_group else 'Grupo'}",
                    content=[],
                    width=70,
                    char="="
                )
            )
            confidencialidade_chat_logger.info(f"[0] PARTICIPANTES:")
            confidencialidade_chat_logger.info(f"     └─ Remetente: {remetente}")
            confidencialidade_chat_logger.info(f"     └─ Destinatário: {destinatario if not is_group else f'Grupo ({destinatario})'}")
            confidencialidade_chat_logger.info(f"[1] GERACAO_CEK:")
            confidencialidade_chat_logger.info(f"     └─ Algoritmo: IDEA-128")
            confidencialidade_chat_logger.info(f"     └─ Tamanho: 128 bits")
            confidencialidade_chat_logger.info(f"     └─ CEK_Fingerprint: {cek_fp_truncado}")
        
        # 2. Mostrar mensagem original
        texto_bytes = texto_plano.encode('utf-8')
        plaintext_size = len(texto_bytes)
        
        if log_enabled:
            logger.info(f"[{step_counter[0]}] Mensagem original: '{texto_plano}'")
            step_counter[0] += 1
            
            # Log de confidencialidade: Plaintext apenas tamanho e amostra (usar logger específico por tipo)
            from backend.utils.log_formatter import truncate_text
            confidencialidade_chat_logger = confidencialidade_chat_grupo_logger if is_group else confidencialidade_chat_individual_logger
            confidencialidade_chat_logger.info(f"[2] PLAINTEXT:")
            confidencialidade_chat_logger.info(f"     └─ {truncate_text(texto_plano, max_chars=30, show_sample=True)}")
        
        # 3. Calcular padding PKCS7
        bloco_size = 8
        padding_size = bloco_size - (plaintext_size % bloco_size) if (plaintext_size % bloco_size) != 0 else bloco_size
        texto_com_padding_size = plaintext_size + padding_size
        num_blocos = texto_com_padding_size // bloco_size
        
        if log_enabled:
            # Log de confidencialidade: Padding e blocos (usar logger específico por tipo)
            confidencialidade_chat_logger = confidencialidade_chat_grupo_logger if is_group else confidencialidade_chat_individual_logger
            confidencialidade_chat_logger.info(f"[3] PADDING_PKCS7:")
            confidencialidade_chat_logger.info(f"     └─ Plaintext: {plaintext_size} bytes → Com padding: {texto_com_padding_size} bytes")
            confidencialidade_chat_logger.info(f"     └─ Padding adicionado: {padding_size} bytes")
            confidencialidade_chat_logger.info(f"     └─ Blocos: {num_blocos}")
        
        # 4. Criptografar mensagem UMA ÚNICA VEZ (IDEA/CBC)
        if log_enabled:
            resultado, exemplo_real = self.idea.cifrar_cbc(texto_plano, capture_example=True)
        else:
            resultado = self.idea.cifrar_cbc(texto_plano)
            exemplo_real = None
        
        mensagem_cifrada_hex, iv_hex = resultado.split(':')
        ciphertext_bytes = bytes.fromhex(mensagem_cifrada_hex)
        ciphertext_size = len(ciphertext_bytes)
        iv_bytes = bytes.fromhex(iv_hex)
        iv_truncado = truncate_hex(iv_hex, 8, 8)
        
        if log_enabled:
            # Mensagem criptografada: truncada para reduzir exposição
            cipher_truncado = truncate_hex(mensagem_cifrada_hex, 8, 8)
            logger.info(f"[{step_counter[0]}] Mensagem criptografada (IDEA/CBC) - Ciphertext: {cipher_truncado}, IV: {iv_truncado}")
            step_counter[0] += 1
            if is_group:
                logger.info(f"[{step_counter[0]}] Mensagem criptografada UMA VEZ (será distribuída para todos os membros)")
                step_counter[0] += 1
            
            # Log de confidencialidade: Processo CBC e resultado (usar logger específico por tipo)
            confidencialidade_chat_logger = confidencialidade_chat_grupo_logger if is_group else confidencialidade_chat_individual_logger
            confidencialidade_chat_logger.info(f"[4] CIFRAGEM_IDEA_CBC:")
            confidencialidade_chat_logger.info(f"     └─ Algoritmo: IDEA-128/CBC")
            confidencialidade_chat_logger.info(f"     └─ Modo: CBC (Cipher Block Chaining)")
            confidencialidade_chat_logger.info(f"     └─ IV: {iv_truncado} | Tamanho: 8 bytes")
            confidencialidade_chat_logger.info(f"     └─ Processo_Geral: XOR(IV + Bloco1) → IDEA → Bloco1_cifrado → XOR(Bloco1_cifrado + Bloco2) → IDEA → ... ({num_blocos} blocos)")
            confidencialidade_chat_logger.info(f"     └─ Processo_IDEA_Por_Bloco:")
            confidencialidade_chat_logger.info(f"         └─ Cada bloco (8 bytes) passa por: 8 rodadas IDEA + rodada final")
            confidencialidade_chat_logger.info(f"         └─ Rodadas: 8 rodadas principais (6 subchaves cada) + 1 rodada final (4 subchaves)")
            confidencialidade_chat_logger.info(f"         └─ Operacoes_por_rodada: Mult_Mod, Soma_Mod, XOR entre sub-blocos (4 sub-blocos de 16 bits)")
            if exemplo_real:
                confidencialidade_chat_logger.info(f"         └─ Exemplo de operacoes que aconteceram na cifragem:")
                confidencialidade_chat_logger.info(f"             └─ Mult_Mod: 0x{exemplo_real['p1_inicial']:04X} * 0x{exemplo_real['k1']:04X} = 0x{exemplo_real['p1_mult']:04X}")
                confidencialidade_chat_logger.info(f"             └─ XOR: 0x{exemplo_real['p1_mult']:04X} XOR 0x{exemplo_real['p3_soma']:04X} = 0x{exemplo_real['xor_p1_p3']:04X}")
                confidencialidade_chat_logger.info(f"             └─ Soma_Mod: 0x{exemplo_real['t0_mult']:04X} + 0x{exemplo_real['xor_p2_p4']:04X} = 0x{exemplo_real['x3_soma']:04X}")
            confidencialidade_chat_logger.info(f"[5] RESULTADO:")
            confidencialidade_chat_logger.info(f"     └─ Ciphertext: {cipher_truncado} | Tamanho: {ciphertext_size} bytes")
            confidencialidade_chat_logger.info(f"     └─ Transformacao: {plaintext_size} bytes (plaintext) + {padding_size} bytes (padding) → {ciphertext_size} bytes (ciphertext)")
        
        # 4. Log de obtenção de chave pública (para chat individual apenas)
        # Para grupos, o log de obtenção de chaves públicas é feito no adapter_api DEPOIS da criptografia
        if not is_group and log_enabled:
            chave_publica_fingerprint = truncate_hex(sha256(chave_publica_destinatario_pem.encode()).hexdigest(), 8, 8)
            logger.info(f"[{step_counter[0]}] {remetente} obteve chave pública RSA de {destinatario} (Fingerprint: {chave_publica_fingerprint})")
            step_counter[0] += 1
        
        # 5. Converter chave de sessão para bytes e criptografar com RSA (wrap da CEK)
        chave_sessao_cripto_b64 = RSAManager.cifrar_chave_sessao(chave_sessao_bytes, chave_publica_destinatario_pem)
        pubkey_fingerprint = truncate_hex(sha256(chave_publica_destinatario_pem.encode()).hexdigest(), 8, 8)
        
        if log_enabled:
            if not is_group:
                # Para chat individual, mostra wrap da CEK
                cek_enc_truncado = truncate_hex(chave_sessao_cripto_b64, 12, 12)
                logger.info(f"[{step_counter[0]}] CEK wrapada (RSA) para {destinatario}: {cek_enc_truncado}")
                step_counter[0] += 1
                
                # Log de confidencialidade: Wrap RSA (usar logger específico para individual)
                confidencialidade_chat_individual_logger.info(f"[6] WRAP_RSA:")
                confidencialidade_chat_individual_logger.info(f"     └─ Algoritmo: RSA-2048/OAEP")
                confidencialidade_chat_individual_logger.info(f"     └─ Destinatario: {destinatario}")
                confidencialidade_chat_individual_logger.info(f"     └─ PubKey_Fingerprint: {pubkey_fingerprint}")
                confidencialidade_chat_individual_logger.info(f"     └─ Processo: CEK (hex) → RSA-Encrypt → CEK_wrapped (Base64)")
                confidencialidade_chat_individual_logger.info(f"     └─ CEK_Criptografada: {truncate_hex(chave_sessao_cripto_b64, 12, 12)} | Tamanho: {len(chave_sessao_cripto_b64)} caracteres Base64")
                confidencialidade_chat_individual_logger.info(f"{'='*70}\n")
            elif is_group:
                # Para grupos, não mostra wrap aqui (será mostrado no adapter_api para cada membro)
                # Mas registra no log de confidencialidade
                confidencialidade_chat_grupo_logger.info(f"[DISTRIBUIÇÃO] CEK será distribuída para todos os membros do grupo via RSA-2048")
                confidencialidade_chat_grupo_logger.info(f"{'='*70}\n")
        
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
        ciphertext_bytes = bytes.fromhex(mensagem_cifrada_hex)
        ciphertext_size = len(ciphertext_bytes)
        iv_bytes = bytes.fromhex(iv_hex)
        
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
            
            # Log de confidencialidade: Recebimento (usar logger específico por tipo)
            confidencialidade_chat_logger = confidencialidade_chat_grupo_logger if is_group else confidencialidade_chat_individual_logger
            contexto = "Grupo" if is_group else "Individual"
            grupo_info = f" (Grupo: {group_name})" if is_group and group_name else ""
            confidencialidade_chat_logger.info(
                format_box(
                    title=f"DESCRIPTOGRAFIA {contexto.upper()}: {destinatario}{grupo_info}",
                    content=[],
                    width=70,
                    char="="
                )
            )
            confidencialidade_chat_logger.info(f"[0] PARTICIPANTES:")
            if sender:
                confidencialidade_chat_logger.info(f"     └─ Remetente: {sender}")
            confidencialidade_chat_logger.info(f"     └─ Destinatário: {destinatario}")
            if is_group and group_name:
                confidencialidade_chat_logger.info(f"     └─ Grupo: {group_name}")
            num_blocos = ciphertext_size // 8
            confidencialidade_chat_logger.info(f"[1] RECEBIMENTO:")
            confidencialidade_chat_logger.info(f"     └─ Ciphertext: {cipher_truncado} | Tamanho: {ciphertext_size} bytes")
            confidencialidade_chat_logger.info(f"     └─ IV: {iv_truncado} | Tamanho: 8 bytes")
            confidencialidade_chat_logger.info(f"     └─ Algoritmo: IDEA-128/CBC")
            confidencialidade_chat_logger.info(f"     └─ Blocos: {num_blocos}")
            confidencialidade_chat_logger.info(f"     └─ CEK_Wrapada: {cek_enc_truncado} | Tamanho: {len(cek_b64)} caracteres Base64")
            
            # [1.5] CARREGAMENTO_CHAVE_PRIVADA
            confidencialidade_chat_logger.info(f"[1.5] CARREGAMENTO_CHAVE_PRIVADA:")
            private_key_path = None
            try:
                # Tentar obter o caminho da chave privada (mesmo padrão usado em adapter_api.py)
                # O arquivo idea_manager.py está em backend/crypto/, então:
                # - dirname(__file__) = backend/crypto/
                # - dirname(dirname(__file__)) = backend/
                BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                user_keys_dir = os.path.join(BACKEND_DIR, "keys", destinatario)
                priv_path = os.path.join(user_keys_dir, f"{destinatario}_private.pem")
                if os.path.exists(priv_path):
                    private_key_path = priv_path
            except Exception:
                pass
            
            if private_key_path:
                try:
                    file_size = os.path.getsize(private_key_path)
                    confidencialidade_chat_logger.info(f"     └─ Caminho: {private_key_path}")
                    confidencialidade_chat_logger.info(f"     └─ Tamanho_Arquivo: {file_size} bytes")
                except Exception:
                    confidencialidade_chat_logger.info(f"     └─ Caminho: {private_key_path}")
            else:
                confidencialidade_chat_logger.info(f"     └─ Caminho: Carregado da memória")
            
            # Calcular fingerprint da chave pública correspondente
            try:
                priv_key_obj = RSA.import_key(chave_privada_pem.encode())
                pub_key_obj = priv_key_obj.publickey()
                pub_key_pem = pub_key_obj.export_key().decode()
                pubkey_fingerprint_full = sha256(pub_key_pem.encode()).hexdigest()
                pubkey_fingerprint_trunc = truncate_hex(pubkey_fingerprint_full, 8, 8)
                key_size_bits = pub_key_obj.size_in_bits()
                confidencialidade_chat_logger.info(f"     └─ Tamanho_Chave: {key_size_bits} bits (RSA)")
                confidencialidade_chat_logger.info(f"     └─ PubKey_Fingerprint: {pubkey_fingerprint_trunc}")
            except Exception as e:
                confidencialidade_chat_logger.info(f"     └─ Status: Erro ao obter informações da chave ({str(e)})")
            
            # [1.6] PARSING_CEK_WRAPADA
            confidencialidade_chat_logger.info(f"[1.6] PARSING_CEK_WRAPADA:")
            cek_wrap_size_b64 = len(cek_b64)
            try:
                cek_wrap_bytes = base64.b64decode(cek_b64)
                cek_wrap_size_bytes = len(cek_wrap_bytes)
                cek_wrap_hex = cek_wrap_bytes.hex().upper()
                cek_wrap_trunc = truncate_hex(cek_wrap_hex, 8, 8)
                confidencialidade_chat_logger.info(f"     └─ Base64: {cek_wrap_size_b64} caracteres")
                confidencialidade_chat_logger.info(f"     └─ Bytes: {cek_wrap_size_bytes} bytes")
                confidencialidade_chat_logger.info(f"     └─ Valor_Truncado: {cek_wrap_trunc}")
                # Sanity check: RSA-2048 deve produzir 256 bytes
                expected_size = 256
                if cek_wrap_size_bytes == expected_size:
                    confidencialidade_chat_logger.info(f"     └─ Sanity_Check: OK ({cek_wrap_size_bytes} == {expected_size} bytes)")
                else:
                    confidencialidade_chat_logger.info(f"     └─ Sanity_Check: ATENCAO ({cek_wrap_size_bytes} != {expected_size} bytes esperados)")
            except Exception as e:
                confidencialidade_chat_logger.info(f"     └─ Status: Erro ao fazer parsing ({str(e)})")
            
            # [1.7] VALIDACAO_IV
            confidencialidade_chat_logger.info(f"[1.7] VALIDACAO_IV:")
            iv_size = len(iv_bytes)
            confidencialidade_chat_logger.info(f"     └─ IV: {iv_truncado} | Tamanho: {iv_size} bytes")
            if iv_size == 8:
                confidencialidade_chat_logger.info(f"     └─ Validacao: OK (8 bytes = 64 bits, tamanho do bloco IDEA)")
            else:
                confidencialidade_chat_logger.info(f"     └─ Validacao: ERRO (esperado 8 bytes, obtido {iv_size})")
        
        # ============================================================
        # FLUXO DE RECEBIMENTO: PASSO 2 - Desembrulha CEK: CEK = RSA_Decrypt(priv_me, cek_wrapped)
        # ============================================================
        chave_sessao_bytes = RSAManager.decifrar_chave_sessao(cek_b64, chave_privada_pem)
        chave_sessao_hex = chave_sessao_bytes.hex().upper()
        cek_fingerprint = sha256(chave_sessao_bytes).hexdigest()
        
        if log_enabled:
            cek_truncada = truncate_hex(chave_sessao_hex, 8, 8)
            cek_fp_truncado = truncate_hex(cek_fingerprint, 8, 8)
            logger.info(f"[{step_counter[0]}] Desembrulhando CEK: RSA_Decrypt(priv_{destinatario}, cek_wrapped)")
            step_counter[0] += 1
            logger.info(f"[{step_counter[0]}] CEK desembrulhada (CEK ID: {cek_truncada})")
            step_counter[0] += 1
            
            # Log de confidencialidade: Unwrap RSA (melhorado)
            confidencialidade_chat_logger = confidencialidade_chat_grupo_logger if is_group else confidencialidade_chat_individual_logger
            confidencialidade_chat_logger.info(f"[2] UNWRAP_RSA:")
            confidencialidade_chat_logger.info(f"     └─ Algoritmo: RSA-2048/OAEP")
            confidencialidade_chat_logger.info(f"     └─ Chave_Privada: {destinatario}")
            confidencialidade_chat_logger.info(f"     └─ Processo: CEK_wrapped (Base64) → RSA-Decrypt → CEK (hex)")
            confidencialidade_chat_logger.info(f"     └─ Status: OK (descriptografado com sucesso)")
            confidencialidade_chat_logger.info(f"     └─ CEK_Original: {cek_truncada}")
            confidencialidade_chat_logger.info(f"     └─ CEK_Fingerprint: {cek_fp_truncado}")
            confidencialidade_chat_logger.info(f"     └─ Tamanho_CEK: {len(chave_sessao_bytes)} bytes (128 bits)")
            # Validação do tamanho da CEK
            if len(chave_sessao_bytes) == 16:
                confidencialidade_chat_logger.info(f"     └─ Validacao_CEK: OK (16 bytes = 128 bits para IDEA)")
            else:
                confidencialidade_chat_logger.info(f"     └─ Validacao_CEK: ERRO (esperado 16 bytes, obtido {len(chave_sessao_bytes)})")
        
        # ============================================================
        # FLUXO DE RECEBIMENTO: PASSO 3 - Decifra corpo: msg = SymDec(CEK, IV, ciphertext)
        # ============================================================
        chave_sessao_int = int.from_bytes(chave_sessao_bytes, 'big')
        self.idea = IDEA(chave_sessao_int)
        
        # Calcular informações antes de descriptografar
        num_blocos = ciphertext_size // 8
        texto_sem_padding_size = ciphertext_size
        
        if log_enabled:
            # Log de confidencialidade: Processo CBC inverso (usar logger específico por tipo)
            confidencialidade_chat_logger = confidencialidade_chat_grupo_logger if is_group else confidencialidade_chat_individual_logger
            confidencialidade_chat_logger.info(f"[3] DECIFRAGEM_IDEA_CBC:")
            confidencialidade_chat_logger.info(f"     └─ Algoritmo: IDEA-128/CBC")
            confidencialidade_chat_logger.info(f"     └─ Modo: CBC (Cipher Block Chaining inverso)")
            confidencialidade_chat_logger.info(f"     └─ CEK_ID: {cek_truncada}")
            confidencialidade_chat_logger.info(f"     └─ Processo_Geral: IDEA-Decrypt(Bloco1) → XOR(IV) → Plaintext1 → IDEA-Decrypt(Bloco2) → XOR(Bloco1_cifrado) → Plaintext2 → ... ({num_blocos} blocos)")
            confidencialidade_chat_logger.info(f"     └─ Processo_IDEA_Por_Bloco:")
            confidencialidade_chat_logger.info(f"         └─ Cada bloco (8 bytes) passa por: rodada final inversa + 8 rodadas IDEA inversas")
            confidencialidade_chat_logger.info(f"         └─ Rodadas: 1 rodada final inversa (4 subchaves) + 8 rodadas principais inversas (6 subchaves cada)")
            confidencialidade_chat_logger.info(f"         └─ Operacoes_por_rodada: Mult_Mod_inv, Soma_Mod_inv, XOR entre sub-blocos (4 sub-blocos de 16 bits)")
        
        # Decifrar com captura de exemplo
        exemplo_real = None
        if log_enabled:
            resultado_decifrar = self.idea.decifrar_cbc(packet, capture_example=True)
            if isinstance(resultado_decifrar, tuple):
                texto_decifrado, exemplo_real = resultado_decifrar
            else:
                texto_decifrado = resultado_decifrar
        else:
            texto_decifrado = self.idea.decifrar_cbc(packet)
        
        if log_enabled and exemplo_real:
            k1_val = exemplo_real.get('k1_inv') or exemplo_real.get('k1', 0)
            confidencialidade_chat_logger.info(f"         └─ Exemplo de operacoes que aconteceram na Decifragem:")
            confidencialidade_chat_logger.info(f"             └─ Mult_Mod_inv: 0x{exemplo_real['p1_inicial']:04X} * 0x{k1_val:04X}_inv = 0x{exemplo_real['p1_mult']:04X}")
            confidencialidade_chat_logger.info(f"             └─ XOR: 0x{exemplo_real['p1_mult']:04X} XOR 0x{exemplo_real['p3_soma']:04X} = 0x{exemplo_real['xor_p1_p3']:04X}")
            confidencialidade_chat_logger.info(f"             └─ Soma_Mod_inv: 0x{exemplo_real['t0_mult']:04X} + 0x{exemplo_real['xor_p2_p4']:04X} = 0x{exemplo_real['x3_soma']:04X}")
        
        texto_decifrado_bytes = texto_decifrado.encode('utf-8')
        plaintext_size = len(texto_decifrado_bytes)
        
        if log_enabled:
            logger.info(f"[{step_counter[0]}] Decifrando corpo: SymDec(CEK, IV, ciphertext)")
            step_counter[0] += 1
            logger.info(f"[{step_counter[0]}] Mensagem descriptografada: '{texto_decifrado}'")
            step_counter[0] += 1
            logger.info(f"{'='*70}\n")
            
            # Log de confidencialidade: Remoção de padding e resultado (usar logger específico por tipo)
            from backend.utils.log_formatter import truncate_text
            confidencialidade_chat_logger = confidencialidade_chat_grupo_logger if is_group else confidencialidade_chat_individual_logger
            padding_size = ciphertext_size - plaintext_size
            
            # Validação detalhada do padding PKCS7
            padding_valid = True
            padding_details = ""
            if padding_size > 0 and padding_size <= 8:
                try:
                    # Verificar último byte (deve ser o tamanho do padding)
                    last_byte = texto_decifrado_bytes[-1] if len(texto_decifrado_bytes) > 0 else 0
                    # Em PKCS7, os últimos N bytes devem ser iguais a N
                    if last_byte == padding_size:
                        # Verificar se todos os bytes de padding são iguais
                        padding_bytes = texto_decifrado_bytes[-padding_size:]
                        if all(b == padding_size for b in padding_bytes):
                            padding_valid = True
                            padding_details = f"PKCS7 valido (ultimos {padding_size} bytes = 0x{padding_size:02X})"
                        else:
                            padding_valid = False
                            padding_details = f"PKCS7 INVALIDO (bytes de padding inconsistentes)"
                    else:
                        padding_valid = False
                        padding_details = f"PKCS7 INVALIDO (ultimo byte 0x{last_byte:02X} != 0x{padding_size:02X})"
                except Exception as e:
                    padding_valid = False
                    padding_details = f"Erro ao validar padding: {str(e)}"
            elif padding_size == 0:
                padding_details = "Nenhum padding (tamanho exato de blocos)"
            else:
                padding_valid = False
                padding_details = f"Padding invalido (tamanho {padding_size} > 8)"
            
            confidencialidade_chat_logger.info(f"[4] REMOCAO_PADDING_PKCS7:")
            confidencialidade_chat_logger.info(f"     └─ Antes: {ciphertext_size} bytes (ciphertext completo)")
            confidencialidade_chat_logger.info(f"     └─ Padding_Removido: {padding_size} bytes")
            confidencialidade_chat_logger.info(f"     └─ Depois: {plaintext_size} bytes (plaintext sem padding)")
            confidencialidade_chat_logger.info(f"[5] RESULTADO:")
            confidencialidade_chat_logger.info(f"     └─ {truncate_text(texto_decifrado, max_chars=30, show_sample=True)}")
            confidencialidade_chat_logger.info(f"{'='*70}\n")
        
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
        from backend.utils.logger_config import confidencialidade_logger

        fingerprint = sha256(key_bytes).hexdigest()
        confidencialidade_logger.info(f"[GENERATE_IDEA_KEY] Chave IDEA gerada | SHA256={fingerprint}")
        return key_bytes

