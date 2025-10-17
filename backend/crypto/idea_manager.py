# backend/crypto/idea_manager.py
import json
import os
from datetime import datetime
from backend.crypto.idea import IDEA
from backend.crypto.rsa_manager import RSAManager
from backend.utils.crypto_logger import crypto_logger

class IDEAManager:
    def __init__(self):
        self.idea = IDEA()
        self.historico_file = "historico_individual.json"
        self._ensure_historico_file()
    
    def _ensure_historico_file(self):
        if not os.path.exists(self.historico_file):
            with open(self.historico_file, 'w') as f:
                json.dump({}, f)
    
    def cifrar_para_chat(self, texto_plano: str, remetente: str, destinatario: str, chave_publica_destinatario_pem: str):
        crypto_logger.logger.info("=== INICIO PROCESSO DE ENVIO ===")
        crypto_logger.logger.info(f"Remetente: {remetente}")
        crypto_logger.logger.info(f"Destinatario: {destinatario}")
        crypto_logger.logger.info(f"Mensagem Original: {texto_plano}")
        
        chave_sessao_hex = self.idea.get_chave_sessao_hex()
        crypto_logger.logger.info(f"Chave de Sessao IDEA: {chave_sessao_hex}")
        
        resultado = self.idea.cifrar_cbc(texto_plano)
        crypto_logger.logger.info(f"Mensagem Criptografada (IDEA-CBC): {resultado}")
        
        chave_sessao_bytes = bytes.fromhex(chave_sessao_hex)
        chave_sessao_cripto_b64 = RSAManager.cifrar_chave_sessao(chave_sessao_bytes, chave_publica_destinatario_pem)
        crypto_logger.logger.info(f"Chave de Sessao Criptografada (RSA): {chave_sessao_cripto_b64[:50]}...")
        
        self._salvar_no_historico(
            remetente, destinatario, resultado, 
            chave_sessao_hex, chave_sessao_cripto_b64, 'enviada'
        )
        
        crypto_logger.logger.info("=== FIM PROCESSO DE ENVIO ===")
        
        return resultado, chave_sessao_cripto_b64
    
    def decifrar_do_chat(self, packet: str, cek_b64: str, destinatario: str, chave_privada_pem: str):
        crypto_logger.logger.info("=== INICIO PROCESSO DE RECEBIMENTO ===")
        crypto_logger.logger.info(f"Destinatario: {destinatario}")
        crypto_logger.logger.info(f"Mensagem Criptografada Recebida: {packet}")
        crypto_logger.logger.info(f"Chave de Sessao Criptografada Recebida: {cek_b64[:50]}...")
        
        chave_sessao_bytes = RSAManager.decifrar_chave_sessao(cek_b64, chave_privada_pem)
        chave_sessao_hex = chave_sessao_bytes.hex().upper()
        crypto_logger.logger.info(f"Chave de Sessao Decifrada (RSA): {chave_sessao_hex}")
        
        chave_sessao_int = int.from_bytes(chave_sessao_bytes, 'big')
        self.idea = IDEA(chave_sessao_int)
        
        texto_decifrado = self.idea.decifrar_cbc(packet)
        crypto_logger.logger.info(f"Mensagem Decifrada: {texto_decifrado}")
        
        self._salvar_no_historico(
            "Desconhecido", destinatario, packet, 
            chave_sessao_hex, cek_b64, 'recebida'
        )
        
        crypto_logger.logger.info("=== FIM PROCESSO DE RECEBIMENTO ===")
        
        return texto_decifrado
    
    def decifrar_do_historico(self, entrada_historico: dict, chave_privada_pem: str, usuario_atual: str):
        """Decifra uma mensagem do histórico com verificações de segurança - VERSÃO CORRIGIDA"""
        
        # VERIFICAÇÃO 1: Usuário deve ser participante da conversa
        destinatario = entrada_historico.get('destinatario', '')
        remetente = entrada_historico.get('remetente', '')
        
        if destinatario != usuario_atual and remetente != usuario_atual:
            raise ValueError(f"Acesso negado: mensagem entre {remetente} e {destinatario}")
        
        # VERIFICAÇÃO 2: Deve existir chave RSA criptografada
        if 'chave_rsa_criptografada' not in entrada_historico:
            raise ValueError("Mensagem não pode ser decifrada - falta chave RSA")
        
        # VERIFICAÇÃO 3: Mensagem deve estar criptografada
        mensagem_cripto = entrada_historico.get('mensagem_criptografada', '')
        if not mensagem_cripto:
            raise ValueError("Mensagem criptografada não encontrada")
        
        chave_rsa_cripto = entrada_historico['chave_rsa_criptografada']
        
        crypto_logger.logger.info("=== DECIFRAGEM HISTÓRICO ===")
        crypto_logger.logger.info(f"Usuário: {usuario_atual}")
        crypto_logger.logger.info(f"Remetente: {remetente} -> Destinatário: {destinatario}")
        
        try:
            if destinatario == usuario_atual:
                # Usuário é o DESTINATÁRIO: usar sua chave privada para descriptografar
                chave_sessao_bytes = RSAManager.decifrar_chave_sessao(chave_rsa_cripto, chave_privada_pem)
                crypto_logger.logger.info("✅ Modo: Destinatário - usando própria chave privada")
                
            else:  # remetente == usuario_atual
                # Usuário é o REMETENTE: a chave RSA foi criptografada com chave pública do DESTINATÁRIO
                # NÃO podemos descriptografar com nossa chave privada!
                raise ValueError(f"Esta mensagem foi criptografada com a chave pública de {destinatario}. "
                            f"Como remetente, você não pode descriptografá-la.")
            
            chave_sessao_hex = chave_sessao_bytes.hex().upper()
            crypto_logger.logger.info(f"Chave de sessão recuperada: {chave_sessao_hex}")
            
            # Configurar IDEA com a chave de sessão
            chave_sessao_int = int.from_bytes(chave_sessao_bytes, 'big')
            self.idea = IDEA(chave_sessao_int)
            
            # Descriptografar a mensagem
            texto_decifrado = self.idea.decifrar_cbc(mensagem_cripto)
            
            crypto_logger.logger.info(f"Mensagem decifrada: {texto_decifrado}")
            crypto_logger.logger.info("=== FIM DECIFRAGEM ===")
            
            return texto_decifrado
            
        except Exception as e:
            crypto_logger.logger.error(f"ERRO na decifragem: {e}")
            raise ValueError(f"Falha na decifragem: {e}")
    
    def _salvar_no_historico(self, remetente: str, destinatario: str, mensagem_cripto: str, 
                           chave_sessao: str, chave_rsa_cripto: str, tipo: str):
        historico = self._carregar_historico()
        
        conversa_id = f"{remetente}_{destinatario}" if tipo == 'enviada' else f"{destinatario}_{remetente}"
        
        if conversa_id not in historico:
            historico[conversa_id] = []
        
        entrada = {
            'timestamp': datetime.now().isoformat(),
            'remetente': remetente,
            'destinatario': destinatario,
            'tipo': tipo,
            'mensagem_criptografada': mensagem_cripto,
            'chave_sessao_utilizada': chave_sessao,
            'chave_rsa_criptografada': chave_rsa_cripto  # AGORA SEMPRE SALVA
        }
        
        historico[conversa_id].append(entrada)
        self._salvar_historico(historico)
    
    def ver_historico_individual(self, usuario: str, outro_usuario: str):
        historico = self._carregar_historico()
        
        conversa_id1 = f"{usuario}_{outro_usuario}"
        conversa_id2 = f"{outro_usuario}_{usuario}"
        
        mensagens = []
        if conversa_id1 in historico:
            mensagens.extend(historico[conversa_id1])
        if conversa_id2 in historico:
            mensagens.extend(historico[conversa_id2])
        
        mensagens.sort(key=lambda x: x['timestamp'])
        return mensagens
    
    def _carregar_historico(self):
        with open(self.historico_file, 'r') as f:
            return json.load(f)
    
    def _salvar_historico(self, historico):
        with open(self.historico_file, 'w') as f:
            json.dump(historico, f, indent=2)
    
    def get_chave_sessao_hex(self):
        return self.idea.get_chave_sessao_hex()