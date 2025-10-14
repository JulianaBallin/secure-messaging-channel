import secrets
from .idea import IDEA
from .idea_fallback import validar_chave_hex
from .rsa_manager import RSAManager

class IDEAManager:
    def __init__(self):
        self.chave_sessao = None
        self.idea = None
    
    def cifrar_para_chat(self, texto_plano, chave_publica_pem):
        self.idea = IDEA()
        
        # Cifra o texto com IDEA
        packet = self.idea.cifrar_cbc(texto_plano)
        
        # Protege CEK com RSA
        cek_bytes = bytes.fromhex(self.idea.get_chave_sessao_hex())
        cek_b64 = RSAManager.cifrar_chave_sessao(cek_bytes, chave_publica_pem)
        
        return packet, cek_b64
    
    def decifrar_do_chat(self, packet, cek_b64, chave_privada_pem):
        try:
            # Decifra CEK com RSA
            cek_bytes = RSAManager.decifrar_chave_sessao(cek_b64, chave_privada_pem)
            
            # Converte para hex e valida
            cek_hex = cek_bytes.hex().upper()
            
            # Garante 32 caracteres hex
            if len(cek_hex) != 32:
                raise ValueError(f"Chave de sessão deve gerar 32 hex, gerou {len(cek_hex)}")
            
            chave_sessao = validar_chave_hex(cek_hex)
            self.idea = IDEA(chave_sessao)
            return self.idea.decifrar_cbc(packet)
            
        except Exception as e:
            raise ValueError(f"Erro na decifração: {e}")