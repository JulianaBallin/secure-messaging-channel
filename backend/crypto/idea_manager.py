import secrets
from .idea import IDEA
from .idea_fallback import validar_chave_hex


class IDEAManager:
    def __init__(self):
        self.chave_sessao = None
        self.idea = None
    
    def iniciar_sessao_automatica(self):
        #Inicia uma nova sessão com chave IDEA gerada automaticamente"
        self.idea = IDEA()  
        self.chave_sessao = self.idea.get_chave_sessao()
        return self.chave_sessao
    
    def iniciar_sessao_com_chave(self, chave_hex: str = None):
        #Inicia sessão com chave específica (para decifração)
        if chave_hex:
            self.chave_sessao = validar_chave_hex(chave_hex)
        else:
            self.chave_sessao = self.gerar_chave_aleatoria()
        
        self.idea = IDEA(self.chave_sessao)
        return self.chave_sessao
    
    def gerar_chave_aleatoria(self) -> int:
        return int.from_bytes(secrets.token_bytes(16), 'big')
    
    def cifrar_texto(self, texto_plano: str) -> tuple:
        #Cifra texto e retorna (pacote_cifrado, chave_sessao) no formato: (cifrado_hex:iv_hex, chave_sessao_hex)
        if not self.idea:
            self.iniciar_sessao_automatica()
        
        pacote_cifrado = self.idea.cifrar_cbc(texto_plano)
        chave_sessao = self.idea.get_chave_sessao_hex()
        
        return pacote_cifrado, chave_sessao
    
    def decifrar_texto_com_chave(self, pacote_cifrado: str, chave_sessao_hex: str) -> str:
        # Decifra texto usando chave de sessão fornecida
        try:
            chave_sessao = validar_chave_hex(chave_sessao_hex)
            self.idea = IDEA(chave_sessao)
            return self.idea.decifrar_cbc(pacote_cifrado)
        except Exception as e:
            raise ValueError(f"Erro na decifração: {e}")
    
    def configurar_chave(self, chave_hex=None, usar_padrao=False):
        """Método legado - mantido para compatibilidade"""
        if usar_padrao:
            return self.iniciar_sessao_automatica()
        else:
            return self.iniciar_sessao_com_chave(chave_hex)
    
    def cifrar_texto_legado(self, texto_plano):
        """Método legado - mantido para compatibilidade"""
        if not self.idea:
            self.iniciar_sessao_automatica()
        return self.idea.cifrar_cbc(texto_plano)
    
    def decifrar_texto_legado(self, resultado_cifrado):
        """Método legado - mantido para compatibilidade"""
        if not self.idea:
            raise ValueError("Chave não configurada")
        return self.idea.decifrar_cbc(resultado_cifrado)
    
    def get_info_sessao(self):
        """Retorna informações da sessão atual"""
        if not self.chave_sessao:
            return "Sessão não iniciada"
        
        return {
            'chave_sessao_hex': hex(self.chave_sessao),
            'chave_sessao_bytes': self.chave_sessao.bit_length() // 8,
            'chave_sessao_decimal': str(self.chave_sessao)
        }
    
