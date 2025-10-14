import os
import secrets
from .idea_fallback import padding_pkcs7, remove_pkcs7

class IDEA:
    def __init__(self, chave: int = None):
        self._chaves = None
        #GERA CHAVE DE SESSAO AUTOMATICAMENTE
        if chave is None:
            chave = self.gerar_chave_aleatoria()
        self.chave_sessao = chave  
        self.gerar_chaves(chave)

    def gerar_chave_aleatoria(self) -> int:
        #Chave IDEA aleatória de 128 bits
        return int.from_bytes(secrets.token_bytes(16), 'big')

    def get_chave_sessao(self) -> int:
        return format(self.chave_sessao, "032X")

    def get_chave_sessao_hex(self) -> str:
        #chave de sessão em hexadecimal
        return hex(self.chave_sessao)[2:].upper() 

    def mult_mod(self, a, b):
        assert 0 <= a <= 0xFFFF
        assert 0 <= b <= 0xFFFF

        if a == 0:
            a = 0x10000
        if b == 0:
            b = 0x10000

        r = (a * b) % 0x10001

        if r == 0x10000:
            r = 0

        assert 0 <= r <= 0xFFFF
        return r

    def soma_mod(self, a, b):
        return (a + b) % 0x10000

    def inv_aditivo(self, chave):
        return (0x10000 - chave) % 0x10000

    def inv_multiplicativo(self, a):
        if a == 0:
            return 0
        
        m = 0x10001
        t0, t1 = 0, 1
        r0, r1 = m, a
        
        while r1 != 0:
            q = r0 // r1
            t0, t1 = t1, t0 - q * t1
            r0, r1 = r1, r0 - q * r1
        
        if r0 != 1:
            raise ValueError("Não tem inverso multiplicativo")
        
        if t0 < 0:
            t0 += m
        
        return t0 % 0x10000

    # Rodada IDEA
    def rodada(self, p1, p2, p3, p4, chaves):
        k1, k2, k3, k4, k5, k6 = chaves

        
        p1 = self.mult_mod(p1, k1)
        p4 = self.mult_mod(p4, k4)
        p2 = self.soma_mod(p2, k2)
        p3 = self.soma_mod(p3, k3)
        
        x = p1 ^ p3
        t0 = self.mult_mod(k5, x)
        x = p2 ^ p4
        x = self.soma_mod(t0, x)
        t1 = self.mult_mod(k6, x)
        t2 = self.soma_mod(t0, t1)
        
        p1 = p1 ^ t1
        p4 = p4 ^ t2
        a = p2 ^ t2
        p2 = p3 ^ t1
        p3 = a

        return p1, p2, p3, p4

    # Geração das subchaves
    def gerar_chaves(self, chave):
        assert 0 <= chave < (1 << 128)
        modulo = 1 << 128

        sub_chaves = []
        for i in range(9 * 6):
            sub_chaves.append((chave >> (112 - 16 * (i % 8))) % 0x10000)
            if i % 8 == 7:
                chave = ((chave << 25) | (chave >> 103)) % modulo

        chaves = []
        for i in range(9):
            chaves_rodada = sub_chaves[6 * i: 6 * (i + 1)]
            chaves.append(tuple(chaves_rodada))
        self._chaves = tuple(chaves)
        
    # Cifração por bloco (ECB) 
    def cifrar(self, texto_plano):
        p1 = (texto_plano >> 48) & 0xFFFF
        p2 = (texto_plano >> 32) & 0xFFFF
        p3 = (texto_plano >> 16) & 0xFFFF
        p4 = texto_plano & 0xFFFF
        
        # 8 rodadas
        for i in range(8):
            chaves = self._chaves[i]
            p1, p2, p3, p4 = self.rodada(p1, p2, p3, p4, chaves)
        
        #Rodada final
        k1, k2, k3, k4, x, y = self._chaves[8]
        y1 = self.mult_mod(p1, k1)
        y2 = self.soma_mod(p3, k2)
        y3 = self.soma_mod(p2, k3)
        y4 = self.mult_mod(p4, k4)

        texto_cifrado = (y1 << 48) | (y2 << 32) | (y3 << 16) | y4
        return texto_cifrado

    def decifrar(self, texto_cifrado):
        p1 = (texto_cifrado >> 48) & 0xFFFF
        p2 = (texto_cifrado >> 32) & 0xFFFF
        p3 = (texto_cifrado >> 16) & 0xFFFF
        p4 = texto_cifrado & 0xFFFF

        # Rodada 1 - usa chaves da rodada 8 para decifração
        chaves = self._chaves[8]
        k1 = self.inv_multiplicativo(chaves[0])
        k2 = self.inv_aditivo(chaves[1])
        k3 = self.inv_aditivo(chaves[2])
        k4 = self.inv_multiplicativo(chaves[3])
        chaves = self._chaves[7]
        k5 = chaves[4]
        k6 = chaves[5]
        chaves = [k1, k2, k3, k4, k5, k6]
        p1, p2, p3, p4 = self.rodada(p1, p2, p3, p4, chaves)

        # Rodadas 2-8
        for i in range(1, 8):
            chaves = self._chaves[8-i]
            k1 = self.inv_multiplicativo(chaves[0])
            k2 = self.inv_aditivo(chaves[2])  # Note: k2 e k3 trocados
            k3 = self.inv_aditivo(chaves[1])
            k4 = self.inv_multiplicativo(chaves[3])
            chaves = self._chaves[7-i]
            k5 = chaves[4]
            k6 = chaves[5]
            chaves = [k1, k2, k3, k4, k5, k6]
            p1, p2, p3, p4 = self.rodada(p1, p2, p3, p4, chaves)
        
        # Transformação da rodada final
        chaves = self._chaves[0]
        k1 = self.inv_multiplicativo(chaves[0])
        k2 = self.inv_aditivo(chaves[1])
        k3 = self.inv_aditivo(chaves[2])
        k4 = self.inv_multiplicativo(chaves[3])
        y1 = self.mult_mod(p1, k1)
        y2 = self.soma_mod(p3, k2)
        y3 = self.soma_mod(p2, k3)
        y4 = self.mult_mod(p4, k4)
        texto_decifrado = (y1 << 48) | (y2 << 32) | (y3 << 16) | y4
        return texto_decifrado

    # CBC e PKCS7
    def cifrar_cbc(self, texto_ascii, iv_hex=None):
        """
        Cifra texto ASCII usando CBC + PKCS7
        Retorna: "cifrado_hex:iv_hex"
        """
        # IV aleatório 
        if iv_hex is None:
            iv = os.urandom(8)
        else:
            iv = bytes.fromhex(iv_hex)
        
        texto_bytes = texto_ascii.encode('utf-8')
        
        texto_com_padding = padding_pkcs7(texto_bytes)
        
        blocos = [texto_com_padding[i:i+8] for i in range(0, len(texto_com_padding), 8)]
        
        texto_cifrado_bytes = b''
        bloco_anterior = iv
        
        for bloco in blocos:
            # XOR com bloco anterior (CBC)
            bloco_xor = bytes(a ^ b for a, b in zip(bloco, bloco_anterior))
            
            # Cifra com IDEA
            bloco_int = int.from_bytes(bloco_xor, 'big')
            bloco_cifrado_int = self.cifrar(bloco_int)
            bloco_cifrado = bloco_cifrado_int.to_bytes(8, 'big')
            
            texto_cifrado_bytes += bloco_cifrado
            bloco_anterior = bloco_cifrado
        
        # Retorna: cifrado_hex:iv_hex
        return f"{texto_cifrado_bytes.hex()}:{iv.hex()}"

    def decifrar_cbc(self, cifrado_com_iv):
        try:
            # Separa cifrado e IV
            cifrado_hex, iv_hex = cifrado_com_iv.split(':')
            cifrado_bytes = bytes.fromhex(cifrado_hex)
            iv = bytes.fromhex(iv_hex)
            
            # Verifica se o tamanho é múltiplo de 8
            if len(cifrado_bytes) % 8 != 0:
                raise ValueError("Texto cifrado deve ter tamanho múltiplo de 8 bytes")
            
            # Divide em blocos de 8 bytes
            blocos = [cifrado_bytes[i:i+8] for i in range(0, len(cifrado_bytes), 8)]
            
            texto_decifrado_bytes = b''
            bloco_anterior = iv
            
            for bloco in blocos:
                # Decifra com IDEA
                bloco_int = int.from_bytes(bloco, 'big')
                bloco_decifrado_int = self.decifrar(bloco_int)
                bloco_decifrado = bloco_decifrado_int.to_bytes(8, 'big')
                
                bloco_final = bytes(a ^ b for a, b in zip(bloco_decifrado, bloco_anterior))
                
                texto_decifrado_bytes += bloco_final
                bloco_anterior = bloco
            
            # Remove PKCS7 padding
            texto_sem_padding = remove_pkcs7(texto_decifrado_bytes)
                                    
            return texto_sem_padding.decode('utf-8')
            
        except Exception as e:
            raise ValueError(f"Erro na decifração: {e}")