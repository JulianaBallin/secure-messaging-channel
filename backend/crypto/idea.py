import os
import secrets
from .idea_fallback import padding_pkcs7, remove_pkcs7


class IDEA:
    def __init__(self, chave: int = None):
        self._chaves = None
        # GERA CHAVE DE SESSAO AUTOMATICAMENTE
        if chave is None:
            chave = self.gerar_chave_aleatoria()
        
        self.chave_sessao = chave  
        self.gerar_chaves(chave)

    def gerar_chave_aleatoria(self) -> int:
        # Chave IDEA aleatória de 128 bits
        chave = int.from_bytes(secrets.token_bytes(16), 'big')
        return chave

    def get_chave_sessao(self) -> int:
        return format(self.chave_sessao, "032X")

    def get_chave_sessao_hex(self) -> str:
        # chave de sessão em hexadecimal
        return hex(self.chave_sessao)[2:].upper().zfill(32)

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
    def rodada(self, p1, p2, p3, p4, chaves, capture_example=False):
        k1, k2, k3, k4, k5, k6 = chaves

        p1_inicial = p1
        p2_inicial = p2
        p3_inicial = p3
        p4_inicial = p4
        
        p1_mult = self.mult_mod(p1, k1)
        p4_mult = self.mult_mod(p4, k4)
        p2_soma = self.soma_mod(p2, k2)
        p3_soma = self.soma_mod(p3, k3)
        
        xor_p1_p3 = p1_mult ^ p3_soma
        t0_mult = self.mult_mod(k5, xor_p1_p3)
        xor_p2_p4 = p2_soma ^ p4_mult
        x3_soma = self.soma_mod(t0_mult, xor_p2_p4)
        t1_mult = self.mult_mod(k6, x3_soma)
        t2_soma = self.soma_mod(t0_mult, t1_mult)
        
        p1_final = p1_mult ^ t1_mult
        p4_final = p4_mult ^ t2_soma
        a = p2_soma ^ t2_soma
        p2_final = p3_soma ^ t1_mult
        p3_final = a

        if capture_example:
            exemplo = {
                'p1_inicial': p1_inicial, 'p2_inicial': p2_inicial, 'p3_inicial': p3_inicial, 'p4_inicial': p4_inicial,
                'p1_mult': p1_mult, 'p4_mult': p4_mult, 'p2_soma': p2_soma, 'p3_soma': p3_soma,
                'xor_p1_p3': xor_p1_p3, 't0_mult': t0_mult, 'xor_p2_p4': xor_p2_p4, 'x3_soma': x3_soma,
                't1_mult': t1_mult, 't2_soma': t2_soma,
                'p1_final': p1_final, 'p2_final': p2_final, 'p3_final': p3_final, 'p4_final': p4_final,
                'k1': k1, 'k2': k2, 'k3': k3, 'k4': k4, 'k5': k5, 'k6': k6
            }
            return (p1_final, p2_final, p3_final, p4_final), exemplo

        return p1_final, p2_final, p3_final, p4_final

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
    def cifrar(self, texto_plano, capture_example=False):
        p1 = (texto_plano >> 48) & 0xFFFF
        p2 = (texto_plano >> 32) & 0xFFFF
        p3 = (texto_plano >> 16) & 0xFFFF
        p4 = texto_plano & 0xFFFF
        
        exemplo_rodada = None
        
        # 8 rodadas
        for i in range(8):
            chaves = self._chaves[i]
            if capture_example and i == 0:  # Capturar primeira rodada
                (p1, p2, p3, p4), exemplo_rodada = self.rodada(p1, p2, p3, p4, chaves, capture_example=True)
            else:
                p1, p2, p3, p4 = self.rodada(p1, p2, p3, p4, chaves)
        
        #Rodada final
        k1, k2, k3, k4, x, y = self._chaves[8]
        y1 = self.mult_mod(p1, k1)
        y2 = self.soma_mod(p3, k2)
        y3 = self.soma_mod(p2, k3)
        y4 = self.mult_mod(p4, k4)

        texto_cifrado = (y1 << 48) | (y2 << 32) | (y3 << 16) | y4
        
        if capture_example:
            return texto_cifrado, exemplo_rodada
        return texto_cifrado

    def decifrar(self, texto_cifrado, capture_example=False):
        p1 = (texto_cifrado >> 48) & 0xFFFF
        p2 = (texto_cifrado >> 32) & 0xFFFF
        p3 = (texto_cifrado >> 16) & 0xFFFF
        p4 = texto_cifrado & 0xFFFF

        exemplo_rodada = None

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
        
        if capture_example:  # Capturar primeira rodada inversa
            (p1, p2, p3, p4), exemplo_rodada = self.rodada(p1, p2, p3, p4, chaves, capture_example=True)
            exemplo_rodada['k1_inv'] = k1
            exemplo_rodada['k2_inv'] = k2
            exemplo_rodada['k3_inv'] = k3
            exemplo_rodada['k4_inv'] = k4
        else:
            p1, p2, p3, p4 = self.rodada(p1, p2, p3, p4, chaves)

        # Rodadas 2-8
        for i in range(1, 8):
            chaves = self._chaves[8-i]
            k1 = self.inv_multiplicativo(chaves[0])
            k2 = self.inv_aditivo(chaves[2])  #k2 e k3 trocados
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
        
        if capture_example:
            return texto_decifrado, exemplo_rodada
        return texto_decifrado

    # CBC e PKCS7
    def cifrar_cbc(self, texto_ascii, iv_hex=None, capture_example=False):
        """
        Cifra texto ASCII usando CBC + PKCS7
        Retorna: "cifrado_hex:iv_hex" ou (resultado, exemplo_rodada) se capture_example=True
        """
        # IV aleatório 
        if iv_hex is None:
            iv = os.urandom(8)
            iv_hex = iv.hex().upper()
        else:
            iv = bytes.fromhex(iv_hex)
        
        texto_bytes = texto_ascii.encode('utf-8')
        texto_com_padding = padding_pkcs7(texto_bytes)
        blocos = [texto_com_padding[i:i+8] for i in range(0, len(texto_com_padding), 8)]
        
        texto_cifrado_bytes = b''
        bloco_anterior = iv
        exemplo_real = None
        
        for i, bloco in enumerate(blocos):
            # XOR com bloco anterior (CBC)
            bloco_xor = bytes(a ^ b for a, b in zip(bloco, bloco_anterior))
            
            # Cifra com IDEA
            bloco_int = int.from_bytes(bloco_xor, 'big')
            
            if capture_example and i == 0:  # Capturar apenas primeiro bloco
                bloco_cifrado_int, exemplo_real = self.cifrar(bloco_int, capture_example=True)
            else:
                bloco_cifrado_int = self.cifrar(bloco_int)
            
            bloco_cifrado = bloco_cifrado_int.to_bytes(8, 'big')
            
            texto_cifrado_bytes += bloco_cifrado
            bloco_anterior = bloco_cifrado
        
        for i, bloco in enumerate(blocos):
            bloco_hex = bloco.hex().upper()
        
        resultado = f"{texto_cifrado_bytes.hex().upper()}:{iv_hex}"
        
        if capture_example:
            return resultado, exemplo_real
        return resultado

    def decifrar_cbc(self, cifrado_com_iv, capture_example=False):
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
            exemplo_real = None
            
            for i, bloco in enumerate(blocos):
                # Decifra com IDEA
                bloco_int = int.from_bytes(bloco, 'big')
                
                if capture_example and i == 0:  # Capturar apenas primeiro bloco
                    bloco_decifrado_int, exemplo_real = self.decifrar(bloco_int, capture_example=True)
                else:
                    bloco_decifrado_int = self.decifrar(bloco_int)
                
                bloco_decifrado = bloco_decifrado_int.to_bytes(8, 'big')
                
                bloco_final = bytes(a ^ b for a, b in zip(bloco_decifrado, bloco_anterior))
                
                texto_decifrado_bytes += bloco_final
                bloco_anterior = bloco
            
            # Log sobre descriptografia de blocos
            for i, bloco in enumerate(blocos):
                bloco_hex = bloco.hex().upper()
            
            # Remove PKCS7 padding
            texto_sem_padding = remove_pkcs7(texto_decifrado_bytes)
            texto_final = texto_sem_padding.decode('utf-8')
                                    
            if capture_example:
                return texto_final, exemplo_real
            return texto_final
            
        except Exception as e:
            raise ValueError(f"Erro na decifração: {e}")