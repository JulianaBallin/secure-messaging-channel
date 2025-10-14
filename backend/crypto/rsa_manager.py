from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

class RSAManager:
    
    @staticmethod
    def gerar_par_chaves():
        chave = RSA.generate(2048)
        privada = chave.export_key().decode()
        publica = chave.publickey().export_key().decode()
        return privada, publica
    
    @staticmethod
    def cifrar_chave_sessao(cek_bytes, chave_publica_pem):
        pub = RSA.import_key(chave_publica_pem.encode())
        cipher = PKCS1_OAEP.new(pub)
        cek_cifrado = cipher.encrypt(cek_bytes)
        return base64.b64encode(cek_cifrado).decode()
    
    @staticmethod
    def decifrar_chave_sessao(cek_b64, chave_privada_pem):
        try:
            priv = RSA.import_key(chave_privada_pem.encode())
            cipher = PKCS1_OAEP.new(priv)
            cek_bytes = cipher.decrypt(base64.b64decode(cek_b64))
            
            if len(cek_bytes) != 16:
                raise ValueError(f"Chave de sessão deve ter 16 bytes, tem {len(cek_bytes)}")
                
            return cek_bytes
            
        except Exception as e:
            raise ValueError(f"Erro ao decifrar chave de sessão: {e}")
    
    @staticmethod
    def carregar_chave_publica(caminho):
        with open(caminho, 'r') as f:
            return f.read()
    
    @staticmethod
    def carregar_chave_privada(caminho):
        with open(caminho, 'r') as f:
            return f.read()