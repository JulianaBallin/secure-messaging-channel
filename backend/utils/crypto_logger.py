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
            self.logger = logging.getLogger("crypto_chat")
            self.logger.setLevel(logging.INFO)

            if not os.path.exists("logs"):
                os.makedirs("logs")

            logfile = f'logs/crypto_chat_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.log'

            fh = logging.FileHandler(logfile, encoding="utf-8")
            fh.setLevel(logging.INFO)

            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)

            formatter = logging.Formatter("%(asctime)s - %(message)s")
            fh.setFormatter(formatter)
            ch.setFormatter(formatter)

            self.logger.addHandler(fh)
            self.logger.addHandler(ch)
            self._initialized = True

    # Helpers de formatação 
    def section(self, titulo: str):
        self.logger.info("")
        self.logger.info("=" * 70)
        self.logger.info(titulo.upper())
        self.logger.info("=" * 70)

    def kv(self, chave: str, valor: str):
        self.logger.info(f"{chave}: {valor}")

    def hr(self):
        self.logger.info("-" * 70)

    #USUÁRIOS 
    def log_usuario_criado(self, nome: str, chave_publica: str, chave_privada: str):
        self.section("Novo usuário criado")
        self.kv("Usuário", nome)
        self.kv("Chave Pública (RSA)", (chave_publica or "")[:120] + "...")
        self.kv("Chave Privada (RSA)", (chave_privada or "")[:120] + "...")
        self.hr()

    def log_usuario_selecionado(self, usuario: str):
        self.section("Usuário selecionado")
        self.kv("Usuário atual", usuario)
        self.hr()

    #MENSAGENS INDIVIDUAIS
    def log_envio_mensagem(self, remetente: str, destinatario: str, mensagem_original: str,
                           chave_sessao_hex: str, chave_sessao_criptografada: str,
                           mensagem_criptografada: str, chave_publica_destinatario: str):
        self.section("Envio de mensagem")
        self.kv("De", remetente)
        self.kv("Para", destinatario)
        self.kv("Mensagem original", mensagem_original)
        self.kv("Chave de sessão (IDEA)", chave_sessao_hex)
        self.kv("Chave de sessão criptografada (RSA b64)", (chave_sessao_criptografada or "")[:120] + "...")
        self.kv("Mensagem criptografada (IDEA-CBC)", mensagem_criptografada)
        self.kv("Chave pública do destinatário", (chave_publica_destinatario or "")[:120] + "...")
        self.hr()

    def log_recebimento_mensagem(self, destinatario: str, remetente: str,
                                 mensagem_criptografada: str, chave_sessao_criptografada: str,
                                 chave_sessao_decifrada: str, mensagem_decifrada: str,
                                 chave_privada_destinatario: str):
        self.section("Recebimento de mensagem")
        self.kv("Para", destinatario)
        self.kv("De", remetente)
        self.kv("Mensagem criptografada", mensagem_criptografada)
        self.kv("Chave de sessão criptografada (RSA b64)", (chave_sessao_criptografada or "")[:120] + "...")
        self.kv("Chave de sessão decifrada (hex)", chave_sessao_decifrada)
        self.kv("Mensagem decifrada", mensagem_decifrada)
        self.kv("Chave privada do destinatário", (chave_privada_destinatario or "")[:120] + "...")
        self.hr()

    #GRUPOS 
    def log_grupo_criado(self, nome_grupo: str, admin: str, chave_grupo: str):
        self.section("Grupo criado")
        self.kv("Grupo", nome_grupo)
        self.kv("Admin", admin)
        self.kv("Chave IDEA Grupo", chave_grupo)
        self.hr()

    def log_membro_removido(self, nome_grupo: str, membro: str, admin: str):
        self.section("Membro removido do grupo")
        self.kv("Grupo", nome_grupo)
        self.kv("Membro Removido", membro)
        self.kv("Por Admin", admin)
        self.hr()

    def log_admin_transferido(self, nome_grupo: str, novo_admin: str, nova_chave: str):
        self.section("Admin transferido")
        self.kv("Grupo", nome_grupo)
        self.kv("Novo Admin", novo_admin)
        self.kv("Nova Chave IDEA", nova_chave)
        self.hr()

    # GRUPOS MELHORADOS
    def log_envio_grupo_melhorado(self, nome_grupo: str, remetente: str, mensagem: str, 
                                 mensagem_cripto: str, chave_grupo: str, chaves_cripto: dict):
        self.section("ENVIO PARA GRUPO - DETALHADO")
        self.kv("Grupo", nome_grupo)
        self.kv("Remetente", remetente)
        self.kv("Mensagem Original", mensagem)
        self.kv("Chave IDEA Grupo", chave_grupo)
        self.kv("Mensagem Criptografada (IDEA-CBC)", mensagem_cripto)
        # Mostra chaves RSA para cada membro
        for membro, chave_cripto in chaves_cripto.items():
            self.kv(f"🔐 Chave RSA para {membro}", (chave_cripto or "")[:80] + "...")
        self.kv("Total de Destinatários", str(len(chaves_cripto)))
        self.hr()

    def log_recebimento_grupo_melhorado(self, nome_grupo: str, destinatario: str, 
                                      mensagem_cripto: str, mensagem: str, 
                                      chave_grupo: str, chave_privada: str = None):
        self.section("RECEBIMENTO DE GRUPO - DETALHADO")
        self.kv("Grupo", nome_grupo)
        self.kv("Destinatário", destinatario)
        self.kv("Mensagem Criptografada", mensagem_cripto)
        self.kv("Chave IDEA Grupo Usada", chave_grupo)
        self.kv("Mensagem Decifrada", mensagem)
        if chave_privada:
            self.kv("Chave Privada do Destinatário", (chave_privada or "")[:120] + "...")
        self.hr()

    def log_recebimento_grupo(self, nome_grupo: str, destinatario: str, mensagem_cripto: str, mensagem: str, chave_grupo: str):
        self.section("Recebimento de grupo")
        self.kv("Grupo", nome_grupo)
        self.kv("Destinatário", destinatario)
        self.kv("Mensagem Criptografada", mensagem_cripto)
        self.kv("Mensagem Decifrada", mensagem)
        self.kv("Chave Grupo Usada", chave_grupo)
        self.hr()

    def log_membro_adicionado(self, nome_grupo: str, admin: str, novo_membro: str, chave_antiga: str, chave_nova: str, chave_cripto: str):
        self.section("MEMBRO ADICIONADO - TROCA DE CHAVE")
        self.kv("Grupo", nome_grupo)
        self.kv("Admin", admin)
        self.kv("Novo Membro", novo_membro)
        self.kv("CHAVE ANTIGA (INVALIDADA)", chave_antiga)
        self.kv("CHAVE NOVA GERADA", chave_nova)
        self.kv("CHAVE NOVA CRIPTOGRAFADA (RSA)", (chave_cripto or "")[:120] + "...")
        self.kv("Status", "Chave redistribuída para TODOS os membros (antigos + novo)")
        self.hr()

    def log_membro_removido_melhorado(self, nome_grupo: str, membro: str, admin: str, chave_antiga: str, chave_nova: str, chaves_cripto: dict):
        self.section("MEMBRO REMOVIDO - TROCA DE CHAVE")
        self.kv("Grupo", nome_grupo)
        self.kv("Membro Removido", membro)
        self.kv("Por Admin", admin)
        self.kv(" CHAVE ANTIGA (INVALIDADA)", chave_antiga)
        if chave_nova:
            self.kv("🔄 CHAVE NOVA GERADA", chave_nova)
            if chaves_cripto:
                primeiro_membro = next(iter(chaves_cripto.keys()))
                self.kv(f" EXEMPLO Chave Criptografada para {primeiro_membro}", (chaves_cripto[primeiro_membro] or "")[:80] + "...")
            self.kv("Status", f"Chave redistribuída para {len(chaves_cripto)} MEMBROS RESTANTES")
        else:
            self.kv("Status", "Último membro - grupo removido")
        self.hr()

    def log_admin_transferido_melhorado(self, nome_grupo: str, admin_antigo: str, novo_admin: str, chave_antiga: str, chave_nova: str, chaves_cripto: dict):
        self.section("ADMIN TRANSFERIDO - TROCA DE CHAVE")
        self.kv("Grupo", nome_grupo)
        self.kv("Admin Anterior", admin_antigo)
        self.kv("Novo Admin", novo_admin)
        self.kv("CHAVE ANTIGA (INVALIDADA)", chave_antiga)
        self.kv("CHAVE NOVA GERADA", chave_nova)
        if chaves_cripto:
            primeiro_membro = next(iter(chaves_cripto.keys()))
            self.kv(f"EXEMPLO Chave Criptografada para {primeiro_membro}", (chaves_cripto[primeiro_membro] or "")[:80] + "...")
        self.kv("Status", f"Admin transferido + chave redistribuída para {len(chaves_cripto)} membros restantes")
        self.hr()

    # SISTEMA 
    def log_troca_usuario(self, usuario_anterior: str):
        self.section("Troca de usuário")
        self.kv("Usuário Anterior", usuario_anterior)
        self.kv("Novo Usuário", "None")
        self.hr()

    def log_saida_sistema(self, usuario: str):
        self.section("Saída do sistema")
        self.kv("Último Usuário", usuario)
        self.kv("Encerramento", "Solicitado pelo usuário")
        self.hr()

    #OPERAÇÕES IDEA
    def log_operacao_idea(self, operacao: str, chave_sessao: str, iv: Optional[str] = None,
                          bloco_entrada: Optional[str] = None, bloco_saida: Optional[str] = None):
        self.section(f"IDEA {operacao.upper()}")
        self.kv("Chave de sessão", chave_sessao)
        if iv:
            self.kv("IV", iv)
        if bloco_entrada:
            self.kv("Bloco entrada", bloco_entrada)
        if bloco_saida:
            self.kv("Bloco saída", bloco_saida)
        self.hr()

    #ERROS
    def log_erro(self, contexto: str, erro: str):
        self.section(f"ERRO - {contexto}")
        self.kv("Erro", erro)
        self.hr()

crypto_logger = CryptoLogger()