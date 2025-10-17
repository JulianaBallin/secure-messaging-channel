import os
import json
import secrets
from datetime import datetime
from backend.crypto.idea import IDEA
from backend.crypto.rsa_manager import RSAManager
from backend.utils.crypto_logger import crypto_logger

class GroupManager:
    def __init__(self):
        self.groups_file = "groups.json"
        self._ensure_groups_file()
    
    def _ensure_groups_file(self):
        if not os.path.exists(self.groups_file):
            with open(self.groups_file, 'w') as f:
                json.dump({}, f)
    
    def criar_grupo(self, nome_grupo: str, admin: str):
        """CRIAÇÃO DO GRUPO - Conforme especificação"""
        groups = self._carregar_groups()
        
        if nome_grupo in groups:
            raise ValueError(f"Grupo '{nome_grupo}' já existe")
        
        # Gerar chave IDEA única para o grupo (no cliente do admin)
        chave_grupo = secrets.randbits(128)
        grupo_idea = IDEA(chave_grupo)
        chave_grupo_hex = grupo_idea.get_chave_sessao_hex()
        
        grupo = {
            'admin': admin,
            'membros': [admin],
            'chave_grupo_hex': chave_grupo_hex,
            'ativo': True,
            'historico_mensagens': []  # 🔥 NOVO: Histórico de mensagens
        }
        
        groups[nome_grupo] = grupo
        self._salvar_groups(groups)
        
        # LOG: Grupo criado
        crypto_logger.log_grupo_criado(nome_grupo, admin, chave_grupo_hex)
        
        return chave_grupo_hex
    
    def adicionar_membro(self, nome_grupo: str, admin: str, novo_membro: str):
        """ENTRADA DE NOVO MEMBRO - Conforme especificação"""
        groups = self._carregar_groups()
        
        if nome_grupo not in groups:
            raise ValueError(f"Grupo '{nome_grupo}' não existe")
        
        grupo = groups[nome_grupo]
        
        if grupo['admin'] != admin:
            raise ValueError("Apenas o admin pode adicionar membros")
        
        if novo_membro in grupo['membros']:
            raise ValueError(f"Usuário '{novo_membro}' já está no grupo")
        
        # CAPTURA CHAVE ANTIGA
        chave_antiga = grupo['chave_grupo_hex']
        
        # REGRA: SEMPRE gerar NOVA chave quando adiciona membro
        nova_chave = secrets.randbits(128)
        nova_chave_hex = IDEA(nova_chave).get_chave_sessao_hex()
        grupo['chave_grupo_hex'] = nova_chave_hex
        
        # Adicionar novo membro
        grupo['membros'].append(novo_membro)
        groups[nome_grupo] = grupo
        self._salvar_groups(groups)
        
        # Criptografar nova chave para TODOS os membros (incluindo o novo)
        chaves_criptografadas = self._criptografar_chave_para_todos_membros(nova_chave_hex, grupo['membros'])
        
        # LOG MELHORADO: Membro adicionado
        crypto_logger.log_membro_adicionado(
            nome_grupo, admin, novo_membro, chave_antiga, nova_chave_hex, 
            chaves_criptografadas.get(novo_membro, "")
        )
        
        return nova_chave_hex, chaves_criptografadas
    
    def remover_membro(self, nome_grupo: str, usuario: str, admin_remocao: str = None):
        """SAÍDA DE MEMBRO - Conforme especificação"""
        groups = self._carregar_groups()
        
        if nome_grupo not in groups:
            raise ValueError(f"Grupo '{nome_grupo}' não existe")
        
        grupo = groups[nome_grupo]
        
        if usuario not in grupo['membros']:
            raise ValueError(f"Usuário '{usuario}' não está no grupo")
        
        # Verificar permissões: admin pode remover qualquer um, usuário comum só pode sair
        if usuario != grupo['admin'] and admin_remocao != grupo['admin'] and usuario != admin_remocao:
            raise ValueError("Apenas o admin pode remover outros membros")
        
        nova_chave_hex = None
        chaves_criptografadas = {}
        chave_antiga = grupo['chave_grupo_hex']  # CAPTURA CHAVE ANTIGA
        
        # REGRA: SEMPRE gerar nova chave quando membro SAI
        if len(grupo['membros']) > 1:
            nova_chave = secrets.randbits(128)
            nova_chave_hex = IDEA(nova_chave).get_chave_sessao_hex()
            grupo['chave_grupo_hex'] = nova_chave_hex
            
            # Se é o ADMIN saindo, promover outro membro
            if usuario == grupo['admin']:
                novo_admin = next(m for m in grupo['membros'] if m != usuario)
                grupo['admin'] = novo_admin
                crypto_logger.log_admin_transferido_melhorado(
                    nome_grupo, usuario, novo_admin, chave_antiga, nova_chave_hex, chaves_criptografadas
                )
            
            # Criptografar nova chave para TODOS os membros restantes
            membros_restantes = [m for m in grupo['membros'] if m != usuario]
            chaves_criptografadas = self._criptografar_chave_para_todos_membros(nova_chave_hex, membros_restantes)
        
        # Remover membro
        grupo['membros'].remove(usuario)
        
        # Verificar se grupo ficou vazio
        if len(grupo['membros']) == 0:
            del groups[nome_grupo]
            self._salvar_groups(groups)
            crypto_logger.logger.info("=== GRUPO REMOVIDO ===")
            crypto_logger.logger.info(f"Grupo: {nome_grupo} (último membro saiu)")
            crypto_logger.logger.info("=" * 50)
            return None, {}
        else:
            groups[nome_grupo] = grupo
            self._salvar_groups(groups)
        
        # LOG MELHORADO da remoção
        admin_atual = grupo.get('admin', 'N/A')
        if usuario == admin_atual:
            crypto_logger.log_membro_removido_melhorado(
                nome_grupo, usuario, f"Auto-transferência para {admin_atual}", 
                chave_antiga, nova_chave_hex, chaves_criptografadas
            )
        else:
            crypto_logger.log_membro_removido_melhorado(
                nome_grupo, usuario, admin_atual, chave_antiga, nova_chave_hex, chaves_criptografadas
            )
        
        return nova_chave_hex, chaves_criptografadas
    
    def _criptografar_chave_para_todos_membros(self, chave_grupo_hex: str, membros: list):
     #Criptografa a chave do grupo para TODOS os membros via RSA
        chaves_criptografadas = {}
        
        for membro in membros:
            chave_publica_path = f"keys/{membro}/publica.pem"
            if os.path.exists(chave_publica_path):
                try:
                    chave_publica = RSAManager.carregar_chave_publica(chave_publica_path)
                    chave_grupo_bytes = bytes.fromhex(chave_grupo_hex)
                    chave_cripto = RSAManager.cifrar_chave_sessao(chave_grupo_bytes, chave_publica)
                    chaves_criptografadas[membro] = chave_cripto
                except Exception as e:
                    crypto_logger.log_erro(f"CRIPTOGRAFIA_CHAVE_{membro}", str(e))
        
        return chaves_criptografadas
    
    def cifrar_mensagem_grupo(self, nome_grupo: str, mensagem: str, remetente: str):
        groups = self._carregar_groups()
        
        if nome_grupo not in groups:
            raise ValueError(f"Grupo '{nome_grupo}' não existe")
        
        grupo = groups[nome_grupo]
        
        if remetente not in grupo['membros']:
            raise ValueError(f"Remetente '{remetente}' não é membro do grupo")
        
        # Usar chave do grupo para cifrar
        chave_grupo_int = int(grupo['chave_grupo_hex'], 16)
        grupo_idea = IDEA(chave_grupo_int)
        
        mensagem_cifrada = grupo_idea.cifrar_cbc(mensagem)
        
        # Preparar chaves cifradas para cada membro (exceto remetente)
        chaves_cifradas = {}
        for membro in grupo['membros']:
            if membro != remetente:
                chave_publica_path = f"keys/{membro}/publica.pem"
                if os.path.exists(chave_publica_path):
                    chave_publica = RSAManager.carregar_chave_publica(chave_publica_path)
                    chave_grupo_bytes = bytes.fromhex(grupo['chave_grupo_hex'])
                    chave_cifrada = RSAManager.cifrar_chave_sessao(chave_grupo_bytes, chave_publica)
                    chaves_cifradas[membro] = chave_cifrada
        
        # 🔥 NOVO: Armazenar no histórico
        mensagem_info = {
            'remetente': remetente,
            'timestamp': datetime.now().isoformat(),
            'mensagem_cripto': mensagem_cifrada,
            'chave_utilizada': grupo['chave_grupo_hex']
        }
        grupo['historico_mensagens'].append(mensagem_info)
        groups[nome_grupo] = grupo
        self._salvar_groups(groups)
        
        # 🔥 NOVO: Log detalhado
        crypto_logger.log_envio_grupo_melhorado(
            nome_grupo, remetente, mensagem, mensagem_cifrada, 
            grupo['chave_grupo_hex'], chaves_cifradas
        )
        
        return mensagem_cifrada, chaves_cifradas
    
    def decifrar_mensagem_grupo(self, nome_grupo: str, mensagem_cifrada: str, destinatario: str, chave_privada_pem: str = None):
        """RECEBIMENTO DE MENSAGEM - Conforme especificação"""
        groups = self._carregar_groups()
        
        if nome_grupo not in groups:
            raise ValueError(f"Grupo '{nome_grupo}' não existe")
        
        grupo = groups[nome_grupo]
        
        if destinatario not in grupo['membros']:
            raise ValueError(f"Destinatário '{destinatario}' não é membro do grupo")
        
        # Se não foi fornecida chave privada, carregar do arquivo
        if chave_privada_pem is None:
            chave_privada_path = f"keys/{destinatario}/privada.pem"
            chave_privada_pem = RSAManager.carregar_chave_privada(chave_privada_path)
        
        # Decifrar usando chave do grupo
        chave_grupo_int = int(grupo['chave_grupo_hex'], 16)
        grupo_idea = IDEA(chave_grupo_int)
        
        mensagem_decifrada = grupo_idea.decifrar_cbc(mensagem_cifrada)
        
        # Log detalhado
        crypto_logger.log_recebimento_grupo_melhorado(
            nome_grupo, destinatario, mensagem_cifrada, mensagem_decifrada,
            grupo['chave_grupo_hex'], chave_privada_pem
        )
        
        return mensagem_decifrada
    
    def ver_historico_grupo(self, nome_grupo: str, usuario: str):
        #MELHORADO: Ver histórico de mensagens do grupo com verificação automática
        groups = self._carregar_groups()
        
        if nome_grupo not in groups:
            raise ValueError(f"Grupo '{nome_grupo}' não existe")
        
        grupo = groups[nome_grupo]
        
        if usuario not in grupo['membros']:
            raise ValueError(f"Usuário '{usuario}' não é membro do grupo")
        
        historico = grupo.get('historico_mensagens', [])
        
        # Verificação automática de acesso
        historico_com_acesso = []
        chave_privada_path = f"keys/{usuario}/privada.pem"
        chave_privada = RSAManager.carregar_chave_privada(chave_privada_path)
        
        for msg in historico:
            # Tenta descriptografar automaticamente cada mensagem
            try:
                chave_grupo_int = int(grupo['chave_grupo_hex'], 16)
                grupo_idea = IDEA(chave_grupo_int)
                texto_decifrado = grupo_idea.decifrar_cbc(msg['mensagem_cripto'])
                
                #  informação de acesso bem-sucedido
                msg_com_acesso = msg.copy()
                msg_com_acesso['acesso_permitido'] = True
                msg_com_acesso['mensagem_decifrada'] = texto_decifrado
                historico_com_acesso.append(msg_com_acesso)
                
            except Exception as e:
                # Acesso negado
                msg_com_acesso = msg.copy()
                msg_com_acesso['acesso_permitido'] = False
                msg_com_acesso['erro'] = str(e)
                historico_com_acesso.append(msg_com_acesso)
        
        return historico_com_acesso
    
    
    def listar_grupos_usuario(self, usuario: str):
        groups = self._carregar_groups()
        grupos_usuario = []
        
        for nome_grupo, grupo in groups.items():
            if usuario in grupo['membros'] and grupo['ativo']:
                grupos_usuario.append({
                    'nome': nome_grupo,
                    'admin': grupo['admin'],
                    'membros': grupo['membros']
                })
        
        return grupos_usuario
    
    def listar_grupos_admin(self, admin: str):
        groups = self._carregar_groups()
        grupos_admin = []
        
        for nome_grupo, grupo in groups.items():
            if grupo['admin'] == admin and grupo['ativo']:
                grupos_admin.append({
                    'nome': nome_grupo,
                    'membros': grupo['membros']
                })
        
        return grupos_admin
    
    def _carregar_groups(self):
        with open(self.groups_file, 'r') as f:
            return json.load(f)
    
    def _salvar_groups(self, groups):
        with open(self.groups_file, 'w') as f:
            json.dump(groups, f, indent=2)