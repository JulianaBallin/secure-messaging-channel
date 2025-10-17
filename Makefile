# =========================================
# 🗄️ Makefile - CipherTalk Database Manager (versão geral e independente)
# =========================================
#
# Este Makefile gerencia o banco de dados e o ambiente de execução do CipherTalk.
# Comandos principais:
#   - setup: cria o ambiente virtual e instala dependências
#   - db-init, db-reset, db-run, db-inspect, db-clean, db-remove
# =========================================

# Caminhos e variáveis globais
VENV = .venv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip
DB_PATH = backend/database/cipher_talk.db
INIT_SCRIPT = backend/database/init_db.py
RUN_BANCO = backend/database/run_banco_dados.py
LOG_DIR = logs

# ======================================================
# 🐍 Ambiente virtual e dependências
# ======================================================
setup:
	@echo "🐍 Criando ambiente virtual e instalando dependências..."
	@python3 -m venv $(VENV)
	@$(PIP) install --upgrade pip
	@$(PIP) install -r requirements.txt
	@echo "✅ Ambiente virtual criado e dependências instaladas com sucesso!"

# ======================================================
# 🧱 Inicializar ou atualizar banco
# ======================================================
db-init:
	@echo "🔧 Inicializando banco de dados (criação/atualização)..."
	@python $(INIT_SCRIPT)
	@echo "✅ Banco verificado e pronto!"

# ======================================================
# ♻️ Recriar completamente o banco
# ======================================================
db-reset:
	@echo "♻️ Recriando banco do zero..."
	@python $(INIT_SCRIPT) --reset
	@echo "✅ Banco recriado com sucesso!"

# ======================================================
# 🗑️ Remover banco manualmente
# ======================================================
db-remove:
	@if [ -f $(DB_PATH) ]; then \
		rm $(DB_PATH); \
		echo "🧹 Banco removido: $(DB_PATH)"; \
	else \
		echo "⚠️ Nenhum banco encontrado em $(DB_PATH)"; \
	fi

# ======================================================
# 🧭 Executar painel CRUD
# ======================================================
db-run:
	@echo "🧭 Iniciando painel central do banco CipherTalk..."
	@python $(RUN_BANCO)


# ======================================================
# 🔍 Verificar banco
# ======================================================
db-inspect-full:
	@echo "🔍 Inspecionando todas as tabelas com todas as colunas..."
	@sqlite3 backend/database/cipher_talk.db ".mode column" ".headers on" "SELECT name FROM sqlite_master WHERE type='table';" | while read table; do \
		if [ -n "$$table" ]; then \
			echo "\n=== 📦 Tabela: $$table ==="; \
			sqlite3 backend/database/cipher_talk.db ".mode column" ".headers on" "SELECT * FROM $$table;"; \
		fi; \
	done

# ======================================================
# 🔍 Verificar estrutura do banco
# ======================================================
db-inspect:
	@echo "🔍 Estrutura atual do banco:"
	@sqlite3 $(DB_PATH) ".tables" || echo "⚠️ Banco não encontrado!"
	@echo ""
	@sqlite3 $(DB_PATH) ".schema users" 2>/dev/null | head -n 20 || true

# ======================================================
# 🧹 Limpar logs e caches
# ======================================================
db-clean:
	@echo "🧹 Limpando logs e temporários..."
	@if [ -d $(LOG_DIR) ]; then rm -rf $(LOG_DIR)/*.log; fi
	find backend/database -type d -name "__pycache__" -exec rm -rf {} +
	@echo "✅ Limpeza concluída."

# ======================================================
# 🧰 Ajuda
# ======================================================
help:
	@echo ""
	@echo "🗄️ Comandos disponíveis:"
	@echo "-----------------------------------------"
	@echo "  make setup       → Cria venv e instala dependências"
	@echo "  make db-init     → Cria ou atualiza o banco"
	@echo "  make db-reset    → Apaga e recria tudo"
	@echo "  make db-remove   → Remove o arquivo .db"
	@echo "  make db-run      → Abre painel CRUD interativo"
	@echo "  make db-inspect  → Mostra tabelas e schema"
	@echo "  make db-clean    → Limpa logs e caches"
	@echo "-----------------------------------------"
