# =========================================
# 🛠️ Makefile - CipherTalk Secure Channel
# =========================================

# Nome do ambiente virtual
VENV = .venv

# Caminho do Python dentro do ambiente
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip

# -------------------------
# 📦 Setup inicial do projeto
# -------------------------
setup:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	@echo "✅ Ambiente virtual criado e dependências instaladas!"

# -------------------------
# ▶️ Executar servidor
# -------------------------
run:
	$(PYTHON) -m uvicorn backend.main:app --reload

# -------------------------
# 🧪 Rodar testes
# -------------------------
test:
	$(PYTHON) -m pytest -v --disable-warnings

# -------------------------
# 📊 Cobertura de testes
# -------------------------
coverage:
	$(PYTHON) -m coverage run -m pytest
	$(PYTHON) -m coverage report -m

# -------------------------
# 🧹 Verificação de código (lint)
# -------------------------
lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m mypy .

# -------------------------
# 🔥 Limpar arquivos temporários
# -------------------------
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	rm -rf .pytest_cache .mypy_cache htmlcov .coverage
	@echo "🧹 Arquivos temporários removidos."

# -------------------------
# 📦 Atualizar dependências
# -------------------------
update:
	$(PIP) install --upgrade -r requirements.txt
	@echo "📦 Dependências atualizadas!"

# -------------------------
# 📦 Iniciar Banco de Dados
# -------------------------
db-init:
	python init_db.py
