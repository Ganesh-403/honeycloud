# ══════════════════════════════════════════════════════════════════════════════
#  HoneyCloud-X  ·  Developer Makefile
#  Usage: make <target>
# ══════════════════════════════════════════════════════════════════════════════

.PHONY: help dev prod down logs test lint format \
        gen-key seed simulate train-ml clean

# ── Formatting ────────────────────────────────────────────────────────────────
GREEN  := \033[0;32m
YELLOW := \033[0;33m
CYAN   := \033[0;36m
RESET  := \033[0m

help:  ## Show this help
	@echo ""
	@echo "$(CYAN)  HoneyCloud-X – Available Commands$(RESET)"
	@echo "  ────────────────────────────────────────"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-18s$(RESET) %s\n", $$1, $$2}'
	@echo ""

# ── Environment ───────────────────────────────────────────────────────────────
.env:
	@echo "$(YELLOW)⚠  .env not found – copying .env.example$(RESET)"
	cp .env.example .env
	@echo "$(YELLOW)⚠  Set SECRET_KEY in .env before running:$(RESET)"
	@echo "   make gen-key"

gen-key:  ## Generate a secure SECRET_KEY and write it to .env
	@[ -f .env ] || cp .env.example .env
	@SK=$$(openssl rand -hex 32) && \
	  sed -i.bak "s|^SECRET_KEY=.*|SECRET_KEY=$$SK|" .env && rm -f .env.bak && \
	  echo "$(GREEN)✓  SECRET_KEY written to .env$(RESET)"

# ── Docker ────────────────────────────────────────────────────────────────────
dev: .env  ## Start development stack (hot-reload, DEBUG=true)
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build

prod: .env  ## Start production stack
	docker compose up --build -d
	@echo "$(GREEN)✓  Stack running$(RESET)"
	@echo "  Dashboard → http://localhost:80"
	@echo "  API Docs  → http://localhost:8000/docs"

down:  ## Stop and remove containers
	docker compose -f docker-compose.yml -f docker-compose.dev.yml down

logs:  ## Tail all container logs
	docker compose logs -f

logs-api:  ## Tail backend logs only
	docker compose logs -f backend

restart-api:  ## Restart backend container
	docker compose restart backend

# ── Python dev environment ────────────────────────────────────────────────────
venv:  ## Create backend virtualenv
	cd backend && python3 -m venv .venv && \
	  .venv/bin/pip install -q --upgrade pip && \
	  .venv/bin/pip install -r requirements.txt
	@echo "$(GREEN)✓  venv ready – activate with: source backend/.venv/bin/activate$(RESET)"

venv-test:  ## Install test dependencies into existing venv
	cd backend && .venv/bin/pip install -q pytest httpx pytest-asyncio

run-local: .env  ## Run backend locally without Docker
	cd backend && SECRET_KEY=$$(grep SECRET_KEY .env | cut -d= -f2) \
	  DATABASE_URL=sqlite:///./data/honeycloud.db \
	  ENVIRONMENT=development DEBUG=true \
	  .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# ── Testing ───────────────────────────────────────────────────────────────────
test:  ## Run full test suite
	cd backend && \
	  SECRET_KEY=test-secret-key-that-is-long-enough-32chars \
	  ENVIRONMENT=development DEBUG=true \
	  .venv/bin/pytest tests/ -v --tb=short

test-cov:  ## Run tests with coverage report
	cd backend && \
	  SECRET_KEY=test-secret-key-that-is-long-enough-32chars \
	  ENVIRONMENT=development DEBUG=true \
	  .venv/bin/pytest tests/ --cov=app --cov-report=term-missing

test-fast:  ## Run tests excluding slow ML tests
	cd backend && \
	  SECRET_KEY=test-secret-key-that-is-long-enough-32chars \
	  ENVIRONMENT=development DEBUG=true \
	  .venv/bin/pytest tests/ -v --ignore=tests/test_ml.py -x

# ── Code quality ──────────────────────────────────────────────────────────────
lint:  ## Lint with ruff
	cd backend && .venv/bin/ruff check app/ tests/

format:  ## Format with ruff
	cd backend && .venv/bin/ruff format app/ tests/

typecheck:  ## Type-check with mypy
	cd backend && .venv/bin/mypy app/ --ignore-missing-imports

# ── Demo / data ───────────────────────────────────────────────────────────────
seed:  ## Run attack simulation (30 events) via the API
	@echo "$(CYAN)Simulating 30 attacks…$(RESET)"
	@TOKEN=$$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
	  -F "username=admin" -F "password=admin123" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])") && \
	curl -s -X POST "http://localhost:8000/api/v1/simulate/?count=30" \
	  -H "Authorization: Bearer $$TOKEN" | python3 -m json.tool
	@echo "$(GREEN)✓  Events generated$(RESET)"

simulate: seed  ## Alias for seed

train-ml:  ## Train ML model on stored events
	@echo "$(CYAN)Training ML model…$(RESET)"
	@TOKEN=$$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
	  -F "username=admin" -F "password=admin123" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])") && \
	curl -s -X POST http://localhost:8000/api/v1/ml/train \
	  -H "Authorization: Bearer $$TOKEN" | python3 -m json.tool

# ── Cleanup ───────────────────────────────────────────────────────────────────
clean:  ## Remove generated data, reports, and Python caches
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	find . -name "*.db" -delete 2>/dev/null || true
	find . -name "*.db-shm" -delete 2>/dev/null || true
	find . -name "*.db-wal" -delete 2>/dev/null || true
	rm -rf backend/reports/*.csv backend/reports/*.xlsx backend/reports/*.txt 2>/dev/null || true
	rm -rf backend/data/ml_model.pkl 2>/dev/null || true
	@echo "$(GREEN)✓  Cleaned$(RESET)"

clean-docker:  ## Remove all containers, volumes, and images for this project
	docker compose down -v --rmi local
	@echo "$(GREEN)✓  Docker cleaned$(RESET)"
