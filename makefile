# ImpactGuard 3.1 Makefile
# Convenient commands for development and deployment

.PHONY: help install install-dev run test clean docker-build docker-up docker-down lint format security-check backup

# Default target
help:
	@echo "ImpactGuard 3.1 - Available Commands:"
	@echo "====================================="
	@echo "make install       - Install production dependencies"
	@echo "make install-dev   - Install development dependencies"
	@echo "make run          - Run the application"
	@echo "make test         - Run test suite"
	@echo "make lint         - Run code linting"
	@echo "make format       - Format code with black"
	@echo "make security     - Run security checks"
	@echo "make clean        - Clean temporary files"
	@echo "make docker-build - Build Docker images"
	@echo "make docker-up    - Start Docker containers"
	@echo "make docker-down  - Stop Docker containers"
	@echo "make backup       - Backup data and reports"

# Python virtual environment
VENV = venv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip

# Create virtual environment
$(VENV)/bin/activate: requirements.txt
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip setuptools wheel

# Install production dependencies
install: $(VENV)/bin/activate
	$(PIP) install -r requirements.txt
	@echo "✓ Production dependencies installed"

# Install minimal dependencies
install-minimal: $(VENV)/bin/activate
	$(PIP) install -r requirements-minimal.txt
	@echo "✓ Minimal dependencies installed"

# Install development dependencies
install-dev: $(VENV)/bin/activate
	$(PIP) install -r requirements.txt
	$(PIP) install ipython ipdb pytest pytest-cov black flake8 mypy bandit
	@echo "✓ Development dependencies installed"

# Run the application
run: $(VENV)/bin/activate
	@echo "Starting ImpactGuard 3.1..."
	$(PYTHON) -m streamlit run app.py

# Run tests
test: $(VENV)/bin/activate
	@echo "Running tests..."
	$(PYTHON) -m pytest tests/ -v --cov=impactguard --cov-report=html

# Run specific test file
test-file: $(VENV)/bin/activate
	@echo "Running test file: $(FILE)"
	$(PYTHON) -m pytest $(FILE) -v

# Run linting
lint: $(VENV)/bin/activate
	@echo "Running linting checks..."
	$(PYTHON) -m flake8 . --config=.flake8
	$(PYTHON) -m mypy . --config-file=mypy.ini

# Format code
format: $(VENV)/bin/activate
	@echo "Formatting code..."
	$(PYTHON) -m black . --config=pyproject.toml

# Security checks
security: $(VENV)/bin/activate
	@echo "Running security checks..."
	$(PYTHON) -m bandit -r . -f json -o security-report.json
	$(PYTHON) -m safety check --json

# Clean temporary files
clean:
	@echo "Cleaning temporary files..."
	find . -type f -name '*.pyc' -delete
	find . -type d -name '__pycache__' -delete
	find . -type d -name '*.egg-info' -delete
	rm -rf .pytest_cache
	rm -rf .mypy_cache
	rm -rf htmlcov
	rm -rf .coverage
	rm -f security-report.json
	@echo "✓ Cleanup complete"

# Docker commands
docker-build:
	@echo "Building Docker images..."
	docker-compose build

docker-up:
	@echo "Starting Docker containers..."
	docker-compose up -d
	@echo "✓ Application running at http://localhost:8501"

docker-up-dev:
	@echo "Starting development containers..."
	docker-compose --profile development up

docker-up-full:
	@echo "Starting full stack with monitoring..."
	docker-compose --profile monitoring --profile backup up -d

docker-down:
	@echo "Stopping Docker containers..."
	docker-compose down

docker-logs:
	docker-compose logs -f

docker-clean:
	@echo "Cleaning Docker resources..."
	docker-compose down -v
	docker system prune -f

# Database commands
db-migrate:
	@echo "Running database migrations..."
	$(PYTHON) -m alembic upgrade head

db-backup:
	@echo "Backing up database..."
	docker-compose exec postgres pg_dump -U postgres impactguard > backups/db_backup_$(shell date +%Y%m%d_%H%M%S).sql

db-restore:
	@echo "Restoring database from backup..."
	@echo "Usage: make db-restore FILE=backups/db_backup_20240120_120000.sql"
	docker-compose exec -T postgres psql -U postgres impactguard < $(FILE)

# Backup commands
backup:
	@echo "Creating backup..."
	mkdir -p backups/$(shell date +%Y%m%d)
	cp -r reports backups/$(shell date +%Y%m%d)/
	cp -r data backups/$(shell date +%Y%m%d)/
	cp .env backups/$(shell date +%Y%m%d)/
	tar -czf backups/backup_$(shell date +%Y%m%d_%H%M%S).tar.gz backups/$(shell date +%Y%m%d)
	rm -rf backups/$(shell date +%Y%m%d)
	@echo "✓ Backup created: backups/backup_$(shell date +%Y%m%d_%H%M%S).tar.gz"

# Development shortcuts
dev-setup: install-dev
	@echo "Setting up development environment..."
	cp .env.template .env
	mkdir -p reports data logs backups uploads tests
	@echo "✓ Development environment ready"

dev-reset:
	@echo "Resetting development environment..."
	rm -rf $(VENV)
	make clean
	make dev-setup

# Production deployment
deploy-check:
	@echo "Running pre-deployment checks..."
	make lint
	make test
	make security
	@echo "✓ All checks passed"

deploy-prod: deploy-check
	@echo "Deploying to production..."
	docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
	@echo "✓ Deployed to production"

# Monitoring
monitor-logs:
	@echo "Tailing application logs..."
	tail -f logs/*.log

monitor-metrics:
	@echo "Opening metrics dashboard..."
	open http://localhost:3000  # Grafana

# Utility commands
update-deps:
	@echo "Updating dependencies..."
	$(PIP) list --outdated
	$(PIP) install --upgrade -r requirements.txt

freeze-deps:
	@echo "Freezing current dependencies..."
	$(PIP) freeze > requirements.freeze.txt

check-env:
	@echo "Checking environment configuration..."
	@test -f .env || (echo "❌ .env file not found" && exit 1)
	@echo "✓ Environment configured"

# API testing
api-test:
	@echo "Testing API connections..."
	$(PYTHON) -m scripts.test_apis

# Generate documentation
docs:
	@echo "Generating documentation..."
	$(PYTHON) -m mkdocs build

docs-serve:
	@echo "Serving documentation..."
	$(PYTHON) -m mkdocs serve

# Performance profiling
profile:
	@echo "Running performance profiling..."
	$(PYTHON) -m cProfile -o profile.stats app.py

profile-view:
	@echo "Viewing profiling results..."
	$(PYTHON) -m pstats profile.stats

# Quick commands for common tasks
quick-test:
	$(PYTHON) -m pytest tests/test_basic.py -v

quick-run:
	streamlit run app.py --server.runOnSave=true

# CI/CD commands
ci-test:
	@echo "Running CI tests..."
	make lint
	make test
	make security

ci-build:
	@echo "Building for CI..."
	docker build -t impactguard:ci .

# Version management
version:
	@echo "ImpactGuard version 3.1.0"
	@$(PYTHON) --version
	@$(PIP) --version

# Installation verification
verify:
	@echo "Verifying installation..."
	@$(PYTHON) -c "import streamlit; print('✓ Streamlit:', streamlit.__version__)"
	@$(PYTHON) -c "import pandas; print('✓ Pandas:', pandas.__version__)"
	@$(PYTHON) -c "import plotly; print('✓ Plotly:', plotly.__version__)"
	@$(PYTHON) -c "import numpy; print('✓ NumPy:', numpy.__version__)"
	@echo "✓ All core dependencies verified"
