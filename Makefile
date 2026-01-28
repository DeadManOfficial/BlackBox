# HexStrike AI - Makefile
# ========================
# Common operations and shortcuts

.PHONY: help install dev test lint format clean docker-build docker-up docker-down scope

# Default target
help:
	@echo "HexStrike AI - Available Commands"
	@echo "=================================="
	@echo ""
	@echo "Development:"
	@echo "  make install     - Install dependencies"
	@echo "  make dev         - Install dev dependencies"
	@echo "  make test        - Run test suite"
	@echo "  make test-cov    - Run tests with coverage"
	@echo "  make lint        - Run linters"
	@echo "  make format      - Format code"
	@echo "  make clean       - Clean build artifacts"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build  - Build Docker image"
	@echo "  make docker-up     - Start all services"
	@echo "  make docker-down   - Stop all services"
	@echo "  make docker-logs   - View service logs"
	@echo ""
	@echo "CLI:"
	@echo "  make scope       - Show authorized scope"
	@echo "  make scan        - Run example scan"
	@echo "  make pentest     - Start pentest workflow"
	@echo ""

# ==========================================================================
# DEVELOPMENT
# ==========================================================================

install:
	pip install -r requirements.txt

dev:
	pip install -r requirements.txt
	pip install pytest pytest-cov pytest-asyncio black isort flake8 mypy

test:
	python -m pytest tests/ -v

test-cov:
	python -m pytest tests/ --cov=modules --cov=cli --cov=wrappers --cov-report=term-missing --cov-report=html

test-fast:
	python -m pytest tests/ -q --tb=no

lint:
	flake8 modules/ cli/ wrappers/ --max-line-length=100
	mypy modules/ cli/ wrappers/ --ignore-missing-imports

format:
	black modules/ cli/ wrappers/ tests/
	isort modules/ cli/ wrappers/ tests/

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name ".coverage" -delete 2>/dev/null || true
	rm -rf htmlcov/ 2>/dev/null || true
	rm -rf dist/ build/ 2>/dev/null || true

# ==========================================================================
# DOCKER
# ==========================================================================

docker-build:
	docker build -t hexstrike-ai:latest .

docker-up:
	docker-compose up -d

docker-up-all:
	docker-compose --profile monitoring up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

docker-shell:
	docker-compose exec hexstrike-api /bin/bash

docker-clean:
	docker-compose down -v --rmi local

# ==========================================================================
# CLI SHORTCUTS
# ==========================================================================

scope:
	python -m cli.main scope show

scope-confirm:
	python -m cli.main scope confirm

scan-nuclei:
	@read -p "Enter target URL: " target; \
	python -m cli.main scan nuclei $$target

pentest-status:
	python -m cli.main pentest status

modules:
	python -m cli.main -q modules list

health:
	python -m cli.main -q modules health

# ==========================================================================
# SECURITY TOOLS
# ==========================================================================

install-tools:
	@echo "Installing security tools..."
	@echo "Note: Some tools require Go or other dependencies"
	go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || true
	go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
	go install github.com/projectdiscovery/httpx/cmd/httpx@latest || true
	go install github.com/tomnomnom/gau@latest || true
	go install github.com/ffuf/ffuf@latest || true
	@echo "Done. Ensure Go bin is in PATH."

check-tools:
	@echo "Checking tool availability..."
	@which nuclei >/dev/null 2>&1 && echo "✓ nuclei" || echo "✗ nuclei"
	@which subfinder >/dev/null 2>&1 && echo "✓ subfinder" || echo "✗ subfinder"
	@which httpx >/dev/null 2>&1 && echo "✓ httpx" || echo "✗ httpx"
	@which nmap >/dev/null 2>&1 && echo "✓ nmap" || echo "✗ nmap"
	@which gobuster >/dev/null 2>&1 && echo "✓ gobuster" || echo "✗ gobuster"
	@which ffuf >/dev/null 2>&1 && echo "✓ ffuf" || echo "✗ ffuf"
	@which sqlmap >/dev/null 2>&1 && echo "✓ sqlmap" || echo "✗ sqlmap"

# ==========================================================================
# REPORTS
# ==========================================================================

report-generate:
	python -m cli.main pentest report --format markdown

report-view:
	@ls -la data/reports/ 2>/dev/null || echo "No reports found"

# ==========================================================================
# VERSION
# ==========================================================================

version:
	@echo "HexStrike AI v1.0.0"
	@python --version
	@pip --version
