# Use a project-local virtualenv so we never depend on a bare `pip` being on
# PATH, and never trip over macOS' "externally-managed-environment" (PEP 668).
# Override the base interpreter with: make install PYTHON=python3.12
PYTHON ?= python3
VENV   ?= .venv
PY     := $(VENV)/bin/python

.PHONY: help install lint format test run refresh-schema build clean

help:           ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

$(PY):          ## (internal) create the virtualenv
	$(PYTHON) -m venv $(VENV)
	$(PY) -m pip install --upgrade pip

install: $(PY)  ## Create venv + install package with dev/tui extras + hooks
	$(PY) -m pip install -e ".[dev,tui]"
	$(PY) -m pre_commit install || true
	@echo "\nDone. Activate the venv with:  source $(VENV)/bin/activate"
	@echo "Then run:  mde-builder   (or: $(PY) -m mdebuilder)"

lint:           ## Run ruff + mypy (what CI runs)
	$(PY) -m ruff check src tests
	$(PY) -m ruff format --check src tests
	$(PY) -m mypy

format:         ## Auto-fix lint and format
	$(PY) -m ruff check --fix src tests
	$(PY) -m ruff format src tests

test:           ## Run the test suite
	$(PY) -m pytest

run:            ## Launch the interactive builder
	$(PY) -m mdebuilder

refresh-schema: ## Pull the latest Defender schema from Microsoft
	$(PY) -m mdebuilder --refresh-schema

build:          ## Build sdist + wheel
	$(PY) -m pip install build
	$(PY) -m build

clean:          ## Remove caches and generated output (keeps the venv)
	rm -rf build dist .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage *.egg-info src/*.egg-info
