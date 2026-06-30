.PHONY: install lint format test run refresh-schema build clean

install:        ## Install the package with dev + TUI extras
	pip install -e ".[dev,tui]"
	pre-commit install || true

lint:           ## Run ruff + mypy (what CI runs)
	ruff check src tests
	ruff format --check src tests
	mypy

format:         ## Auto-fix lint and format
	ruff check --fix src tests
	ruff format src tests

test:           ## Run the test suite
	pytest

run:            ## Launch the interactive builder
	mde-builder

refresh-schema: ## Pull the latest Defender schema from Microsoft
	mde-builder --refresh-schema

build:          ## Build sdist + wheel (needs the 'build' package)
	python -m build

clean:          ## Remove caches and generated output
	rm -rf build dist .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage *.egg-info src/*.egg-info
