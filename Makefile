.PHONY: help bootstrap install install-all test test-cov lint format typecheck security verify pilot-confidence prov01-confidence base08-confidence vs01-confidence scale01-confidence base04-confidence base02-confidence base10-confidence dbpkg04-confidence dbpkg01-confidence dbx01-confidence dbx04-confidence dp03-confidence dp04-confidence dp05-confidence val01-confidence schemaint-confidence task11-confidence task12-confidence task24-confidence task25-confidence cv04-confidence spike02-confidence airep01-confidence aip05-confidence fail01-confidence orch01-confidence orch03-confidence clean

PYTHON ?= python3.12

help:
	@echo "SAS Modernization Factory developer commands"
	@echo ""
	@echo "  make bootstrap    Create .venv and install development dependencies"
	@echo "  make install      Install core + dev dependencies"
	@echo "  make install-all  Install all project extras"
	@echo "  make test         Run unit/integration tests"
	@echo "  make test-cov     Run tests with coverage"
	@echo "  make lint         Run Ruff lint checks"
	@echo "  make format       Format Python"
	@echo "  make typecheck    Run mypy"
	@echo "  make security     Audit Python dependencies"
	@echo "  make verify       Run lint, typecheck, tests, and security audit"
	@echo "  make base08-confidence  Run qualified local SAS reader confidence gates"
	@echo "  make vs01-confidence  Run the real local SAS7BDAT-to-Delta vertical slice"
	@echo "  make scale01-confidence  Run partitioned SAS7BDAT reader qualification"
	@echo "  make base04-confidence  Run canonical cross-provider descriptor qualification"
	@echo "  make base02-confidence  Run governed type and semantic mapping qualification"
	@echo "  make base10-confidence  Run governed Delta target mapping qualification"
	@echo "  make dbpkg04-confidence  Run restartable Spark-to-Delta ingestion qualification"
	@echo "  make dbpkg01-confidence  Run offline Unity Catalog validation planning confidence"
	@echo "  make dbx01-confidence  Run governed remote-execution boundary confidence"
	@echo "  make dbx04-confidence  Run immutable runtime-evidence receipt confidence"
	@echo "  make dp03-confidence  Run distributed aggregate reconciliation confidence"
	@echo "  make dp04-confidence  Run distributed null and distribution confidence"
	@echo "  make dp05-confidence  Run deterministic sample comparison confidence"
	@echo "  make val01-confidence  Run distributed cell reconciliation contract confidence"
	@echo "  make task12-confidence  Run aggregate tolerance policy confidence"
	@echo "  make task11-confidence  Run row-count tolerance policy confidence"
	@echo "  make schemaint-confidence  Run canonical schema integration confidence"
	@echo "  make task24-confidence  Run exception lifecycle confidence"
	@echo "  make cv04-confidence  Run deterministic sas2databricks package qualification"
	@echo "  make spike02-confidence  Characterize bounded sas2databricks construct coverage"
	@echo "  make airep01-confidence  Run bounded deterministic-plus-gateway repair confidence"
	@echo "  make aip05-confidence  Run offline prompt/model governance confidence"
	@echo "  make fail01-confidence  Run machine-actionable failure taxonomy confidence"
	@echo "  make orch01-confidence  Run canonical workload lifecycle confidence"
	@echo "  make orch03-confidence  Run governed retry and restart planning confidence"
	@echo "  make task25-confidence  Run certification-bundle contract confidence"
	@echo "  make clean        Remove generated local artifacts"

bootstrap:
	./scripts/bootstrap.sh

install:
	python -m pip install --upgrade pip setuptools wheel
	python -m pip install -e ".[dev]"

install-all:
	python -m pip install --upgrade pip setuptools wheel
	python -m pip install -e ".[dev,conversion,azure,databricks,ai,api]"

test:
	python -m pytest

test-cov:
	python -m pytest --cov=smf --cov-report=term-missing --cov-report=html

lint:
	python -m ruff check src tests

format:
	python -m ruff format src tests
	python -m ruff check --fix src tests

typecheck:
	python -m mypy src

security:
	python -m pip_audit

verify: lint typecheck test security

pilot-confidence:
	./scripts/test-pilot-selection-confidence.sh

prov01-confidence:
	./scripts/test-prov01-confidence.sh

base08-confidence:
	SMF_REQUIRE_SAS_READER=1 python -c "import pyreadstat; assert pyreadstat.__version__ == '1.3.6'"
	SMF_REQUIRE_SAS_READER=1 python -m pytest -q tests/unit/test_sas_binary_reader.py

vs01-confidence:
	SMF_REQUIRE_VS01=1 python -m pytest -q tests/integration/test_vs01_vertical_slice.py

scale01-confidence:
	./scripts/test-scale01-confidence.sh

base04-confidence:
	./scripts/test-base04-confidence.sh

base02-confidence:
	./scripts/test-base02-confidence.sh

base10-confidence:
	./scripts/test-base10-confidence.sh

dbpkg04-confidence:
	./scripts/test-db-pkg-04-confidence.sh

dbpkg01-confidence:
	./scripts/test-db-pkg-01-confidence.sh

dbx01-confidence:
	./scripts/test-dbx-01-confidence.sh

dbx04-confidence:
	./scripts/test-dbx-04-confidence.sh

dp03-confidence:
	./scripts/test-dp03-confidence.sh

dp04-confidence:
	./scripts/test-dp04-confidence.sh

dp05-confidence:
	./scripts/test-dp05-confidence.sh

val01-confidence:
	./scripts/test-val01-confidence.sh

task12-confidence:
	./scripts/test-task-12-confidence.sh

task11-confidence:
	./scripts/test-task-11-confidence.sh

schemaint-confidence:
	./scripts/test-schema-int-01-confidence.sh

task24-confidence:
	./scripts/test-task-24-confidence.sh

cv04-confidence:
	./scripts/test-cv04-confidence.sh

spike02-confidence:
	./scripts/test-spike02-confidence.sh

airep01-confidence:
	./scripts/test-airep01-confidence.sh

aip05-confidence:
	./scripts/test-aip05-confidence.sh

fail01-confidence:
	./scripts/test-fail01-confidence.sh

orch01-confidence:
	./scripts/test-orch01-confidence.sh

orch03-confidence:
	./scripts/test-orch03-confidence.sh

task25-confidence:
	./scripts/test-task25-confidence.sh

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage build dist *.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
