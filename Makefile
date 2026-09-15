# Open Authority Trials — METHOD_DEVELOPMENT_ONLY. Claim-bearing use PROHIBITED.
.DEFAULT_GOAL := help
PYTHON ?= python3
REFERENCE_RUN := examples/rb001/reference-run
SCENARIOS := scenarios/rb001

.PHONY: help install format lint typecheck test coverage build verify falsify demo ci clean

help: ## Show available targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  %-12s %s\n", $$1, $$2}'

install: ## Install the package and development tooling
	$(PYTHON) -m pip install -U pip
	$(PYTHON) -m pip install -e ".[dev]"

format: ## Apply formatting
	$(PYTHON) -m ruff format .
	$(PYTHON) -m ruff check --fix .

lint: ## Check formatting and lint rules
	$(PYTHON) -m ruff format --check .
	$(PYTHON) -m ruff check .

typecheck: ## Static type check
	$(PYTHON) -m mypy oat

test: ## Run the test suite
	$(PYTHON) -m pytest

coverage: ## Run tests under the coverage gate
	$(PYTHON) -m pytest --cov=oat --cov-report=term-missing --cov-fail-under=90

build: ## Build the sdist and wheel
	$(PYTHON) -m build

verify: ## Deterministic positive/control verification suite
	$(PYTHON) -m oat.cli run $(SCENARIOS)/VULN-A.json
	$(PYTHON) -m oat.cli run $(SCENARIOS)/VULN-B.json
	$(PYTHON) -m oat.cli run $(SCENARIOS)/CONTROL.json
	$(PYTHON) -m oat.cli verify $(REFERENCE_RUN)
	$(PYTHON) -m oat.cli inspect $(REFERENCE_RUN)
	$(PYTHON) -m pytest tests/test_rb001_vuln_a.py tests/test_rb001_vuln_b.py \
		tests/test_rb001_control.py tests/test_replay.py

falsify: ## Deliberate defect/tamper suite: the instrument must reject bad evidence
	$(PYTHON) -m pytest tests/test_tamper_detection.py tests/test_manifest_binding.py \
		tests/test_claim_quarantine.py

demo: ## Regenerate the checked-in reference run from frozen fixtures
	$(PYTHON) -m oat.cli demo --scenario $(SCENARIOS)/VULN-A.json --out $(REFERENCE_RUN)
	$(PYTHON) -m oat.cli replay $(REFERENCE_RUN)

ci: lint typecheck coverage build verify falsify demo ## Full local push gate
	@git diff --quiet -- $(REFERENCE_RUN) || \
		{ echo "FAIL: reference run is not reproducible from frozen fixtures"; exit 1; }
	@echo "LOCAL_CI_EQUIVALENT = PASS"

clean: ## Remove build and cache artifacts
	rm -rf build dist .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	find . -name '*.egg-info' -type d -prune -exec rm -rf {} +
