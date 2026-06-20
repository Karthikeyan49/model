# Cybersecurity Specialist Model — task runner.
# `make help` lists targets. Mock backends mean most targets run with zero setup.

.PHONY: help install baseline sweep data curate index correlate test ci clean

PY ?= python3

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install: ## Install Python deps for the baseline
	$(PY) -m pip install -r baseline/requirements.txt

baseline: ## Run Phase 1 hybrid baseline (A/B/C arms + go/no-go)
	cd baseline && $(PY) run.py --config config.yaml

sweep: ## Run Phase 5 precision/recall FP-hardening sweep
	cd baseline && $(PY) sweep.py --config config.yaml

data: ## Phase 2: build training pairs from labeled programs
	cd training && $(PY) convert.py --config ../baseline/config.yaml --out-dir data

curate: data ## Phase 2: dedup + train/val split
	cd training && $(PY) curate.py --in data/train.jsonl --out-dir data

index: ## Build the live CVE index (set CSV=path/to/ICS-CERT_ADV.csv)
	cd retrieval && $(PY) cve_index.py build --csv $(CSV) --out index.json

correlate: ## Phase 4: correlate (set MANIFEST=... INDEX=...)
	cd engine && $(PY) correlate.py --manifest $(MANIFEST) --index $(INDEX)

test: ## Run the pytest suite
	$(PY) -m pytest -q tests/

ci: ## Byte-compile everything + run tests (what CI runs)
	$(PY) -m py_compile baseline/*.py training/*.py retrieval/*.py engine/*.py tools/*.py
	$(PY) -m pytest -q tests/

clean: ## Remove generated artifacts
	rm -rf baseline/out training/data/*.jsonl retrieval/index.json engine/*.md
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
