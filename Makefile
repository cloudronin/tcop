PYTHON ?= python3
PYTHONPATH := src
ARTIFACTS ?= artifacts/verify

# Developer-only shortcuts.  The installed `tcop` CLI is the public TCOP
# contract; no research logic is implemented in this Makefile.
.PHONY: schema test verify benchmark experiments research-regression research-witness research-reliability research-confirmation research-minimality research-minimality-core research-minimality-combinations research-minimality-validation research-federated-v0.6 research report clean

schema:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m tcop.schema_check

test:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m unittest discover -s tests -v

benchmark:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m tcop.cli benchmark --all --artifact-dir $(ARTIFACTS)

experiments:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m tcop.cli experiments --artifact-dir artifacts/experiments

research-regression: schema test
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m tcop.cli regression --artifact-dir artifacts/regression-v0.1
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m tcop.cli experiments --artifact-dir artifacts/regression-v0.1/experiments

research-witness: schema test
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m tcop.cli witness --artifact-dir artifacts/witness-v0.2

research-reliability: schema test
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m tcop.cli reliability --artifact-dir artifacts/reliability-v0.3

research-confirmation: schema test
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m tcop.cli confirmation --artifact-dir artifacts/confirmation-v0.4

research-minimality: schema test
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m tcop.cli minimality --stage all --artifact-dir artifacts/minimality-v0.5

research-minimality-core: schema test
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m tcop.cli minimality --stage core --artifact-dir artifacts/minimality-v0.5

research-minimality-combinations: schema test
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m tcop.cli minimality --stage combinations --artifact-dir artifacts/minimality-v0.5

research-minimality-validation: schema test
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m tcop.cli minimality-validation --source artifacts/minimality-v0.5 --artifact-dir artifacts/minimality-v0.5-validation

# This target performs the v0.6 atomic sequence: frozen-input verification,
# strategy certification, harness conformance, replay, full matrix, reports,
# and artifact verification. It writes only to the v0.6 artifact root.
research-federated-v0.6: schema test
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m tcop.cli study reproduce --plan benchmark/studies/v0.6-federated.yaml --selection full --source artifacts/minimality-v0.5-validation --output artifacts/federated-domain-v0.6

research: research-regression research-witness research-reliability research-confirmation research-minimality research-federated-v0.6

verify: schema test
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m tcop.cli verify --artifact-dir $(ARTIFACTS)

report: verify
	@echo "Report: $(ARTIFACTS)/benchmark-report.md"

clean:
	rm -rf $(ARTIFACTS)
