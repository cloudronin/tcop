PYTHON ?= python3
PYTHONPATH := src
ARTIFACTS ?= artifacts/verify

.PHONY: schema test verify benchmark experiments research report clean

schema:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m tcop.schema_check

test:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m unittest discover -s tests -v

benchmark:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m tcop.cli benchmark --all --output $(ARTIFACTS)

experiments:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m tcop.cli experiments --output artifacts/experiments

research: verify experiments

verify: schema test
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m tcop.cli verify --output $(ARTIFACTS)

report: verify
	@echo "Report: $(ARTIFACTS)/benchmark-report.md"

clean:
	rm -rf $(ARTIFACTS)
