PYTHON ?= python3.11

.PHONY: test doctest docs quality check clean

test:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src $(PYTHON) -m pytest -m 'not external' -p no:cacheprovider

doctest:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src $(PYTHON) -m pytest --doctest-modules src/claasp -p no:cacheprovider -q
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src $(MAKE) -C docs doctest

docs:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src $(MAKE) -C docs html

quality:
	$(PYTHON) -m ruff format --check src tests tools docs/conf.py
	$(PYTHON) -m ruff check src tests tools docs/conf.py
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src $(PYTHON) tools/typecheck_closure.py --check

check: quality test doctest docs

clean:
	$(MAKE) -C docs clean
	find . -type f -name '*.py[co]' -delete
	find . -type d -name '__pycache__' -empty -delete
