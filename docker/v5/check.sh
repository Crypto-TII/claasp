#!/bin/sh
set -eu

cd /workspace/next
export MPLBACKEND=Agg
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH=/workspace/next/src

claasp-release-smoke

ruff format --check src tests tools docs/conf.py
ruff check src tests tools docs/conf.py
python tools/typecheck_closure.py --check
python tools/public_api_closure.py --check
python tools/documentation_quality_closure.py --check
python tools/repository_destination_closure.py --check
python tools/license_provenance_closure.py --check
python tools/release_environment_closure.py --check
python tools/upstream_reconciliation_closure.py --check
python tools/bidirectional_migration_audit.py --check

python -m pytest -m 'not external' -p no:cacheprovider
python -m pytest -m external -p no:cacheprovider
python -m pytest --doctest-modules src/claasp_next -p no:cacheprovider -q
make -C docs doctest
make -C docs html

python tools/legacy_inventory.py --check
python tools/legacy_inventory.py --check-model-closure
python tools/legacy_inventory.py --check-catalogue-classification
python tools/legacy_inventory.py --check-component-closure
python tools/legacy_inventory.py --check-primitive-closure
python tools/legacy_inventory.py --check-transformation-closure
python tools/legacy_inventory.py --check-component-analysis-closure
python tools/legacy_inventory.py --check-presentation-closure
python tools/legacy_inventory.py --check-tooling-closure
python tools/catalogue_closure.py --check
python tools/realization_closure.py --check
python tools/terminology_guard.py

python -m build --wheel
python tools/wheel_audit.py dist/*.whl
