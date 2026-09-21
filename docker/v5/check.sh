#!/bin/sh
set -eu

cd /workspace
export MPLBACKEND=Agg
export MYPY_CACHE_DIR=/tmp/claasp-mypy-cache
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH=/workspace/src
export RUFF_CACHE_DIR=/tmp/claasp-ruff-cache

# A release check must be repeatable against the same mounted checkout.  Remove
# only project-owned generated outputs that can otherwise affect closure gates
# or make a later architecture inspect an earlier architecture's artifacts.
for generated_path in \
    /workspace/build \
    /workspace/dist \
    /workspace/docs/_build \
    /workspace/src/claasp.egg-info
do
    if [ -d "$generated_path" ]; then
        find "$generated_path" -depth -delete
    fi
done

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
python tools/release_tree_closure.py --check
python tools/private_release_candidate_closure.py --check
python tools/publication_preflight.py --check-plan
python tools/review_release_plan_closure.py --check

python -m pytest -m 'not external' -p no:cacheprovider
python -m pytest -m external -p no:cacheprovider
python -m pytest --doctest-modules src/claasp -p no:cacheprovider -q
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

python -m build
python tools/wheel_audit.py dist/*.whl
python tools/private_release_candidate_closure.py --check --artifacts dist/*
