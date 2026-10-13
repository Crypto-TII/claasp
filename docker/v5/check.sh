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

case "${CLAASP_RELEASE_CHECK_PROFILE:-full}" in
    architecture-smoke)
        python -m pytest \
            tests/unit/unit_types \
            tests/unit/representations/execution \
            tests/unit/serialization \
            tests/unit/representations/source/test_c.py \
            tests/unit/primitives/block_ciphers/aes/test_package.py \
            tests/unit/primitives/permutations/test_chacha.py \
            -p no:cacheprovider
        python -m build
        python tools/wheel_audit.py dist/*.whl
        exit 0
        ;;
    full)
        ;;
    *)
        echo "unknown CLAASP_RELEASE_CHECK_PROFILE: ${CLAASP_RELEASE_CHECK_PROFILE}" >&2
        exit 2
        ;;
esac

ruff format --check src tests tools docs/conf.py
ruff check src tests tools docs/conf.py
python tools/typecheck_closure.py --check
python tools/public_api_closure.py --check
python tools/documentation_quality_closure.py --check

if [ -n "${CLAASP_DEPENDENCY_FREE_EXPRESSION:-}" ]; then
    python -m pytest -m "$CLAASP_DEPENDENCY_FREE_EXPRESSION" -p no:cacheprovider
else
    python -m pytest -m 'not external' -p no:cacheprovider
fi
if [ -n "${CLAASP_EXTERNAL_EXPRESSION:-}" ]; then
    python -m pytest -m "$CLAASP_EXTERNAL_EXPRESSION" -p no:cacheprovider
else
    python -m pytest -m external -p no:cacheprovider
fi
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
