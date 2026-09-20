# CLAASP

CLAASP 5 is a Sage-independent framework for describing, evaluating, and
analysing cryptographic primitives with immutable typed graphs. It supports
ordinary CPython 3.11 and later; compilers, solvers, statistical tools, and ML
frameworks are isolated optional integrations.

Development installation:

```bash
python -m pip install -e '.[dev]'
pytest
```

Run the dependency-free suite with:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
python -m pytest -m 'not external' -p no:cacheprovider
```

Complete test and documentation commands are in
[`docs/development.rst`](docs/development.rst).

The legacy v4 implementation and its Sage-based environment are retained in
the `v4-maintenance` branch, not in the CLAASP 5 release tree.
