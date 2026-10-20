# CLAASP

CLAASP 5 is a Sage-independent Python framework for describing, evaluating, and
analysing cryptographic primitives. Describe a primitive once as an immutable,
typed graph, then reuse it for evaluation, cryptanalysis, and visualization.
The core supports CPython 3.11 and later with no runtime dependencies; compilers,
solvers, statistical tools, and ML frameworks are optional integrations.

## Getting started

Install from this checkout:

```bash
python -m pip install .
```

Evaluate a standard AES-128 test vector:

```python
from claasp.primitives import AES

cipher = AES()
result = cipher.evaluate(
    plaintext=0x00112233445566778899AABBCCDDEEFF,
    key=0x000102030405060708090A0B0C0D0E0F,
)
assert f"{result:032x}" == "69c4e0d86a7b0430d8cdb78070b4c55a"
```

## Documentation

Start with the [User guide](docs/user_guide.rst) and
[Getting started](docs/getting_started.rst). The guides cover:

- [Available primitives](docs/primitive_catalogue.rst) and
  [evaluating primitives](docs/evaluating_primitives.rst), including batch and
  non-binary inputs.
- [Defining primitives](docs/primitive_authoring.rst) and
  [reusable composite blocks](docs/composite_blocks.rst).
- [Cryptanalysis](docs/analysis.rst) and
  [displaying results](docs/displaying_results.rst).

To browse the documentation as HTML, build both guides locally:

```bash
python -m pip install '.[docs]'
make -C docs html
```

Open `docs/_build/user/user_guide.html` for the user guide or
`docs/_build/developer/developer_guide.html` for the developer guide.

## Contributing

Install the development tools and run the routine dependency-free suite:

```bash
python -m pip install -e '.[dev]'
python -m pytest
```

The default suite excludes external integrations and extended exhaustive tests.
Complete testing, documentation, and quality-check commands are in the
[contribution guide](docs/development.rst).

For the design, see the [v5 change summary](docs/architecture/v5-main-changes.md)
and [developer architecture guide](docs/architecture.rst).

The legacy v4 implementation and its Sage-based environment are retained in
the `v4-maintenance` branch. CLAASP is licensed under the
[GNU General Public License v3 or later](LICENSE).
