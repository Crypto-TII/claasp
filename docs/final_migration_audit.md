# Final bidirectional migration audit

This generated M11a summary is review material; the JSON matrix and closure tool are authoritative.

- Legacy records: 581
- Shipped v5 artifacts: 408
- Legacy dispositions: inapplicable=34, migrate=332, remove=8, supersede=207
- Reverse classifications: legacy-lineage=367, new-v5=41

Every legacy record has a final migrated, superseded, removed, or out-of-scope disposition. Every shipped v5 artifact links to one or more legacy records or carries the category rationale shown below.

## New-v5 artifact rationale groups

### annotations

New immutable graph-annotation and execution-trace architecture has no single legacy file predecessor.

- `src/claasp/annotations/__init__.py`
- `src/claasp/annotations/base.py`

### catalogue

New immutable generated catalogue and query architecture replaces cross-cutting legacy discovery behavior.

- `src/claasp/catalogue/__init__.py`
- `src/claasp/catalogue/data/catalogue.json`

### composites

New reusable composite-block authoring layer has no direct legacy module predecessor.

- `src/claasp/composites/__init__.py`
- `src/claasp/composites/aes.py`
- `src/claasp/composites/arx.py`
- `src/claasp/composites/substitution.py`

### drivers

New bounded typed external-driver boundary separates tools and optional dependencies from core semantics.

- `src/claasp/drivers/__init__.py`
- `src/claasp/drivers/algebra/__init__.py`
- `src/claasp/drivers/algebra/base.py`
- `src/claasp/drivers/algebra/msolve.py`
- `src/claasp/drivers/algebra/singular.py`
- `src/claasp/drivers/native.py`
- `src/claasp/drivers/neural/__init__.py`
- `src/claasp/drivers/neural/sklearn_driver.py`
- `src/claasp/drivers/solvers/__init__.py`
- `src/claasp/drivers/solvers/base.py`
- `src/claasp/drivers/solvers/milp_results.py`
- `src/claasp/drivers/statistical/__init__.py`
- `src/claasp/drivers/statistical/parsers.py`

### parameters

New validated parameter-resource API makes packaged constants explicit and dependency-free.

- `src/claasp/parameters/__init__.py`
- `src/claasp/parameters/poseidon.py`

### representations

New typed lowering and execution architecture consolidates multiple mutable legacy model backends.

- `src/claasp/representations/__init__.py`
- `src/claasp/representations/base.py`
- `src/claasp/representations/diagrams/__init__.py`
- `src/claasp/representations/diagrams/ascii.py`
- `src/claasp/representations/diagrams/compiler.py`
- `src/claasp/representations/diagrams/formatting.py`
- `src/claasp/representations/diagrams/model.py`
- `src/claasp/representations/diagrams/tikz.py`

### root

New v5 package boundary, provenance, encoding, or public export authority has no single legacy predecessor.

- `src/claasp/__init__.py`
- `src/claasp/encoding.py`
- `src/claasp/primitive_inputs.py`
- `src/claasp/provenance.py`

### serialization

New canonical serialization architecture has no safe legacy serialization predecessor.

- `src/claasp/serialization/__init__.py`
- `src/claasp/serialization/errors.py`
- `src/claasp/serialization/execution.py`
- `src/claasp/serialization/primitive.py`

### utils

New dependency-free validated utility contract consolidates cross-cutting legacy helpers.

- `src/claasp/utils/__init__.py`
- `src/claasp/utils/matrices.py`
