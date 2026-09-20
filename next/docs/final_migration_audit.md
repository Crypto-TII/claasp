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

- `src/claasp_next/annotations/__init__.py`
- `src/claasp_next/annotations/base.py`

### catalogue

New immutable generated catalogue and query architecture replaces cross-cutting legacy discovery behavior.

- `src/claasp_next/catalogue/__init__.py`
- `src/claasp_next/catalogue/data/catalogue.json`

### composites

New reusable composite-block authoring layer has no direct legacy module predecessor.

- `src/claasp_next/composites/__init__.py`
- `src/claasp_next/composites/aes.py`
- `src/claasp_next/composites/arx.py`
- `src/claasp_next/composites/substitution.py`

### drivers

New bounded typed external-driver boundary separates tools and optional dependencies from core semantics.

- `src/claasp_next/drivers/__init__.py`
- `src/claasp_next/drivers/algebra/__init__.py`
- `src/claasp_next/drivers/algebra/base.py`
- `src/claasp_next/drivers/algebra/msolve.py`
- `src/claasp_next/drivers/algebra/singular.py`
- `src/claasp_next/drivers/native.py`
- `src/claasp_next/drivers/neural/__init__.py`
- `src/claasp_next/drivers/neural/sklearn_driver.py`
- `src/claasp_next/drivers/solvers/__init__.py`
- `src/claasp_next/drivers/solvers/base.py`
- `src/claasp_next/drivers/solvers/milp_results.py`
- `src/claasp_next/drivers/statistical/__init__.py`
- `src/claasp_next/drivers/statistical/parsers.py`

### parameters

New validated parameter-resource API makes packaged constants explicit and dependency-free.

- `src/claasp_next/parameters/__init__.py`
- `src/claasp_next/parameters/poseidon.py`

### representations

New typed lowering and execution architecture consolidates multiple mutable legacy model backends.

- `src/claasp_next/representations/__init__.py`
- `src/claasp_next/representations/base.py`
- `src/claasp_next/representations/diagrams/__init__.py`
- `src/claasp_next/representations/diagrams/ascii.py`
- `src/claasp_next/representations/diagrams/compiler.py`
- `src/claasp_next/representations/diagrams/formatting.py`
- `src/claasp_next/representations/diagrams/model.py`
- `src/claasp_next/representations/diagrams/tikz.py`

### root

New v5 package boundary, provenance, encoding, or public export authority has no single legacy predecessor.

- `src/claasp_next/__init__.py`
- `src/claasp_next/encoding.py`
- `src/claasp_next/primitive_inputs.py`
- `src/claasp_next/provenance.py`

### serialization

New canonical serialization architecture has no safe legacy serialization predecessor.

- `src/claasp_next/serialization/__init__.py`
- `src/claasp_next/serialization/errors.py`
- `src/claasp_next/serialization/execution.py`
- `src/claasp_next/serialization/primitive.py`

### utils

New dependency-free validated utility contract consolidates cross-cutting legacy helpers.

- `src/claasp_next/utils/__init__.py`
- `src/claasp_next/utils/matrices.py`
