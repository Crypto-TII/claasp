# CLAASP v5 development plan

## Purpose

CLAASP v5 will replace the implicit bit-only graph with a typed graph whose
wires carry arrays of mathematical units.  The first new use case is native
prime-field evaluation for arithmetization-oriented primitives, while the
model must also describe traditional bit-, word-, and extension-field-based
primitives.

The new implementation is developed as the independently installable
`claasp-next` distribution under `next/`.  It must not import the legacy
`claasp` package.  Tests and migration tools may import both packages for
differential comparison.

## Non-goals for the initial implementation

- Source or serialization compatibility with CLAASP 4.
- Immediate migration of every cipher and analysis backend.
- A general-purpose computer algebra system.
- Automatic conversion between bits, integers, and field elements.
- Arbitrarily nested or heterogeneous port types.

## Architectural invariants

1. `claasp_next.core` and `claasp_next.domains` depend only on Python's
   standard library.
2. A domain describes mathematical semantics; a runtime representation does
   not define those semantics.
3. A value type is a homogeneous shape over one scalar domain.
4. Connections select logical units, not necessarily bits.
5. Components describe operations. Evaluation and analysis live in external
   backends.
6. Cross-domain conversions are explicit graph operations.
7. Unsupported backend/component/domain combinations fail explicitly.
8. Scalar evaluation is the correctness reference for optimized evaluators.
9. Every public API includes CLAASP-style examples that are executable as
   doctests.
10. Documentation builds are warning-free and are tested independently of
    Sage.

## Delivery milestones

### M0: Architecture and baseline

- Record architecture decisions and terminology.
- Inventory Sage imports and legacy features that need migration.
- Select reference ciphers and test vectors.
- Establish independent packaging and CI for `next/`.

### M1: Sage-independent typed core

- Implement immutable domains and value types.
- Implement ports, selections, components, rounds, and a validated cipher DAG.
- Support deterministic identifiers and versioned serialization.

Exit criterion: the core installs and imports on ordinary CPython without
Sage or solver packages.

### M2: Structural components

- Constant, identity, selection, concatenation, permutation, and output.
- The same permutation implementation must work for bits, extension-field
  elements, and prime-field elements.

### M3: Reference scalar evaluator

- Registry-based evaluation outside component classes.
- Pure-Python runtime values and arithmetic.
- Boundary validation with optional internal debug validation.
- Prime-field and binary-extension-field reference arithmetic.

### M4: Algebraic components

- Add, subtract, negate, multiply, inverse, power, and retirement of ambiguous
  operations whose semantics cannot be inferred.
- Linear maps parameterized by their coefficient domain.
- Keep XOR, shifts, rotations, Boolean operations, and integer modular
  addition in a separate bit-vector component family.

### M5: First primitives

- MiMC validates prime-field rounds and exponentiation.
- Poseidon or Poseidon2 validates vector states, partial rounds, and linear
  layers.
- Add authoritative known-answer tests and reduced-round configurations.

### M6: Batch evaluation

- Implement a backend with identical semantics to scalar evaluation.
- Make NumPy or native acceleration optional and benchmark-driven.
- Do not assume machine-word arrays can represent large prime fields.

### M7: Polynomial intermediate representation

- Sparse polynomials over an explicit coefficient domain.
- Variables, equations, grouping, provenance, and problem constraints.
- Configurable lowering of powers, including direct equations and addition
  chains.
- Built-in equation, degree, and incidence statistics.

### M8: Open-source algebra exporters

- Export Singular and msolve inputs.
- Verify reduced-round systems in at least one external backend.
- Treat solver runs as reproducible experiments, not automatic security
  claims.

### M9: Traditional-cipher validation

- Migrate representatives of bit-SPN, ARX, and byte/extension-field designs.
- Suggested validation set: PRESENT or GIFT, Speck, and AES or ToyAES.
- Compare v4 and v5 outputs without retaining v4 APIs in the v5 core.

### M10: Analysis and tooling migration

- Move SAT, SMT, MILP, and CP behavior into external lowering backends.
- Migrate serialization, diagrams, graph transformations, and compilers.
- Explicitly lower domains when a bit-oriented backend requires it.

### M11: Integration and release

- Merge the latest `develop` into `claasp-v5`.
- Run combined, differential, and dependency-isolation tests.
- Rename `claasp_next` to `claasp` only after its public API is accepted.
- Stabilize in `develop`, publish prereleases, then release CLAASP 5.0.

### Documentation throughout all milestones

- Add user-oriented examples and API documentation with each public feature.
- Write examples as executable doctests rather than unverified snippets.
- Build HTML documentation automatically using a modern responsive theme.
- Run both documentation doctests and Python-module doctests in CI.
- Treat warnings and broken internal references as CI failures.
- Add mathematical background and backend guides as the related features
  arrive; documentation is not postponed to the release milestone.

## Branch and synchronization policy

- `claasp-v5` is shared and is never rebased after publication.
- Feature branches target `claasp-v5`, not `develop`.
- Merge `origin/develop` approximately every two weeks, before milestones,
  and after relevant core or cipher-semantic changes.
- Classify incoming changes as ported, superseded, deferred, or inapplicable.
- Preserve CLAASP 4 through tags and, if needed, a maintenance branch instead
  of compatibility branches inside the v5 implementation.

## Testing policy

Tests accompany every milestone. Full polynomial tests arrive with M7, but
core invariants and evaluator correctness are never deferred. The test layers
are:

1. Fast dependency-free unit tests.
2. Algebraic and graph property tests.
3. Published known-answer tests.
4. Differential comparisons between legacy and v5 implementations.
5. Optional integration tests for external tools.

The minimal CI job installs only `next/` and runs its tests in an environment
without Sage.

## Initial vertical slice

The first architectural proof is:

```text
PrimeField
  -> typed three-element state
  -> constant/add/power/linear-map components
  -> scalar evaluator
  -> reduced-round Poseidon test
```

Polynomial representations and optimized evaluation follow only after this
path is correct and stable.

## Current implementation status

- [x] Parallel Sage-free distribution and independent CI.
- [x] Initial `Bit`, `PrimeField`, `BinaryExtensionField`, and `ValueType`.
- [x] Typed ports, logical-unit selections, rounds, and acyclic graph checks.
- [x] Domain-neutral constant, identity, concatenation, and permutation.
- [x] Pure-Python scalar evaluator with explicit component dispatch.
- [x] Addition, multiplication, power maps, and linear maps.
- [x] Minimal MiMC vertical slice.
- [x] Parameterized Poseidon full/partial-round vertical slice.
- [x] Pinned BN254/width-3 Poseidon parameters and reference vector.
- [x] Sage-free Sphinx site and doctest CI.
- [x] Correctness-first batch evaluation contract.
- [ ] Optimized batch evaluation.
- [x] Initial sparse prime-field polynomial representation and graph lowering.
- [x] Singular polynomial exporter with executable integration test.
- [ ] Further polynomial exporters and advanced lowering policies.

## Milestone tracker

| Area | Status | Commit or next action |
| --- | --- | --- |
| Architecture and isolated package | Achieved | `6b2a1b66` |
| Typed logical-unit graph | Achieved | `e683d05b` |
| Scalar field evaluation and MiMC | Achieved | `83cc02e7` |
| Parameterized Poseidon | Achieved | `e8ced5d9` |
| Documentation and doctest pipeline | Achieved | `ca5baa82` |
| Reference batch contract | Achieved | `2236b640` |
| Sparse prime-field polynomial IR | Achieved | `99e1f8f0` |
| Field validation and Singular export | Achieved | `da245951` |
| Pinned Poseidon parameter catalogue | Achieved | Bundled BN254/width-3 data and vector |
| Optimized batch backend | Planned | Benchmark representations first |
| Additional polynomial exporters | Planned | Select msolve interchange format |
| Traditional cipher validation | Planned | Speck, then AES/ToyAES |
| Legacy analysis migration | Planned | Begins after graph API stabilizes |
