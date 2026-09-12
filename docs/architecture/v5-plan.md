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

## Product goals

CLAASP is first a usable workbench for cipher designers and cryptanalysts.
The typed architecture is an implementation technique, not terminology that
users should have to understand before completing common tasks.

The public API must make these workflows straightforward:

1. Describe a cipher at approximately the level of its published pseudocode.
2. Evaluate one vector or a batch without learning graph internals.
3. Run standard analyses, including avalanche tests, trail search, and key
   recovery, through a small and consistent API.
4. Inspect, reproduce, export, and cite the exact model and solver result
   behind an analysis.

Usability is a release requirement, not post-release polish. In particular:

- A whole port is accepted wherever a whole-port selection is expected;
  users should write `state`, not `state.select_all()`.
- Indexed selection uses ordinary subscription, for example
  `key[13, 14, 15, 12]`; the explicit selection API may remain as a lower-level
  facility.
- Component identifiers are deterministic and unique by default. An explicit
  identifier remains available for stable external references and is
  validated for uniqueness.
- Reusable finite-field arithmetic, rotations, standard matrices, S-box
  construction, round constants, and state-layout helpers live in shared
  library modules instead of individual cipher implementations.
- Common construction operations have concise builder methods and sensible
  inference. Domain and shape errors remain early and precise.
- Common analyses require only the cipher, analysis parameters, and optional
  solver choice. Backend IRs and solver command details remain available to
  advanced users but are not required for the usual workflow.

Every usability feature must have a short executable example and at least one
representative cipher written with the public API. AES is the primary
construction and getting-started example; MiMC and Poseidon illustrate the
arithmetization-oriented extensions in a dedicated v5 section.

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
- Compare v4 and v5 outputs, reduced-round behavior, graph structure, and
  supported parameter variants without retaining v4 APIs in the v5 core.
- Inventory every legacy AES, PRESENT, and Speck test and classify it as
  migrated, superseded with an equivalent assertion, deferred with a reason,
  or inapplicable.
- Retain both authoritative published vectors and the semantic expectations
  from existing CLAASP regression tests.

Exit criterion: the three reference ciphers have a reviewed parity matrix;
all applicable legacy assertions execute against v5 or an explicit
differential harness, and any intentional graph-structure difference is
recorded.

### M9.1: Cipher-authoring usability

- Add whole-port coercion, subscription-based selection, and deterministic
  automatic component identifiers.
- Design concise cipher-builder helpers without hiding component semantics or
  weakening graph validation.
- Extract AES-local field arithmetic, byte rotation, MixColumns construction,
  constants, and layout operations into tested reusable modules.
- Rewrite the v5 AES implementation as the acceptance example and compare its
  readability with the published pseudocode and the legacy CLAASP AES class.
- Apply the same API to at least one bit cipher, one ARX cipher, and one
  arithmetization-oriented primitive to prevent AES-specific shortcuts.

Exit criterion: the AES implementation contains round/key-schedule logic but
no private generic finite-field or rotation implementation; routine
components need no manual identifiers or `select_all()` calls; the concise API
and lower-level explicit API produce equivalent validated graphs.

### M9.2: CLAASP-wide documentation

- Make the documentation landing page describe CLAASP as a whole rather than
  presenting the site as documentation only for v5 internals.
- Use AES for the main getting-started path: construct or import it, evaluate a
  standard vector, inspect it, and launch a simple analysis.
- Move typed units, AO primitives, architectural changes, and migration notes
  into a clearly labeled “What is new in CLAASP 5” section.
- Add task-oriented guides for implementing a cipher and analyzing a cipher;
  keep backend and IR material in an advanced/reference section.
- Preserve executable doctests and warning-free generated HTML for the full
  site.

Exit criterion: a new user can reach a successful AES evaluation from the
landing page, and can find a minimal cipher-authoring and analysis example
without first reading domain, port, selection, or lowering terminology.

### M10: Analysis and tooling migration

M10 is split into ordered, reviewable increments. A later backend may reuse
the analysis contracts and semantic models of an earlier increment, but
backend-specific encodings do not become component methods.

#### M10.0: Boolean execution foundation — achieved

- Solver-independent Boolean CNF and DIMACS export.
- Optional MiniSat execution, named assumptions, assignments, and dedicated
  integration CI.

#### M10.1: Analysis contracts and constraint API

- Define backend-neutral fixed-value, equality/inequality, nonzero, weight,
  objective, and model-projection concepts.
- Provide concise constraints over named inputs, outputs, components, slices,
  and rounds without exposing DIMACS variable names.
- Define stable results for status, trail values, weights, timings, solver
  metadata, and reproducibility information.
- Design the simple user-facing analysis facade before expanding solver
  coverage. Raw model/export APIs remain supported for research workflows.

Exit criterion: a documented example fixes plaintext/ciphertext and recovers
an unknown key through the public API; result projection uses graph objects or
logical names rather than encoded solver identifiers.

#### M10.2: SAT cipher and key-recovery models

- Complete Boolean lowering for the component subset needed by selected
  reference ciphers, with explicit word/byte-to-bit lowering where required.
- Support cipher inversion, partial input/output constraints, enumeration,
  blocking clauses, and solution limits.
- Cross-check SAT solutions with scalar evaluation and reproduce applicable
  legacy SAT cipher-model tests.

Exit criterion: reduced-round key-recovery examples for a bit cipher and a
traditional byte/word cipher reproduce known plaintext/ciphertext pairs and
are verified by evaluation.

#### M10.3: Differential and linear trail analysis

- Define shared difference, mask, transition-weight, trail, and optimization
  semantics independently of SAT/SMT/MILP/CP syntax.
- Implement XOR differential and XOR linear trail search for representative
  SPN and ARX ciphers, followed by truncated, impossible, and related models
  selected from the legacy inventory.
- Preserve published/legacy expected characteristics, optimum weights, and
  UNSAT bounds as regression fixtures with provenance.

Exit criterion: a reviewed reference set reproduces the corresponding CLAASP
v4 and publication results on pinned solver versions; every reported trail is
independently checked against component transition semantics.

This milestone is delivered through reviewable checkpoints:

1. M10.3a defines backend-independent patterns, exact transition weights,
   trails, and independently checked S-box DDT/LAT semantics.
2. M10.3b adds SPN propagation/search and sourced PRESENT fixtures.
3. M10.3c adds ARX propagation/search and sourced Speck fixtures.
4. M10.3d ports the selected truncated and impossible models and completes
   the cross-backend regression inventory.

#### M10.4: SMT backend

- Lower the shared cipher and trail semantics to SMT and add open-source
  solver execution.
- Reproduce the applicable legacy SMT regression set and compare results with
  SAT on shared instances.

#### M10.5: MILP backend

- Lower the shared trail semantics to a solver-independent linear model.
- Provide at least one open-source MILP adapter; proprietary adapters remain
  optional and may not be required by the core or baseline CI.
- Reproduce applicable legacy MILP weights, feasibility bounds, and trail
  checks.

#### M10.6: CP backend

- Add MiniZinc/CP lowering and execution outside the core graph.
- Reproduce the selected legacy CP, ARX-optimized, truncated, impossible,
  boomerang, and differential-linear results according to the migration
  inventory.

#### M10.7: Statistical analysis

- Migrate avalanche and other non-solver analyses behind the same concise
  analysis entry point.
- Preserve legacy deterministic fixtures, statistical definitions, output
  schemas, and reproducible random seeding.

#### M10.8: Remaining tooling

- Migrate versioned serialization, diagrams, graph transformations, code
  generation, and compilers.
- Keep human-facing diagrams and generated code independent of analysis
  backends and verify them with legacy semantic fixtures where applicable.

Exit criterion for M10: the migration inventory contains no unclassified
legacy analysis/tooling tests; all release-scope entries are migrated or
superseded, and every deferral is recorded with rationale and ownership.

### M11: Integration and release

- Merge the latest `develop` into `claasp-v5`.
- Run combined, differential, and dependency-isolation tests.
- Rename `claasp_next` to `claasp` only after its public API is accepted.
- Stabilize in `develop`, publish prereleases, then release CLAASP 5.0.

### Documentation throughout all milestones

- Treat the generated site as CLAASP documentation; v5 architecture is one
  section of it, not the organizing principle of the introductory material.
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

Legacy CLAASP is a regression oracle as well as an implementation to replace.
Before migrating a cipher or analysis family, create a migration matrix that
records the legacy test path, scenario, expected result, source provenance,
v5 test path, and disposition. Tests need not retain the old API or internal
component identifiers, but they must retain every applicable semantic
assertion. Structural assertions are translated to typed-graph invariants or
explicitly documented when the new representation intentionally differs.

Cryptanalytic fixtures require stronger provenance than evaluation alone:

- record whether an expected trail, weight, bound, or distinguisher comes from
  a publication, an official submission, legacy CLAASP, or a newly derived
  result;
- preserve publication citations and legacy test locations alongside the
  fixture;
- pin solver/backend versions for reproduced results and distinguish exact
  optima from feasible examples or tolerance-based numerical results;
- independently validate returned trails and recovered keys rather than only
  accepting a solver's status;
- never update an expected cryptanalytic result merely to match a new model;
  investigate and record any discrepancy first.

The maintained inventory is
[`migration/v5-legacy-test-matrix.md`](migration/v5-legacy-test-matrix.md).

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

## Execution order from the current state

Unless this plan is explicitly revised, “next milestone” means the first
unfinished item in this order:

1. M10.2 SAT cipher/key recovery.
2. M10.3 differential and linear trail semantics and reference results.
3. M10.4–M10.8 backend, statistical, and tooling migration.
4. M11 integration and release.

The migration inventory is a maintained artifact, not a one-time search. It
must cover cipher construction/evaluation tests and the legacy SAT, CMS, SMT,
MILP, CP/MiniZinc, avalanche, graph, serialization, diagram, transformation,
and compiler test families. New tests merged into `develop` are classified at
each synchronization.

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
- [x] Dependency-free, one-graph-traversal batch evaluation and benchmark.
- [x] Initial sparse prime-field polynomial representation and graph lowering.
- [x] Singular polynomial exporter with executable integration test.
- [x] msolve exporter with explicit characteristic limit and integration test.
- [x] Direct and binary-chain power lowering with witnesses and statistics.
- [x] Word domain, ARX components, and initial Speck64/128 known-answer validation.
- [x] Byte-field S-box component and initial AES-128 known-answer validation.
- [x] Bit-vector S-box component and initial PRESENT-80 known-answer validation.
- [x] Solver-independent Boolean CNF lowering, witnesses, and DIMACS export.
- [x] Optional MiniSat execution with named assumptions and parsed assignments.
- [x] AES/PRESENT/Speck legacy regression inventory and semantic parity.
- [x] Concise component authoring, automatic IDs, indexing, and shared utilities.
- [x] Friendly packed-integer evaluation with direct cipher methods and explicit traces.
- [x] Graph-level analysis constraints, projections, results, and key-recovery facade.
- [x] CLAASP-wide, AES-first documentation with separate v5/AO and advanced sections.

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
| Dependency-free transposed batch backend | Achieved | Differential tests and benchmark harness |
| msolve polynomial exporter | Achieved | Native format, validation, and optional integration test |
| Traditional cipher reference implementations | Initial slice achieved | Published vectors for Speck64/128, AES-128, and PRESENT-80 |
| Legacy cipher regression parity (M9) | Achieved | Living matrix; AES-128/192/256, PRESENT-80/128, Speck32/64 and Speck64/96 |
| Cipher-authoring usability (M9.1) | Achieved | Whole-port coercion, indexing, automatic IDs, reusable primitives, concise ciphers |
| CLAASP-wide documentation (M9.2) | Achieved | AES-first introduction, simple analysis, and separate v5/AO section |
| Advanced polynomial lowering | Achieved | Direct/binary-chain policies, witnesses, and statistics |
| Boolean CNF and DIMACS analysis layer | Achieved | Dependency-free IR, PRESENT witness validation, and exporter |
| MiniSat execution adapter | Achieved | SAT/UNSAT results, named assumptions, timeouts, and dedicated CI |
| Analysis contracts and constraints (M10.1) | Achieved | Simple facade, graph-level constraints, projection, reproducible results |
| SAT cipher/key recovery (M10.2) | Achieved | Bit/word lowering, packed projections, inversion, enumeration, blocking, MiniSat Speck recovery |
| Differential/linear analysis (M10.3) | Next | Reproduce sourced legacy/publication trails, weights, and bounds |
| Shared trail semantics (M10.3a) | Achieved | Exact typed patterns, transitions, trails, PRESENT DDT/LAT checker |
| SPN trail search (M10.3b) | Achieved | Exact PRESENT-2 optimum, graph-derived semantics, independent trail/wiring checker |
| ARX trail search (M10.3c) | Achieved | Exact carry-pair semantics, Speck32/64-2 weight-1 optimum, independent checker |
| Truncated/impossible trails (M10.3d) | Next | Port selected legacy feasibility and UNSAT fixtures |
| SMT, MILP, and CP (M10.4–M10.6) | Planned | Shared semantics with independent external lowerings |
| Statistical analysis (M10.7) | Planned | Avalanche and related legacy behavior |
| Serialization, diagrams, transforms, compilers (M10.8) | Planned | Inventory-driven tooling migration |
