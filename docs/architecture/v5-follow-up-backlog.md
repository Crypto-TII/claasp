# CLAASP 5 follow-up backlog

This is a living engineering backlog for review findings that should not be
forced into one pull request. It is not user documentation and is not included
in a Sphinx table of contents.

The status labels describe the current working tree, not necessarily changes
already merged into the target branch:

- **In progress**: implemented or being implemented in the current worktree;
- **Next PR**: sufficiently defined follow-up work;
- **Research**: requires design or literature validation before implementation.

## Current documentation and first-use PR

Status: **In progress**

- Keep migration reports and audit terminology out of the user guide. User
  documentation must describe stable CLAASP concepts rather than migration
  events.
- Repair or remove links that expose internal migration material, including the
  broken transformation-page link to the inversion audit.
- Explain how to install the checked-out CLAASP 5 package before showing
  `from claasp ...` imports.
- Keep Getting started task-oriented and self-contained:
  - construct a familiar primitive;
  - show its available inputs without requiring `tuple(...)` or iterator
    terminology;
  - evaluate it;
  - define and inspect an execution trace;
  - perform one useful, small analysis and display its result;
  - link to a separate collection of quick analysis scripts;
  - remove the arbitrary "Next steps" list.
- Explain `ValueType` in Core concepts with keyword arguments, the one-element
  shape syntax `(4,)`, and a multidimensional example.
- Introduce realizations in Core concepts rather than in the AES walkthrough.
- Explain batch and transposed batch evaluation in plain language, using a
  conventional CLAASP primitive and import style.
- Keep generated HTML synchronized whenever an RST source changes.
- Keep RST user/developer pages at stable URLs. Store Markdown engineering
  records and audits under `docs/architecture/`.
- Provide contributing and test-running instructions in the developer guide.

Before opening the PR, verify both Sphinx builds and doctest suites and inspect
the generated Getting started and Transformations HTML pages.

## Trail result and report usability PR

Status: **In progress; split from the documentation PR before review**

- Return a first-class trail result that can be displayed with `trail.show()`.
- Display bit patterns without the redundant `/width` suffix when the table
  already establishes the value context.
- Reduce exact ratios to their smallest fraction; retain `1/1`, never values
  such as `4294967296/4294967296`.
- Show every state and key-schedule component transition. For the default
  single-key search, fix the key difference to zero and omit the resulting
  key-schedule-only transitions. Include the key schedule when a related-key
  search allows a nonzero key difference.
- Use the column names `Component` and `Component ID`; do not call the component
  an operation in the same table.
- Report:
  - optimality and the proved bound;
  - the actual search technique;
  - solver name and version when a solver is used;
  - end-to-end runtime;
  - measured peak memory, or an explicit `not reported` when it was not
    measured.
- Use Kissat, rather than MiniSat, as the current default for the supported
  Speck search. Keep solver choice explicit in result metadata, test the
  installed solver version reporting, and revisit the default when comparative
  benchmarks justify it.
- Ensure presentation code only renders structured metadata; it must not infer
  the search method or fabricate missing measurements.

## Analysis API ergonomics PR

Status: **Next PR**

Introduce a stable analysis namespace without placing an unbounded collection
of analysis methods directly on every primitive. The proposed user-facing form
is:

```python
trail = speck.analysis.find_trail(kind="xor_differential")
```

Design questions to settle in this PR:

- typed arguments or dedicated convenience methods for common trail kinds;
- discoverability and IDE completion;
- solver/backend selection without exposing backend internals to beginners;
- consistent return types for differential, linear, impossible, and other
  trail searches;
- compatibility policy for the current `analyze()` facade.

## Dependency-free Matsui search PR

Status: **Research**

Implement a genuine Matsui-style branch-and-bound trail search as the
dependency-free alternative. Do not describe bounded sparse enumeration as a
general trail-search technique.

Requirements:

- document the precise Matsui algorithm and pruning bounds implemented;
- keep it separate from the default solver-backed search unless benchmarks
  demonstrate that it is competitive for the requested problem;
- validate returned weights and transitions independently;
- test representative designs, including DES, an SPN, an ARX cipher, and a
  bitsliced design;
- record performance and scope limitations rather than implying universal
  efficiency.

## Constraint-model organization PR

Status: **Next PR**

Normalize where backend-specific component models live. The current placement
is inconsistent: S-box models, for example, are spread across SMT
`transitions.py`, MILP `sbox.py`, CP `trails.py`, and SAT `lowering.py`.

Target layout:

```text
representations/constraints/<backend>/
    components/
        sbox.py
        modular_add.py
        ...
    lowering.py
    model.py
    trails.py
```

Responsibilities:

- `components/`: backend-specific component encodings;
- `lowering.py`: select and compose component encodings;
- `model.py`: backend model containers and common infrastructure;
- `trails.py`: assemble complete trail-search problems, without defining local
  component encodings.

Use explicit class names when a component has several models, for example
`SBoxFunctionalSATModel`, `SBoxXorDifferentialSATModel`, and
`SBoxXorLinearSATModel`.

This should be a behavior-preserving move with import compatibility handled
deliberately and tests retained for each public model.

## Constraint-model provenance infrastructure PR

Status: **Next PR, after model organization**

References belong to the backend-specific constraint model that implements the
encoding. They do not belong to `component_analysis`, the component class, or a
presentation-layer lookup table.

Add structured provenance declared by each concrete model and propagated
through lowering and search results. At minimum it must identify:

- backend;
- component model and analysis kind;
- encoding name or variant;
- reference status;
- stable reference identifier when verified;
- exact source locator, such as a section, proposition, theorem, or equation;
- a short rationale for `N/A` or `TBD`.

Every backend/component/analysis-model combination must declare one of:

- `VERIFIED`: the primary source was inspected and the implemented constraints
  were matched to the cited construction;
- `N/A`: CLAASP uses a direct or exhaustive encoding not derived from a paper;
- `TBD`: a source or the correspondence with the code has not been verified.

The trail report should show a compact `Constraint model reference` for every
modeled component and a deduplicated bibliography after the table. The report
must use the provenance emitted by the model that actually generated the
constraints.

Add a coverage test that rejects a model with no explicit status. A
`VERIFIED` entry must have a primary-source URL or DOI and a precise locator.

## Constraint-model literature audit PRs

Status: **Research; split by backend or component family**

Audit references only after the provenance contract is in place. Do not infer
a constraint-model citation from a paper that merely introduced the
cryptanalytic concept.

In particular:

- Biham--Shamir may describe differential cryptanalysis and DDTs, but that
  does not make it a reference for a particular SAT, SMT, MILP, or CP S-box
  encoding.
- Matsui may describe linear cryptanalysis, but that does not make it a
  reference for a particular backend model of S-box linear propagation.
- Lipmaa--Moriai and Wallén are relevant candidates for modular-addition
  differential probabilities and linear correlations. They remain `TBD` as
  constraint-model references until the implemented Boolean or arithmetic
  constraints are matched to precise results in those papers.
- Straightforward truth-table, forbidden-assignment, selector, or finite-table
  encodings may correctly be `N/A` when no published construction was used.

Prefer several small audit PRs over one repository-wide literature claim.
Record unresolved cases as `TBD`; never guess.

## Repository migration-audit test PR

Status: **Next PR**

Review
`tests/unit/repository/test_bidirectional_migration_audit.py::test_committed_bidirectional_migration_audit_passes`.

- Measure where its runtime is spent.
- Decide whether it remains a release/repository contract, moves to an
  extended or CI-only suite, or can be removed now that the migration is
  complete.
- If retained, give it an explicit owner and scope rather than treating it as
  an ordinary module unit test.
- Remove user-facing references to the migration audit regardless of the test
  decision.
