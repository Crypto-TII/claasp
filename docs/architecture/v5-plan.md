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

### Primitive terminology and catalogue taxonomy

CLAASP means **Cryptographic Library for Automated Analysis of Symmetric
Primitives**. Version 5 therefore uses **primitive**, not **cipher**, as its
generic public term. The current ``Cipher`` graph class, ``ciphers`` package,
and related user-facing names are transitional implementation names and must
become ``Primitive``, ``primitives``, and corresponding primitive-oriented API
names in M10.9a. Historical CLAASP 4 paths and evidence may retain their real
legacy spelling. No compatibility alias is required for the unreleased v5 API.

All CLAASP primitives are fixed-length maps and are classified by mathematical
interface rather than by the variable-length construction that uses them:

- ``permutations``: unkeyed bijective fixed-length maps;
- ``functions``: unkeyed fixed-length maps not required to be bijective;
- ``block_ciphers``: keyed permutations;
- ``block_functions``: keyed fixed-length functions not required to be
  permutations;
- ``tweakable_block_ciphers``: tweak-parameterized keyed permutations;
- ``tweakable_block_functions``: tweak-parameterized keyed fixed-length
  functions not required to be permutations.

``single_component_primitives`` and ``toy_primitives`` remain useful
orthogonal catalogue folders. ``hash_functions``, ``macs``, and
``stream_ciphers`` are not primitive categories in v5: they denote
variable-length or stateful modes/constructions. When current CLAASP contains
one, the inventory must identify and migrate its underlying fixed-length
primitive into one of the six categories above, or explicitly classify the
high-level construction as outside the primitive catalogue.

Primitive modules and classes use the official primitive name without a
redundant category suffix: for example ``AES``, not ``AESBlockCipher``. A
suffix is allowed only when no independent official name exists and is needed
to distinguish an underlying primitive extracted from a higher-level mode or
construction. Naming decisions are recorded in the catalogue inventory to
avoid ad hoc exceptions and collisions.

## Product goals

CLAASP is first a usable workbench for primitive designers and cryptanalysts.
The typed architecture is an implementation technique, not terminology that
users should have to understand before completing common tasks.

The public API must make these workflows straightforward:

1. Describe a primitive at approximately the level of its published pseudocode.
2. Evaluate one vector or a batch without learning graph internals.
3. Run standard analyses, including avalanche tests, trail search, and key
   recovery, through a small and consistent API.
4. Inspect, reproduce, export, and cite the exact model and solver result
   behind an analysis.
5. Let researchers prototype new cryptanalysis techniques by composing and
   transforming models instead of rewriting a complete backend.

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
- Research APIs must support inspecting, adding, removing, and replacing
  constraints; choosing alternative component encodings globally or for one
  component; composing objectives and bounds; and preserving provenance
  through model transformations. Their detailed stable design is a dedicated
  future review, but current architecture must not prevent these workflows.

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

1. `claasp_next.graph` and `claasp_next.domains` depend only on Python's
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
11. CLAASP describes processing as ``SemanticType -> Representation ->
    Driver -> Result``. ``Target`` is reserved for the cryptanalytic target of
    an attack and is not used for compiler output formats.
12. Concrete traces, cryptanalytic trails, side-channel traces, and diagram
    annotations share graph-annotation infrastructure while retaining
    distinct semantic types.

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

### M9.3: Separate user and developer guides

- Build two independent HTML documentation sites from tested shared sources.
- Keep the User Guide task-oriented: cipher construction, evaluation,
  input/output formats, result verification, analysis, and result display.
- Keep backend IRs, lowering/compilation, architecture, extension points, and
  contribution workflows in the Developer Guide.
- Record the future migration of the legacy ``Report`` class and the stable
  researcher extension API without presenting unfinished internals as public
  contracts.

Exit criterion: both sites build warning-free and run their own doctests; a
user need not navigate backend internals, while a contributor can find the
compilation pipeline and cryptanalysis extension requirements directly.

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
5. M10.3e adds representative XOR-linear graph search and independently
   checked legacy fixtures before M10.3 as a whole is closed.
6. M10.3f adds ARX XOR-linear search and closes the representative reference
   set for M10.3.

#### M10.4: SMT backend

- Lower the shared cipher and trail semantics to SMT and add open-source
  solver execution.
- Reproduce the applicable legacy SMT regression set and compare results with
  SAT on shared instances.

This milestone is delivered in two checkpoints: M10.4a provides the portable
SMT representation, SMT-LIB exporter, Z3 adapter, and cipher/recovery parity;
M10.4b lowers the shared differential and linear trail semantics and restores
the selected legacy Z3 trail fixtures. M10.4b begins with component transition
relations (M10.4b1), followed by weighted differential composition and UNSAT
bounds (M10.4b2), then linear composition and the remaining legacy Z3
fixtures (M10.4b3). The linear increment separates SPN composition (M10.4b3a)
from the ARX/Speck legacy Z3 reference set (M10.4b3b).

#### M10.5: MILP backend

- Lower the shared trail semantics to a solver-independent linear model.
- Provide at least one open-source MILP adapter; proprietary adapters remain
  optional and may not be required by the core or baseline CI.
- Reproduce applicable legacy MILP weights, feasibility bounds, and trail
  checks.

M10.5 is delivered incrementally. M10.5a establishes the dependency-free
linear IR, deterministic LP export, optional open-source GLPK adapter, and
independent witness validation. M10.5b lowers exact weighted S-box trails and
restores the selected PRESENT optimum. M10.5c adds ARX relations and the
selected Speck regressions before the backend milestone closes.

#### M10.6: CP backend

- Add MiniZinc/CP lowering and execution outside the core graph.
- Reproduce the selected legacy CP, ARX-optimized, truncated, impossible,
  boomerang, and differential-linear results according to the migration
  inventory.

Deliver this broad migration through reviewable checkpoints:

1. **M10.6a — portable CP foundation.** Add an immutable MiniZinc
   representation, deterministic source serialization, a dependency-free CLI
   driver, portable results, documentation, and dedicated external CI.
2. **M10.6b — cipher lowering and recovery.** Lower the typed component subset
   needed by a selected reference cipher, project logical values, and restore
   the legacy fixed-input cipher result plus a key-recovery workflow verified
   independently by scalar evaluation.
3. **M10.6c — shared trail lowering.** Consume ``PropagationProblem`` for
   differential, linear, deterministic truncated, and impossible models;
   restore selected optimum, feasibility, and UNSAT fixtures with independent
   semantic checking.
4. **M10.6d — advanced CP analyses.** Inventory and migrate or explicitly
   supersede ARX-optimized, wordwise/probabilistic-truncated, boomerang,
   differential-linear, and continuous legacy models.

M10.6d is deliberately split by cryptanalytic semantics rather than by legacy
class hierarchy:

1. **M10.6d1 — advanced-suite inventory.** Classify every legacy MiniZinc
   model and result-bearing regression, select preserved scientific fixtures,
   and document whether it is migrated, superseded by a shared representation,
   or deferred with an explicit dependency.
2. **M10.6d2 — exact ARX differential optimization.** Compile modular-add
   XOR-differential support and probability weight composition, then prove the
   legacy Speck32/64 five-round optimum of weight 9 with an independently
   checked witness.
3. **M10.6d3 — generalized truncated propagation.** Add wordwise and
   probabilistic-truncated domains without encoding ``unknown`` as an accidental
   solver convention; preserve the selected Speck output-pattern fixtures.
4. **M10.6d4 — multi-round impossible search.** Compose forward and backward
   propagation and preserve selected legacy impossible-differential UNSAT
   results, including independent boundary checks.
5. **M10.6d5 — composed attacks.** Give boomerang and differential-linear
   models explicit shared semantic types, boundaries, objectives, and
   independently checked result fixtures.
6. **M10.6d6 — continuous models.** Separate floating-point heuristic models
   from exact CP proofs, document numerical tolerances, and migrate their
   result-bearing tests without presenting heuristic output as an exact proof.

M10.6c proceeds as M10.6c1 (native weighted SPN differential tables),
M10.6c2 (linear propagation), and M10.6c3 (deterministic-truncated and
impossible propagation). Each checkpoint must consume ``PropagationProblem``
and independently validate solver witnesses or UNSAT bounds.

M10.6d3 proceeds as M10.6d3a (typed probabilistic-truncated modular-add semantics
and fixed-cost fixtures), M10.6d3b (multi-round Speck composition and fixed
boundary-pattern results), and M10.6d3c (an explicit wordwise activity/value
domain and result-bearing SPN fixtures). Legacy declaration counts are not
acceptance criteria. M10.6d3c is split into M10.6d3c1 (the four-state typed
word abstraction and CP projection) and M10.6d3c2 (component composition and
a newly sourced SPN semantic fixture, since the enabled legacy suite contains
no fixed trail result).

M10.6d4 proceeds as M10.6d4a (fixture/dependency audit), M10.6d4b (a shared
forward/backward contradiction boundary and inverse graph propagation),
M10.6d4c (the legacy seven-round Speck UNSAT result), M10.6d4d1 (typed Simon
and its legacy fixed evaluation vectors), and M10.6d4d2 (the fixed Simon-32/64
eleven-round intermediate patterns). Hybrid-impossible encodings become component semantic
overrides rather than a parallel model hierarchy.

M10.6d5 proceeds as M10.6d5a (fixture and evidence audit), M10.6d5b1 (shared
composition contracts), M10.6d5b2 (exact bijective BCT semantics), M10.6d5b3a
(an exhaustive modular-add quartet oracle), M10.6d5b3b (an exact scalable
carry/borrow automaton), M10.6d5b3c (the legacy restricted Speck ARX switch and
selected empirical fixture), and M10.6d5c
(typed differential-linear composition and the fixed Speck weight-14 fixture).
Solver proofs and seeded statistical corroboration are reported separately.

#### M10.5d: Representation architecture realignment

Complete this cross-cutting milestone before starting the CP backend, so CP
does not reproduce the temporary package organization.

1. **M10.5d1 — terminology and contracts.** Define semantic type,
   annotation, representation, artifact, driver, result, and attack-target
   concepts. Add immutable graph annotations plus distinct execution-trace,
   cryptanalytic-trail, and side-channel-trace types.
2. **M10.5d2 — execution representations.** Move scalar and batch execution
   behind the representation/driver structure. Keep ``primitive.evaluate(...)``
   and ``primitive.evaluate_batch(...)`` as the ordinary user API; direct
   interpreters need not pretend to have exporters.
3. **M10.5d3 — constraint representations.** Group Boolean/CNF, SMT, MILP,
   CP, and polynomial forms under ``representations``. Separate representation
   construction and export from MiniSat, Z3, GLPK, and algebra-system drivers.
   Deliver this as M10.5d3a (SAT/MiniSat), M10.5d3b (SMT/Z3), M10.5d3c
   (MILP/GLPK), and M10.5d3d (polynomial/algebra-system drivers).
4. **M10.5d4 — semantics-driven trails.** Move differential, linear,
   differential-linear, division-property, avalanche, symbolic, and leakage
   semantics outside solver-specific packages. Solver representations lower a
   shared propagation problem and must not define its cryptanalytic meaning.
   Deliver M10.5d4a as the canonical semantic-type extraction, M10.5d4b as a
   backend-neutral propagation problem/registry, and M10.5d4c as migration of
   SMT and MILP composition to that shared problem.
5. **M10.5d5 — diagram representation.** Define a backend-neutral annotated
   diagram IR, then migrate ASCII art and add TikZ serialization. External
   LaTeX execution is a driver producing PDF; PNG/SVG rendering remains an
   independently testable representation or driver step.
6. **M10.5d6 — package vocabulary refinement.** Rename ``core`` to ``graph``
   and ``interpretations`` to ``semantics``. Use ``SemanticType`` and
   ``.semantics`` in public contracts so the API says concretely what values
   and abstract properties flow through a cipher graph.

Exit criterion: public workflows remain concise; internal examples can name
their semantics, representation, driver, and result independently; the
same graph annotation can be consumed by at least execution, trail checking,
and diagram rendering; and no use of ``target`` ambiguously means both an
attack goal and an output format.

#### M10.7: Complete legacy inventory and migration control

- Generate a machine-readable record for every legacy Python module and every
  legacy test module. Family-level prose is not sufficient coverage.
- Record path, responsibility, public entry points, dependencies, tests,
  fixed evidence, v5 destination, prerequisites, disposition, status, and
  acceptance criterion for every entry. Primitive entries additionally record
  their official name, one of the six v5 categories, proposed module/class
  names, and any higher-level construction from which the fixed-length
  primitive is extracted.
- Use the dispositions ``migrate``, ``supersede``, ``defer``, ``remove``, and
  ``inapplicable``. Every non-migration disposition requires a rationale.
- Make CI fail when a new legacy module or test appears without an inventory
  entry, while allowing the legacy tree to remain available as an oracle.
- Reconcile the inventory whenever ``develop`` is merged.

Exit criterion: all legacy modules and tests are classified; aggregate counts
match the filesystem; no release-scope entry has an unspecified destination.

#### M10.8: Remaining mathematical and solver models

- Migrate or explicitly supersede every remaining SAT, CryptoMiniSat, SMT,
  MILP, CP, algebraic, division-property, and specialized model.
- Extract monomial prediction, ANF recovery, algebraic-degree bounds, cube and
  superpoly problems, and monomial transitions from the paywalled Gurobi/Sage
  implementation into backend-neutral semantics and results.
- Provide an open-source baseline representation/driver for monomial and
  division-property analysis. Gurobi remains optional and cannot be required
  by the core package or baseline CI.
- Preserve exact result fixtures and distinguish them from heuristic or
  experimentally estimated claims.

M10.8 proceeds systematically from reusable semantics to whole-primitive
composition: M10.8a provides dependency-free Boolean ANFs, cube coefficients,
exact component monomial transitions, and an open-source MILP baseline;
M10.8b composes division-property/monomial transitions through typed primitive
graphs; M10.8c restores ANF, algebraic-degree, cube, superpoly, balanced-bit,
and parity fixtures; M10.8d closes the remaining SAT/CMS/SMT/MILP/CP/algebraic
inventory entries and optional optimized drivers.

M10.8b is delivered as M10.8b1 (a graph-derived PRESENT SPN round with exact
S-box transitions, structural concatenation/permutation, and an independent
witness checker), M10.8b2 (generic structural/Boolean component propagation),
and M10.8b3 (multi-round primitive composition plus portable solver lowering).
M10.8c begins with M10.8c1, an exact sparse Boolean symbolic evaluator and the
reduced Simon ANF/degree/superpoly fixtures. M10.8c2 preserves the complete
four-round Simon degree, fixed-public-input cube parity, and balanced-bit
evidence through a proof-qualified public result. M10.8c3 will add scalable
degree/parity methods and preserve the remaining Trivium and partial-ANF
fixtures; these bounds must remain distinct from exact expanded ANF degrees.
M10.8c3a first exposes exact partial ANFs as proof-carrying public evidence and
preserves the complete Simon-3 polynomial before scalable bound encodings are
introduced. M10.8c3b1 supplies a fast structural degree bound with explicit
``sound=True``/``complete=False`` metadata; it is a baseline, not a replacement
for the tighter legacy monomial predictor. M10.8c3b2 ports that tighter
backend-neutral reachability/parity model and its open-solver execution.
M10.8c3a2 adds an independent exact cube-sum verifier so recovered
coefficients can be tested against concrete primitive evaluation without Sage
or any solver.

#### M10.9: Complete component and primitive catalogue

##### M10.9a: Primitive terminology and public API

- Rename the generic graph abstraction from ``Cipher`` to ``Primitive`` and
  the public catalogue package from ``ciphers`` to ``primitives``.
- Replace generic user/developer vocabulary such as cipher graph, cipher
  input, and cipher evaluation with primitive graph, primitive input, and
  primitive evaluation. Retain “cipher” only where it is the mathematically
  correct category or part of an official name.
- Rename modules and classes to official primitive names, for example ``AES``
  rather than ``AESBlockCipher``. Document and inventory every necessary
  exception; do not retain aliases for the unreleased transitional v5 names.
- Update imports, annotations, serialization schemas, examples, doctests, and
  both guides atomically, with a repository check preventing new generic uses
  of the transitional terminology in public v5 code.

##### M10.9b: Fixed-length primitive classification

- Classify every legacy catalogue entry as ``permutations``, ``functions``,
  ``block_ciphers``, ``block_functions``, ``tweakable_block_ciphers``,
  ``tweakable_block_functions``, ``single_component_primitives``,
  ``toy_primitives``, or explicitly outside scope.
- Remove ``hash_functions``, ``macs``, and ``stream_ciphers`` as catalogue
  categories. Identify and migrate their underlying fixed-length primitives
  when present; do not mislabel the variable-length/stateful construction as a
  CLAASP primitive.
- Validate category invariants, including bijectivity obligations and the
  roles of key and tweak inputs, in catalogue metadata and tests.

##### M10.9c: Complete reusable component catalogue

- Migrate generic structural, Boolean, word/ARX, finite-field, feedback,
  permutation-specific, and conversion components before primitives duplicate
  their behavior privately.
- Move reusable helper algorithms out of individual primitive implementations
  and keep the authoring API close to published pseudocode.

##### M10.9d: Complete primitive implementations and evidence

- The default CLAASP 5.0 scope is every fixed-length primitive represented by
  the current catalogue. Removing or deferring an entry requires an explicit
  reviewed inventory decision; silence does not reduce scope.
- Migrate entries in component/dependency order into the v5 taxonomy, including
  all parameter families, toy primitives, and single-component fixtures.
- Preserve all applicable official and legacy vectors, parameter variants,
  reduced-round behavior, scalar/batch parity, and cryptanalytic fixtures.
- Record intentional exclusions explicitly; representative-family coverage is
  not completion of this milestone.

##### M10.9e: Primitive realizations and task-directed selection

- Treat a primitive as the mathematical fixed-length mapping and a
  ``realization`` as one typed graph implementing it. Do not create separate
  public primitive classes merely because one graph is lookup-based,
  bitsliced, word-oriented, matrix-based, or a dedicated circuit.
- Give every realization stable metadata describing capabilities, structural
  features, maturity, and provenance. Users can select it explicitly; an
  execution or analysis task can request capabilities and receive a
  deterministic compatible realization.
- Keep execution engines (Python, C, NumPy, CUDA) distinct from graph
  realizations. Record both in produced evidence and reports.
- Require identical external parameter and input/output contracts and preserve
  official vectors for every realization. Add differential equivalence tests
  across realizations and never assume their intermediate traces or trails
  have a component-by-component correspondence.
- Start with AES: retain the lookup-table S-box graph and add a genuine
  algebraic graph consisting of inversion in ``GF(2^8)`` followed by the
  binary affine transformation. Trail-oriented tasks can require S-box
  semantics while algebraic tasks can require explicit algebraic semantics.

#### M10.10: Primitive inversion and graph transformations

- Define inverse semantics per component and build inversion as a typed graph
  transformation independent of solver backends.
- Support retained auxiliary inputs, partial knowledge, equivalent recovered
  wires, and precise diagnostics when inversion stalls.
- Preserve legacy inversion tests and verify forward/inverse round trips for
  each supported component and representative complete primitives.
- Keep graph slicing, key-schedule removal, round reduction, and related
  editor transformations in the same validated transformation layer.

#### M10.11: Component analysis

- Return structured properties for S-boxes, linear layers, MixColumns,
  Boolean functions, and word operations through typed component semantics.
- Cover differential uniformity, nonlinearity, algebraic degree, branch
  numbers, operation grouping, and other applicable legacy properties.
- Implement small exact calculations without Sage where practical; place
  optional heavy algebra and plotting behind drivers consuming the same
  structured results.

#### M10.12: Dataset generation and statistical testing

- Define reproducible, streaming dataset generators for avalanche,
  correlation, CBC, random, low-density, and high-density experiments.
- Specify bit/byte ordering, seeds, sample construction, serialization, hashes,
  and provenance independently of NumPy and external statistical programs.
- Migrate avalanche analysis plus NIST STS and Dieharder drivers/parsers,
  preserving known-answer/parser fixtures and recording tool versions.
- Keep NIST STS and Dieharder optional; dataset generation remains usable in a
  minimal installation.

#### M10.13: Neural distinguishers

- Separate experiment and dataset specifications from machine-learning
  framework adapters.
- Migrate black-box and differential distinguishers, train/validation/test
  splitting, round/component projections, seeds, and result metadata.
- Keep TensorFlow/Keras or alternative frameworks optional and out of normal
  imports. Baseline CI tests deterministic datasets/contracts; a dedicated ML
  job runs bounded end-to-end experiments.
- Treat accuracy as tolerance/threshold-based experimental evidence, not an
  exact cross-platform fixture.

#### M10.14: Reports and result presentation

- Migrate the legacy ``Report`` capabilities onto typed analysis results.
- Provide concise tables, trail/trace views, plots, exportable data, evidence
  classification, citations, and reproducibility metadata.
- Keep presentation independent of solver and ML backends.

#### M10.15: Serialization, diagrams, and code generation

- Migrate versioned serialization, diagrams, generated Python/C/CUDA where in
  release scope, and remaining compiler/export workflows.
- Keep human-facing diagrams and generated code independent of analysis
  backends and verify them with legacy semantic fixtures where applicable.
- Complete routed ASCII art or retain its explicit work-in-progress status;
  do not silently substitute a structural listing.

Exit criterion for M10: the migration inventory contains no unclassified
legacy source or test module; all release-scope entries are migrated or
superseded, and every deferral/removal is recorded with rationale and
ownership. The complete catalogue, analyses, transformations, presentation,
and tooling pass their documented parity and dependency-isolation tests.

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
- Publish independently navigable User Guide and Developer Guide HTML sites.
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
That human-readable evidence matrix remains useful, but M10.7 introduces an
authoritative machine-readable module manifest and a generated coverage
summary. The manifest, rather than manually counted Markdown rows, determines
whether the inventory is complete.

The minimal CI job installs only `next/` and runs its tests in an environment
without Sage.

### Test performance and execution policy

Fast feedback is a correctness feature. The routine dependency-free suite
should remain measurable in seconds even when the catalogue grows: ordinary
unit tests should normally finish below one second each, and an individual
routine integration test should normally finish below ten seconds. A test
that exceeds ten seconds must be profiled, reduced, or explicitly justified
as a release/nightly regression; two-minute routine tests are not acceptable.
Reduced-round and reduced-width fixtures should establish semantics during
normal CI, while the smallest fixture retaining a published result belongs in
the solver-specific regression job.

Test execution follows four levels:

1. Run focused local tests while implementing a change.
2. Before each milestone commit, run the complete dependency-free suite and
   the affected external integration group.
3. At milestone-group checkpoints, run all tests in the canonical CLAASP
   Docker image, using the pinned solver intended by each regression.
4. Before release, run dependency-free, external, documentation, differential,
   and explicitly justified long-running jobs and archive their versions and
   results.

Local absence of a required optimized solver is reported as a skip, never by
silently selecting a fallback that turns a seconds-long regression into a
multi-minute timeout. In particular, the Speck32/64-5 CP optimum requires
Chuffed and has a 30-second guard. Reports must state passes, skips,
deselections, timeouts, environment, and solver; “all tests passed” is reserved
for a complete canonical run.

## Historical initial vertical slice

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

1. M10.8: migrate all remaining mathematical and solver models, including
   monomial prediction and division-property analysis.
2. M10.9a–M10.9d: establish primitive terminology and taxonomy, then migrate
   the complete reusable component and fixed-length primitive catalogues.
3. M10.10–M10.15: inversion/transformations, component analysis, datasets and
   statistical tests, neural distinguishers, reports, and remaining tooling.
4. M11 integration and release.

The migration inventory is a maintained artifact, not a one-time search. It
must cover every legacy source and test module, including ciphers, components,
SAT/CMS/SMT/MILP/CP/algebraic models, monomial prediction, division property,
inversion, component analysis, avalanche, datasets, NIST/Dieharder, neural
distinguishers, reports, graph utilities, serialization, diagrams,
transformations, and compilers. New paths merged into ``develop`` are
classified at each synchronization.

## Current focus

The milestone tracker below is the single source of implementation status; a
second checklist is intentionally not maintained. At this revision:

- The typed core, evaluation, initial AO primitives, representative traditional
  primitives, polynomial/Boolean foundations, usability, and documentation
  checkpoints are achieved as recorded in the tracker.
- M10.0–M10.5c are achieved at their recorded scope; the M10.7 inventory gate
  exposes future family-level omissions without retroactively weakening
  those accepted vertical slices.
- M10.5d remains open only for routed ASCII art.
- M10.6a–M10.6d4 are achieved.
- M10.6, including its advanced exact and heuristic analyses, is achieved.
- M10.7 is achieved: the exhaustive inventory and filesystem gate include the
  reconciled ``develop`` changes.
- M10.8 is next; M10.9–M10.15 and M11 remain planned.

## Milestone tracker

Status meanings are: **Achieved** (acceptance criteria pass), **In progress**
(implementation has committed partial checkpoints), **Next** (the immediate
execution-order checkpoint), **Queued** (ready after the current checkpoint),
**Planned** (specified but not started), and **Blocked** (a named prerequisite
is absent). Update this table in the same commit that changes milestone state.

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
| Traditional primitive reference implementations | Representative slice achieved | AES-128/192/256, PRESENT-80/128, multiple Speck variants, and all standard Simon configurations; names/packages remain transitional until M10.9a and the complete catalogue follows in M10.9d |
| Legacy cipher regression parity (M9) | Achieved | Living matrix; AES-128/192/256, PRESENT-80/128, Speck32/64 and Speck64/96 |
| Cipher-authoring usability (M9.1) | Achieved | Whole-port coercion, indexing, automatic IDs, reusable primitives, concise ciphers |
| CLAASP-wide documentation (M9.2) | Achieved | AES-first introduction, simple analysis, and separate v5/AO section |
| User/developer documentation split (M9.3) | Achieved | Two warning-free sites; research extension and Report requirements recorded |
| Advanced polynomial lowering | Achieved | Direct/binary-chain policies, witnesses, and statistics |
| Boolean CNF and DIMACS analysis layer | Achieved | Dependency-free IR, PRESENT witness validation, and exporter |
| MiniSat execution adapter | Achieved | SAT/UNSAT results, named assumptions, timeouts, and dedicated CI |
| Analysis contracts and constraints (M10.1) | Achieved | Simple facade, graph-level constraints, projection, reproducible results |
| SAT cipher/key recovery (M10.2) | Achieved | Bit/word lowering, packed projections, inversion, enumeration, blocking, MiniSat Speck recovery |
| Differential/linear analysis (M10.3) | Achieved | SPN/ARX differential and linear references, truncated/impossible slice, independent checkers |
| Shared trail semantics (M10.3a) | Achieved | Exact typed patterns, transitions, trails, PRESENT DDT/LAT checker |
| SPN trail search (M10.3b) | Achieved | Exact PRESENT-2 optimum, graph-derived semantics, independent trail/wiring checker |
| ARX trail search (M10.3c) | Achieved | Exact carry-pair semantics, Speck32/64-2 weight-1 optimum, independent checker |
| Truncated/impossible trails (M10.3d) | Achieved | Speck truncated fixture and exhaustive PRESENT S-box impossibility check |
| SPN XOR-linear trail search (M10.3e) | Achieved | PRESENT-3 weight-4 fixture, signed LAT entries, independent checker |
| ARX XOR-linear trail search (M10.3f) | Achieved | Exact Walsh carry semantics and restored Speck32/64-4 weight-3 characteristic |
| SMT cipher backend (M10.4a) | Achieved | Portable IR/SMT-LIB, optional Z3 adapter, full Speck legacy fixture |
| SMT trail backend (M10.4b) | Achieved | Exact S-box and modular-add relations, composed PRESENT optima, restored Speck reference transitions |
| SMT component transitions (M10.4b1) | Achieved | Complete S-box DDT/LAT support relations, Z3 SAT/UNSAT, semantic projection |
| SMT weighted differential trails (M10.4b2) | Achieved | PRESENT-2 composition, sequential weight bound, Z3 UNSAT-3/SAT-4 proof and checker |
| SMT weighted SPN linear trails (M10.4b3a) | Achieved | PRESENT-3 LAT composition, Z3 UNSAT-3/SAT-4 proof, signs and checker |
| SMT weighted ARX linear trails (M10.4b3b) | Achieved | Exact modular-add correlation relation; Z3 validates all four weight/sign transitions of the Speck32/64-4 reference |
| MILP trail backend (M10.5) | Achieved | Portable IR/GLPK plus exact PRESENT composition and modular-add Speck reference relations |
| Portable MILP foundation (M10.5a) | Achieved | Immutable linear IR, LP exporter, GLPK adapter, independent witness/objective checks, dedicated CI |
| Weighted SPN MILP trails (M10.5b) | Achieved | Complete DDT selectors over PRESENT-2; GLPK weight-4 optimum and independent 32-transition checker |
| Weighted ARX MILP trails (M10.5c) | Achieved | Exact parity/support relation; GLPK validates four Speck32/64-4 transitions, weights, and signs |
| Representation architecture (M10.5d) | In progress | Core layer separation achieved; routed ASCII-art serialization remains explicitly marked work in progress |
| Semantic-type/annotation contracts (M10.5d1) | Achieved | Extensible semantic types, immutable graph annotations, distinct trace types, representation artifacts, drivers, attack targets |
| Execution representation migration (M10.5d2) | Achieved | Scalar/batch modules moved under representations; canonical driver names; concrete ExecutionTrace results |
| Constraint representation migration (M10.5d3) | Achieved | SAT, SMT, MILP, and polynomial formats grouped under representations; external processes under drivers |
| SAT representation/driver split (M10.5d3a) | Achieved | CNF, lowering, and DIMACS under representations; MiniSat under drivers |
| SMT representation/driver split (M10.5d3b) | Achieved | SMT IR/export/lowering under representations; Z3 under shared solver drivers |
| MILP representation/driver split (M10.5d3c) | Achieved | Linear IR/export/trail lowering under representations; GLPK and result decoding under drivers |
| Polynomial representation/driver split (M10.5d3d) | Achieved | Polynomial IR/export/lowering under representations; reusable Singular/msolve execution drivers |
| Semantics-driven trail migration (M10.5d4) | Achieved | Canonical semantics, shared propagation problems/overrides, and SMT/MILP consumers |
| Canonical cryptanalytic semantics (M10.5d4a) | Achieved | Trail types and exact S-box/modular-add semantics moved from analysis to `semantics`; common graph annotations |
| Shared propagation problem (M10.5d4b) | Achieved | Immutable semantic registry with per-component overrides; graph scope, objective, bounds, and provenance |
| Shared propagation consumers (M10.5d4c) | Achieved | PRESENT SMT/MILP composition accepts one PropagationProblem and queries identical per-component overrides |
| Diagram representation (M10.5d5) | In progress | Annotated IR, TikZ/PDF, and temporary warned structural listing achieved; actual routed ASCII art remains |
| Graph/semantics vocabulary refactor (M10.5d6) | Achieved | `core` renamed to `graph`; `interpretations` renamed to `semantics`; public contracts use `SemanticType` and `.semantics`; no compatibility packages retained |
| SMT, MILP, and CP (M10.4–M10.6) | Achieved | Portable shared semantics and open-source drivers preserve selected exact, truncated, impossible, composed, and explicitly heuristic continuous evidence |
| CP backend (M10.6) | Achieved | Portable foundation, recovery, shared trails, advanced ARX/truncated/impossible/composed analyses, and qualified continuous heuristics |
| Portable CP foundation (M10.6a) | Achieved | Immutable MiniZinc IR, deterministic export, CLI driver, portable JSON results, external SAT/UNSAT tests |
| CP cipher lowering and recovery (M10.6b) | Achieved | Exact CNF-to-CP lowering reuses typed component semantics; graph-name projections; reduced recovery and full Speck legacy fixture independently evaluated |
| Shared CP trail lowering (M10.6c) | Achieved | Differential, signed-linear, deterministic-truncated, and local impossible fixtures use shared semantics and real MiniZinc tests |
| Native CP SPN differential trails (M10.6c1) | Achieved | PropagationProblem-selected DDT tables, PRESENT-2 UNSAT-3/SAT-4 proof, decoded trail independently checked |
| Native CP linear trails (M10.6c2) | Achieved | PropagationProblem-selected signed LAT tables, PRESENT-3 UNSAT-3/SAT-4 proof, decoded signs and wiring independently checked |
| Native CP truncated/impossible trails (M10.6c3) | Achieved | Truncated semantics moved into `semantics`; Speck paired-carry fixture projected through CP; exact PRESENT S-box possible/impossible proof |
| Advanced CP analyses (M10.6d) | Achieved | ARX optimization, generalized truncated, impossible and composed attacks, plus separately typed continuous heuristics |
| Advanced CP suite inventory (M10.6d1) | Achieved | Every legacy MiniZinc model classified; scientific fixtures, superseded structural tests, dependencies, and migration order recorded |
| Exact CP ARX differential optimization (M10.6d2) | Achieved | Chuffed proves Speck32/64-5 weight 8 UNSAT and weight 9 SAT in the CLAASP image; the five-transition witness is independently recounted and checked |
| Generalized CP truncated propagation (M10.6d3) | Achieved | Probabilistic-truncated Speck fixtures and typed wordwise AES propagation are independently checked and projected through CP |
| Probabilistic-truncated modular-add CP semantics (M10.6d3a) | Achieved | Typed partial transition, independent counter/cost checker, and Docker/Chuffed reproduction of legacy scaled costs 309 and 700 |
| Probabilistic-truncated Speck CP composition (M10.6d3b) | Achieved | Docker/Chuffed preserves the exact two-/three-round output patterns and weights 1.0/0.0; all additions and wiring are independently checked |
| Wordwise truncated CP semantics (M10.6d3c) | Achieved | Typed activity/value state plus graph-derived AES SubBytes/ShiftRows/MixColumns singleton propagation and CP projection |
| Wordwise activity/value domain (M10.6d3c1) | Achieved | Zero, known, nonzero, and unrestricted word differences use typed Python/native MiniZinc enums, with no legacy activity integers or value sentinels |
| Wordwise SPN composition (M10.6d3c2) | Achieved | A zero-key singleton byte difference becomes four guaranteed nonzero bytes in the graph-selected AES column; Docker verifies the typed CP projection |
| Multi-round CP impossible search (M10.6d4) | Achieved | Shared boundaries, Speck-7 UNSAT, and the exact Simon-11 fixed middle patterns are independently checked |
| Impossible-suite fixture audit (M10.6d4a) | Achieved | Selected Speck-7 UNSAT and fixed Simon-11 boundary/intermediate patterns; recorded typed-Simon dependency and rejected generated-line counts |
| Shared impossible boundary (M10.6d4b) | Achieved | Typed forward/backward patterns expose exact contradictory positions; sound inverse Speck subtraction/round propagation and Docker SAT/UNSAT boundary proofs are independently checked |
| Speck multi-round impossible CP (M10.6d4c) | Achieved | Directional forward/inverse Speck dataflows preserve the legacy seven-round, split-after-three UNSAT result with zero key difference in Docker/Chuffed |
| Simon fixed impossible fixture (M10.6d4d) | Achieved | Typed Simon plus the exact legacy 11-round external and middle-boundary patterns |
| Typed Simon prerequisite (M10.6d4d1) | Achieved | Typed word graph, reusable BitwiseAnd, all standard configurations, scalar/two batch evaluators, and four fixed legacy vectors |
| Simon-11 impossible CP fixture (M10.6d4d2) | Achieved | Six forward/five inverse rounds reproduce both fixed middle patterns and their bit-23 contradiction in Docker/Chuffed and independent Python semantics |
| CP composed attacks (M10.6d5) | Achieved | Typed boomerang and differential-linear contracts, exact switch semantics, fixed legacy witnesses, and independently checked exact-versus-heuristic objectives |
| Composed-attack fixture audit (M10.6d5a) | Achieved | Selected Speck boomerang and weight-14 differential-linear evidence; separated exact solver claims from sampled experiments and recorded typed-cipher dependencies |
| Shared composed-attack contracts (M10.6d5b1) | Achieved | Typed two-trail boomerang switch and differential/connector/linear results enforce boundary kinds and explicit objective formulas independently of CP |
| Exact bijective BCT semantics (M10.6d5b2) | Achieved | Exhaustive inverse-table definition, typed count/weight, PRESENT fixed possible/impossible entries, native CP table, and independent decoder |
| Modular-add boomerang oracle (M10.6d5b3a) | Achieved | Exact four-difference quartet equations and exhaustive counts for widths through 8 provide an independent oracle for scalable encodings |
| Exact modular-add switch automaton (M10.6d5b3b) | Achieved | Sixteen carry/borrow states match every exhaustive 3-bit entry and scale to exact 16-bit Speck counts |
| Restricted Speck ARX boomerang composition (M10.6d5b3c) | Achieved | Legacy weight-8 witness pinned; heuristic omission documented; exact switch count/weight independently computed; seeded 65,536-sample experiment preserves 11 successes and the legacy rate threshold |
| Typed differential-linear composition (M10.6d5c) | Achieved | Fixed Speck32/64-6 patterns decompose into p=1, r=7, q=3; legacy search weight 14 and exact composed weight 14.994353436858859 are separately retained and independently checked |
| CP continuous models (M10.6d6) | Achieved | Dependency-free continuous XOR/rotation/addition and one-/two-round Speck fixtures; fixed-mask correlation, binary64 precision, tolerance, and heuristic-only claim type preserved |
| Complete legacy inventory (M10.7) | Achieved | Deterministic standard-library inventory covers 323 source and 258 test modules; AST metadata, primitive taxonomy fields, fixed-evidence locators, and an exact filesystem/CI gate; three pending `develop` commits reconciled |
| Remaining mathematical/solver models (M10.8) | In progress | M10.8a component semantics/baseline achieved; whole-graph composition, fixed algebraic fixtures, and remaining inventory closure follow |
| Boolean ANF/component monomial baseline (M10.8a) | Achieved | Sage-free Möbius ANF, symbolic cube coefficients, exact S-box transition tables, portable one-hot MILP, real GLPK SAT/UNSAT coverage, and user/developer doctests |
| Whole-graph division-property composition (M10.8b) | Achieved | Graph-derived PRESENT and generic component semantics compose across multiple rounds, lower to portable MILP, execute in GLPK, and decode through an independent checker |
| PRESENT round monomial composition (M10.8b1) | Achieved | Sixteen exact S-box relations compose through the typed p-layer; possible witness and impossible pair are independently checked |
| Generic monomial graph semantics (M10.8b2) | Achieved | Typed S-box, Boolean addition/XOR, identity, concatenation, permutation, and constant relations share one independently checked dispatcher |
| Multi-round monomial solver composition (M10.8b3) | Achieved | Complete reduced PRESENT regions use graph p-layers and 3SDP S-box relations; real GLPK witness is independently decoded and checked |
| ANF/degree/cube/superpoly evidence (M10.8c) | In progress | Exact reduced-graph ANF/degree/superpoly slice achieved; scalable parity and balanced-bit fixtures follow |
| Exact symbolic Boolean graph evaluation (M10.8c1) | Achieved | Typed Word rotations/XOR/AND/addition recover Simon-1 ANF terms, Simon-2 degree vector and `k49` superpoly; symbolic evaluation matches a concrete vector |
| Exact parity and balanced-bit evidence (M10.8c2) | Achieved | Exact Simon-4 expansion preserves the legacy degree vector and fixed-public-input cube-degree array; proof-qualified results identify balanced bits and reject incomplete proof claims |
| Scalable algebraic bounds and parity (M10.8c3) | In progress | Restore partial-ANF bounds, Trivium parity-degree and larger cube-feasibility fixtures without relabeling bounds or incomplete searches as exact ANFs |
| Exact partial-ANF evidence (M10.8c3a) | Achieved | Public cube coefficients retain exact Boolean polynomials; Simon-3 preserves all 14 legacy partial-ANF monomials |
| Exact cube-sum verification (M10.8c3a2) | Achieved | Dependency-free exhaustive cube evaluation independently verifies the legacy Simon-2 `k49` superpoly at deterministic key assignments |
| Scalable degree/parity encoding (M10.8c3b) | In progress | Port backend-neutral upper-bound and parity semantics, with explicit soundness/completeness and open-solver execution |
| Structural degree-bound baseline (M10.8c3b1) | Achieved | Bit/Word XOR, AND, rotation, constants, concatenation and modular addition propagate sound bounded degrees; Simon-4 documents exact 8 versus loose bound 16 and never claims completeness |
| Whole-graph monomial reachability solver (M10.8c3b2) | Achieved | Portable COPY/XOR/AND/rotation/concatenation/constant MILP plus GLPK recovers Simon reduced degrees 2/3/8 and the legacy Simon-13 31-variable cube bound 30 |
| Complete monomial-path parity solver (M10.8c3b3) | Achieved | Portable no-good enumeration reaches terminal UNSAT, matches all five exact Simon-2 degree-three ANF monomials, and rejects path-limited results as incomplete |
| Remaining scalable algebraic fixtures (M10.8c3c) | Next | Extract the fixed-length Trivium transformation and migrate its degree/parity/superpoly evidence, then address uBlock, Gaston and divide-and-conquer fixtures as their typed primitives arrive |
| Remaining model inventory closure (M10.8d) | Planned | Resolve every outstanding solver/algebraic entry and keep optimized proprietary drivers optional |
| Primitive terminology/public API (M10.9a) | Planned | `Primitive`/`primitives`, official class names, schemas, documentation, and terminology guard |
| Fixed-length primitive classification (M10.9b) | Planned | Every legacy catalogue entry assigned to the six semantic categories, an orthogonal fixture folder, or an explicit out-of-scope disposition |
| Complete reusable component catalogue (M10.9c) | Planned | All reusable legacy components migrated with parity evidence and pseudocode-level authoring helpers |
| Complete primitive implementations/evidence (M10.9d) | Planned | Every in-scope fixed-length primitive and parameter family migrated under the new taxonomy with evaluation and cryptanalytic fixtures |
| Primitive realizations/task selection (M10.9e) | In progress | Generic capability metadata and AES lookup/algebraic realizations implemented; result provenance and broader task-directed selection remain |
| AES realization vertical slice (M10.9e1) | Achieved | Lookup S-box and field-inverse-plus-binary-affine graphs share one public class and all AES-128/192/256 fixed vectors; deterministic capability selection is documented and tested |
| Primitive inversion and graph transformations (M10.10) | Planned | Typed inverse semantics, partial inversion, round trips, slicing, key-schedule removal, and editor transformations |
| Component analysis (M10.11) | Planned | Structured S-box, linear-layer, Boolean, field, and word-operation properties with optional heavy algebra/plots |
| Dataset/statistical testing (M10.12) | Planned | Reproducible streaming datasets, avalanche, NIST STS and Dieharder optional drivers and parsers |
| Neural distinguishers (M10.13) | Planned | Framework-independent black-box/differential experiment contracts plus optional ML drivers |
| Reports and presentation (M10.14) | Planned | Typed Report replacement, tables, plots, exports, citations, evidence and reproducibility metadata |
| Serialization, diagrams, code generation (M10.15) | Planned | Versioned formats, routed diagrams, language generators, and remaining compiler workflows |
