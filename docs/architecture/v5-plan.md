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
or any solver. M10.8c3c extracts the fixed-length Trivium keystream function
from the legacy stream-cipher construction as a ``block_function`` and derives
its ANF, superpoly, degree-bound and parity evidence anew. The legacy Gurobi
Trivium expectations are confirmed by that independent derivation rather than
transcribed, because every test in that suite is license-skipped and has never
executed. M10.8d subsequently closes the remaining Gurobi-only literals as
unverified hypotheses rather than oracle values: they stay recorded in the
matrix, but do not become v5 proof claims merely because they appeared in
permanently skipped tests.

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

The M10.9c1 audit covers 77 machine-inventory records: 44 source records and
33 test records. Two sources are reviewed empty package markers; the remaining
75 behavioral records comprise 29 legacy component implementations with 29
matching test modules, the component base and its tests, and the DTO,
input/round, name-mapping, integer/sequence, template, Sage-helper, and shared
utility modules assigned to M10.9c. Their 252 discovered legacy test functions
are evidence locators, not 252 promises to preserve generated solver strings.
Each implementation slice must classify every owned assertion before changing
the component: semantic values and independently checkable relations are
preserved, while backend syntax, incidental identifiers, mutable counters, and
code-generation details stay with their already achieved or separately owned
representation/compiler milestones.

Fifteen typed v5 component classes already exist across the algebraic,
structural, substitution, and word families. They are accepted baselines from
earlier milestones, not gaps to reimplement. M10.9c extends and consolidates
that catalogue in this dependency order:

1. **M10.9c1 — component catalogue audit.** Assign every owned machine record
   to one slice, count all legacy component tests, identify the existing v5
   baseline, and add a machine-checked audit summary. This is planning and
   ownership closure only; it does not claim component parity.
2. **M10.9c2 — authoring, state, conversion, and utility foundations.** Resolve
   the legacy DTOs, component-state/base, input/round helpers, name mappings,
   integer and sequence operations, general selection/layout helpers,
   templates, and Sage scripts. Retain only typed, Sage-independent behavior
   needed by later components; explicitly supersede or remove presentation,
   dynamic-loading, and backend-shaped leftovers owned elsewhere.
3. **M10.9c3 — structural and graph-boundary components.** Complete constants,
   identity/concatenation parity, permutations, reverse and word permutation,
   explicit selection/conversion operations, and typed intermediate/final
   output boundaries on the M10.9c2 authoring foundation.
4. **M10.9c4 — Boolean, logical, and substitution components.** Complete XOR,
   AND, OR, NOT, multi-input logical behavior, and lookup substitution while
   reusing shared exact semantics rather than component-local solver methods.
5. **M10.9c5 — word and ARX components.** Complete fixed and variable shifts
   and rotations, modular add/subtract/multiply, and IDEA multiplication after
   the structural and Boolean contracts are stable.
6. **M10.9c6 — finite-field and linear-layer components.** Complete generic
   linear layers and MixColumn-style field matrices using the existing typed
   domains, algebraic maps, and Sage-independent field helpers.
7. **M10.9c7 — feedback-register components.** Add typed binary and word FSR
   descriptions and evaluation after their Boolean, word, and field
   dependencies are complete.
8. **M10.9c8 — permutation-specific reusable components.** Add ShiftRows,
   Sigma, and the Gaston, Keccak, and Xoodoo theta maps as reusable algorithms
   composed from the earlier structural/word/linear catalogue where possible.
9. **M10.9c9 — catalogue closure.** Centralize exports, authoring methods,
   documentation/doctests, and the inventory closure gate; require all 75
   behavioral records to have explicit migrated, superseded, removed, or
   inapplicable dispositions and concrete evidence destinations before M10.9d
   becomes next.
10. **M10.9c10 — hierarchical composite graphs and reusable blocks.** Add this
    follow-on after catalogue closure to distinguish reusable compositions from
    leaf components without changing the canonical flat typed DAG consumed by
    representations. Complete it in this dependency order:

    1. **M10.9c10a — immutable composite graph foundation.** Define immutable
       composite definitions and instantiated graph scopes, deterministic
       namespaced lowering, typed input/output bindings, nested scope lookup,
       and provenance. A primitive, round, and composite expose graph scopes;
       composites do not acquire evaluator- or solver-specific methods.
    2. **M10.9c10b — reusable composite block catalogue.** Add generic parallel
       S-box layers and the ChaCha quarter round with fixed independent
       evidence. Permit a composite definition or instance to be projected as
       a primitive graph so existing execution, constraint, analysis, and
       diagram representations operate on precisely that scope.
    3. **M10.9c10c — compositional AES and variants.** Add reusable AES key
       schedule and round blocks, build an AES-equivalent graph from those
       blocks, and provide an explicitly derived variant API for substituting
       an S-box or omitting MixColumns. Preserve the canonical AES identity and
       fixed FIPS-197 results; record modifications in provenance rather than
       labelling a derived graph as AES.
    4. **M10.9c10d — documentation and closure.** Document block authoring,
       hierarchy/lowering, AES variant studies, scoped evaluation, and scoped
       constraint generation in both guides with executable examples. Run the
       complete dependency-free and compatibility checkpoints before making
       M10.9d next again.

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
- Let a simple primitive remain one module. When a primitive owns multiple
  realizations, vetted parameter sets, generated constants, or substantial
  supporting data, replace ``<primitive>.py`` with a same-import-path
  ``<primitive>/`` package. Keep its public class, realizations, parameter
  schemas, pinned data, provenance, licenses, and reference vectors together;
  for example ``poseidon/{__init__,primitive,parameters,data}``.
- Move the current Poseidon BN254 catalogue into that Poseidon package. A
  top-level ``claasp_next.parameters`` namespace may remain only as a thin
  convenience re-export and must not own primitive-specific data. Do not force
  package directories on small primitives that need only one module.
- A frozen exported graph is an intermediate parity oracle, not a completed
  primitive migration. Final M10.9d destinations must contain readable,
  Sage-independent v5 construction source expressed with typed components and
  reusable blocks. Runtime ``CatalogueGraphPrimitive`` wrappers, opaque graph
  manifests, and compressed graph specifications must be absent at closure.
  A development-only legacy-to-v5 compiler may generate a first source draft,
  but its checked-in output must be structured and reviewable as an
  implementation of the primitive rather than an embedded graph dump.

The M10.9d3 audit covers all 149 classified catalogue source records and the
143 primitive-specific legacy test modules containing 265 test functions.
Four source records are the helpers already classified outside the primitive
catalogue; the other 145 source records are behavioral migration obligations.
Every record has one owner below. A legacy test name locates evidence but does
not make component identifiers, generated strings, counters, or mutable graph
state into v5 compatibility contracts.

Complete M10.9d in this recorded dependency order. M10.9d1 and M10.9d2 were
accepted early vertical slices and remain subject to the final closure gate:

1. **M10.9d1 — ChaCha permutation evaluation.** Retain the official ChaCha
   permutation, standard round convention, fixed vectors, and scalar/batch
   parity. This slice is achieved.
2. **M10.9d2 — Salsa permutation evaluation.** Retain the official Salsa
   permutation, standard round convention, fixed vectors, and scalar/batch
   parity. This slice is achieved.
3. **M10.9d3 — primitive catalogue audit.** Machine-assign every classified
   source and primitive test and retain the four reviewed outside-scope helper
   decisions. The audit is planning and ownership closure, not semantic parity
   for the 145 behavioral sources.
4. **M10.9d4 — single-component and toy primitives.** Resolve 33 source and
   31 test records after M10.9d3. Reuse the M10.9c component catalogue and
   preserve fixture semantics without restoring backend methods on components.
   This slice is achieved: all 26 one-operation primitives and seven toy
   families use typed graphs, all fixed vectors and parameter fixtures pass,
   and ToyAES diffusion matrices have independent finite-field checks.
5. **M10.9d5 — word-oriented and ARX/Feistel block primitives.** Resolve the
   15 source and 15 test records assigned by the machine inventory, preserving
   official parameter families, reduced rounds, and fixed vectors. This slice
   is achieved: all families use typed graphs, every applicable legacy fixed
   vector passes, and scalar/batch parity is checked independently.
6. **M10.9d6 — substitution/linear and tweakable block primitives.** Resolve
   the remaining 55 block/tweakable source and 55 test records, reusing typed
   S-box, field, linear-layer, key-schedule, and composite-block foundations.
   This slice is achieved: readable Sage-free construction source builds
   immutable typed graphs for all families and audited parameter variants;
   every captured legacy fixed vector and independent scalar/batch parity pass.
7. **M10.9d7 — remaining permutations.** Resolve 25 source and 25 test records
   after shared block operations are stable, including invertible interfaces
   represented as forward primitive graphs without claiming the general graph
   inversion work owned by M10.10. This slice is achieved: every assigned
   permutation has a typed forward graph, alternate invertible/FSR realizations
   retain distinct public identities, and all fixed evidence passes.
8. **M10.9d8 — fixed-length functions and block functions.** Resolve all 15
   source and 15 test records extracted from legacy hash, MAC, and stream
   construction folders. Preserve their fixed-length mappings and parent
   provenance without reviving those folders as primitive categories. This
   slice is achieved: all 15 families have typed graphs, all 41 captured fixed
   observations pass, scalar/batch parity is independently checked, and the
   145-source machine closure gate has no unresolved destination.
9. **M10.9d9 — primitive-owned parameters and supporting data.** Move Poseidon
   parameters and data under its same-import-path package, keep only a thin
   convenience re-export at ``claasp_next.parameters``, and colocate any other
   primitive-specific generated constants, licenses, and reference vectors.
   This slice is achieved: Poseidon owns its implementation, typed parameter
   schema, BN254 catalogue, pinned vector, provenance, and license; LowMC owns
   its vetted matrices, while AES uses a same-import-path package for its
   implementation and multiple realizations. Simple primitives remain readable
   single modules.
10. **M10.9d10 — catalogue closure.** Centralize public exports and executable
    user/developer documentation; require all 145 behavioral sources and their
    applicable fixed evidence to have concrete destinations and make the
    machine closure gate pass before returning to M10.9e. This slice is
    achieved: every behavioral destination contains readable native v5 source;
    the runtime frozen-graph loader, manifests, and compressed specifications
    are absent; the complete host, documentation, wheel, and compatibility
    checkpoints pass.
11. **M10.9d11 — catalogue layout and authoring refinement.** Reopen the
    milestone for the following corrective, dependency-ordered slices before
    M10.9e resumes:

    1. **M10.9d11a — realization-family packages.** Use one same-import-path
       package whenever a primitive family has multiple implementations or
       legacy-derived realizations. Co-locate Aradi, DES, GIFT, KATAN,
       KTANTAN, Simeck, Simon, TinyJambu, uBlock, Ascon, Gaston,
       Gimli, Keccak, Spongent-pi, Xoodoo, and QARMAv2. Preserve the existing
       public import path while giving each realization a concise module name.
       The Simon/Simeck/Gimli ``sbox`` forms remain explicitly
       legacy-regression realizations rather than claims about the canonical
       specifications; M10.9f owns their discovery labels and authenticity
       metadata. PRINCE and PRINCEv2 are distinct specified block primitives,
       not realizations, and therefore retain separate module and identity
       boundaries.
    2. **M10.9d11b — primitive and input metadata.** Add typed primitive-kind
       metadata and typed input descriptors, including a default
       public/secret confidentiality marker that callers may override for a
       study. Classify every single-component primitive as a function,
       permutation, block function, or block primitive from its actual input
       and bijectivity contract, and require exactly one round and one semantic
       component. Expose only canonical v5 mathematical parameters: do not
       retain legacy aliases, alternate matrix/permutation orientations,
       nested descriptions, sentinel values, or ignored arguments.
    3. **M10.9d11c — reference authoring implementations.** Make AES, Speck,
       and ChaCha the documented reference sources: follow their published
       pseudocode closely, rely on automatic component identifiers, use
       consistent state/word names, centralize common configuration and input
       validation helpers in ``Primitive``, expose ordered composite outputs,
       and move research-only AES modifications to a separate ``CustomAES``
       module distinct from ToyAES.
    4. **M10.9d11d — structural wiring and closure.** Reconcile v5 structural
       joining with the legacy removal of ``Concatenate``. Prefer typed graph
       wiring at component inputs and primitive/composite outputs; retain a
       semantic component only if an independently useful operation remains.
       Update user/developer documentation and rerun the complete M10.9d
       closure matrix.
    5. **M10.9d11e — base-component primitive alignment.** Make the
       single-component catalogue a one-to-one teaching and analysis wrapper
       over the public v5 base component classes. Use the component's v5 class
       and module name, replace legacy LinearLayer/MixColumn fixtures with
       domain-polymorphic ``LinearMap``, add wrappers for algebraic and
       conversion components introduced in v5, align the feedback-register
       module name, and require a class docstring with an executable example
       on every wrapper. Keep legacy fixture records only as migration
       evidence and record the v5 catalogue independently.

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

The achieved AES slice is followed by these dependency-ordered slices.  They
remain part of M10.9e rather than forming a separate catalogue milestone:

1. **M10.9e2 — realization audit and generic metadata.** Classify every
   multi-module family as equivalent graphs, a distinct parameterization or
   primitive, or a duplicate/historical regression; make stable identity,
   capabilities, structural features, maturity, provenance, priority, and
   explicit selection generic graph metadata; define deterministic preferred
   and unique-match selection policies with precise unsupported/ambiguous
   errors.
2. **M10.9e3 — family selection and equivalence.** Register only proved
   equivalent graphs under their canonical primitive, normalize their typed
   boundaries where legacy-derived source used a different internal unit
   shape or input order, and preserve every assigned fixed vector plus seeded
   independent differential comparisons. Exact aliases are not promoted to
   realizations; DES key-boundary variants, CustomAES/ToyAES, and
   PRINCE/PRINCEv2 remain distinct.
3. **M10.9e4 — result and artifact provenance.** Carry realization identity
   and execution/solver engine identity as separate typed fields through
   scalar and batch evaluation, graph annotations, the high-level analysis
   result, and representation artifacts without confusing an engine
   capability with graph structure.
4. **M10.9e5 — documentation and closure.** Complete executable user and
   developer guidance, add a machine-checkable realization closure gate, and
   run the host, external, doctest/HTML, wheel, and Python-3.10 compatibility
   checkpoints with generated artifacts removed afterwards.

##### M10.9f: Catalogue discovery and query API

- Migrate ``claasp/catalog.py`` as a typed, Sage-independent catalogue API
  over committed v5 primitive, component, realization, parameter,
  representation, analysis, and driver metadata. Do not rediscover the public
  taxonomy by importing every module or by treating legacy folder names as
  semantic categories.
- Preserve useful discovery and filtering behavior, including category,
  component, ARX/AND-RX, S-box, FSR, tweak, realization capability, parameter
  set, and available-driver queries. Availability probes must not import or
  require optional solvers and frameworks during normal package import.
- Return immutable structured records first. Terminal, Markdown, CSV, JSON,
  and optional dataframe views consume those records through the M10.14
  presentation layer rather than defining catalogue semantics themselves.
- Preserve applicable legacy catalogue tests and add invariants tying every
  discoverable entry to the M10.9b classification, official public name,
  import path, input roles, bijectivity obligation, realization metadata, and
  fixed evidence. Complete this milestone after M10.9c/M10.9d so discovery
  cannot hide missing components or primitives.

The remaining work is divided into these dependency-ordered slices:

1. **M10.9f1 — authoritative catalogue metadata.** Commit a versioned,
   machine-checkable catalogue joining every public primitive export to its
   M10.9b classification, official name and import path, input roles,
   bijectivity obligation, fixed evidence, component vocabulary,
   parameter-set metadata, and realization identities. Record components and
   drivers without importing optional implementations.
2. **M10.9f2 — immutable discovery records.** Add the Sage-independent public
   catalogue facade and frozen primitive, component, realization, parameter,
   and driver records. Query only committed metadata and preserve category,
   component, ARX/AND-RX, S-box, FSR, and tweak filters without deriving
   semantics from package paths or source syntax.
3. **M10.9f3 — capability, parameter, and availability queries.** Provide
   deterministic realization-capability and parameter-set filtering plus
   explicit, lazy driver availability probes which neither import nor require
   optional solver, algebra, statistical, renderer, or ML dependencies during
   ordinary package import.
4. **M10.9f4 — documentation and closure.** Preserve applicable legacy
   discovery invariants, document executable user and developer examples,
   add a machine closure gate, and run host, affected external,
   doctest/HTML, wheel, and Python-3.10 compatibility checkpoints with
   generated artifacts removed afterwards.
5. **M10.9f5 — analysis/representation/driver capability graph.** Extend the
   committed metadata and immutable records with explicit many-to-many
   relationships between analyses, component semantics, representations, and
   compatible drivers. Support forward and reverse queries: analyses
   applicable to a primitive, representations available for a component,
   components supported by a representation, and drivers consuming a
   representation. Compatibility declarations must record domain and scope
   restrictions and must not infer support merely from a module's existence.
   Keep rendering in M10.14 and new component-analysis implementations in
   M10.11.
6. **M10.9f6 — semantic component boundary cleanup.** Replace internal
   concatenate nodes and bit/word conversion components with immutable typed
   value bindings shared by evaluation, models, diagrams, composites, and
   realization normalization. Eliminate identities synthesized for legacy
   outputs and degenerate operations while retaining explicitly authored
   ``Identity``. Remove Concatenate/PackBits/UnpackBits teaching primitives
   and catalogue records so primitive component queries report only semantic
   operations; retain MSB-first conversion evidence and machine closure.

#### Cross-cutting legacy module ownership

The exhaustive inventory remains the completion gate. The following ownership
map prevents top-level utility modules from falling between family milestones:

- M10.9c owns reusable component modules plus legacy DTOs, component-state,
  input/round authoring helpers, name mappings, integer/sequence utilities,
  templates, and Sage-helper replacement or removal.
- M10.9f owns ``catalog.py`` and catalogue-specific discovery/filtering.
- M10.10 owns ``editor.py``, ``inverse_cipher.py``, graph splitting/traversal,
  and compound paired/XOR graph transformations.
- M10.14 owns ``report.py`` and presentation/export behavior.
- M10.15 owns evaluator/native/vectorized helper modules, the existing generic
  bit/word C sources and headers, C/CUDA/Python code generation, serialization,
  and remaining diagram/compiler utilities.
- M11 owns reference-vector/test orchestration from ``tester.py``; M11a owns
  the final bidirectional audit of every legacy and shipped v5 artifact.

Analysis-specific top-level modules remain owned by their existing achieved or
planned analysis milestones: algebraic/model evidence by M10.8, continuous
analysis by M10.6d6, component analysis by M10.11, avalanche/statistics by
M10.12, and neural experiments by M10.13.

#### M10.10: Primitive inversion and graph transformations

- Define inverse semantics per component and build inversion as a typed graph
  transformation independent of solver backends.
- Support retained auxiliary inputs, partial knowledge, equivalent recovered
  wires, and precise diagnostics when inversion stalls.
- Preserve legacy inversion tests and verify forward/inverse round trips for
  each supported component and representative complete primitives.
- Keep graph slicing, key-schedule removal, round reduction, and related
  editor transformations in the same validated transformation layer.

M10.10 is delivered through these dependency-ordered slices. They are slices
of the existing transformation milestone, not independent milestones:

1. **M10.10a — transformation contracts, traversal, and provenance.** Define
   immutable transformation results and provenance, a typed dependency index
   over inputs, semantic components, structural bindings, and composite
   scopes, deterministic topological traversal, and exact diagnostics for
   invalid or disconnected boundaries. Transformation provenance remains
   separate from realization and execution/solver provenance.
2. **M10.10b — validated graph slicing and dependency closure.** Construct
   new validated primitive graphs from explicit boundaries, compute backward
   and forward dependency closure without NetworkX, preserve structural
   bindings as bindings, and expose round-range reduction without retaining
   incidental ids or mutable legacy ordering.
3. **M10.10c — component inverse semantics.** Add a registry of typed inverse
   rules for bijective components and partial rules for multi-input operations
   when the required auxiliary operands are retained. Reject information loss,
   unsupported components, multiple predecessors, missing auxiliary values,
   ambiguous boundaries, and disconnected dependencies as distinct typed
   diagnostics; never infer bijectivity from a component name.
4. **M10.10d — complete and partial primitive inversion.** Build inverse
   primitive graphs from the M10.10c rules, support retained auxiliary inputs,
   partial knowledge, and equivalent recovered wires, preserve realization
   identity while adding separate transformation provenance, and verify
   complete and partial round trips by independent scalar evaluation.
5. **M10.10e — editor transformations.** Add round reduction,
   key-schedule removal with explicit round-key boundaries, orphan pruning,
   and inlining of reorder-only semantic operations into structural bindings.
   Every operation returns a new validated graph; none mutates the source.
6. **M10.10f — paired/XOR graph transformations.** Replace the legacy mutable
   compound-XOR cipher copier with typed paired evaluation and XOR-observation
   graph transformations, retaining exact single-key and related-key semantic
   evidence without solver-owned graph state.
7. **M10.10g — inventory, documentation, examples, and closure.** Resolve all
   M10.10 machine-inventory records and row-level fixed evidence, document
   inversion, retained-auxiliary partial inversion, slicing, round reduction,
   and key-schedule removal, add executable public-API doctests, and run the
   host, affected-external, documentation, wheel, and compatibility-container
   checkpoints before marking M10.10 achieved.
8. **M10.10h — catalogue-wide inversion coverage and performance.** Reopen the
   transformation milestone from the committed catalogue audit and complete
   the following dependency-ordered slices. ``M10.10h`` improves the existing
   graph-native methodology; it does not introduce a solver-owned inverse or
   a second mutable editor model.
   1. **M10.10h1 — authoritative inversion audit and acceptance contract.**
      Check every public primitive and named catalogue parameter set, including
      toys and single-component primitives. Record catalogue bijectivity
      separately from retained-input recoverability, measure separately built
      one-round and official full graphs, verify successful inverses by scalar
      round trips, repair invalid catalogue parameter declarations exposed by
      the audit, and retain the reproducible Markdown report as fixed baseline.
   2. **M10.10h2 — dependency-driven inversion engine.** Replace repeated
      whole-graph propagation scans with a deterministic work queue indexed by
      newly known wires. Preserve bindings as bindings, equivalent recovered
      wires, exact typed failures, immutable inputs/results, and separate
      realization/transformation provenance. Demonstrate substantially better
      scaling on the audited KATAN/KTANTAN FSR configurations without changing
      their inverse semantics.
   3. **M10.10h3 — reversible-region and multi-predecessor recovery.** Add an
      explicit, solver-free contract for jointly reversing authored reversible
      state transitions, Feistel/state-split updates, and other catalogue
      regions whose local components expose several temporarily unknown
      predecessors. Never classify an arbitrary underdetermined equation
      system as invertible; require a validated reversible construction or
      retained information, and keep ambiguity/information-loss diagnostics
      exact.
   4. **M10.10h4 — remaining component and boundary semantics.** Add justified
      inverse semantics for reversible feedback-register transitions and IDEA
      encoded-group multiplication, make zero-input and partial-boundary cases
      return typed diagnostics rather than incidental exceptions, and retain
      explicit information-loss failures for genuinely non-bijective
      operations.
   5. **M10.10h5 — complete bijective catalogue coverage.** Require every
      configuration carrying a catalogue bijectivity obligation to construct
      and semantically verify an inverse. Qualify non-obligated functions
      separately when retained-input recovery is valid; keep hashes, stream
      output functions, lossy teaching components, and other non-bijective
      maps outside the completeness claim.
   6. **M10.10h6 — performance, documentation, and closure.** Establish bounded
      one-round and full-primitive regression budgets, update the audit report
      and transformation documentation, run the complete host, relevant
      external, documentation, wheel, and compatibility-container checkpoints,
      and mark M10.10 achieved again only when the audit has no unsupported,
      erroneous, or timed-out catalogue-bijective configuration.
   7. **M10.10h7 — retained-input obligation correction.** Review every toy and
      single-component named configuration plus every successful configuration
      previously outside the obligation. Classify the designated data/state
      map with auxiliary inputs retained, rather than deriving the obligation
      solely from its catalogue folder or whole-arity primitive kind. Keep
      arbitrary non-catalogued constructor choices distinct, retain explicit
      negative classifications for lossy maps, regenerate the inventory,
      catalogue, audit, and documentation, and require every corrected positive
      obligation to pass independent semantic inversion.

#### M10.11: Component analysis

- Return structured properties for S-boxes, linear layers, MixColumns,
  Boolean functions, and word operations through typed component semantics.
- Cover differential uniformity, nonlinearity, algebraic degree, branch
  numbers, operation grouping, and other applicable legacy properties.
- Implement small exact calculations without Sage where practical; place
  optional heavy algebra and plotting behind drivers consuming the same
  structured results.

M10.11 is delivered through these dependency-ordered slices. They are slices
of this component-analysis milestone, not independent milestones:

1. **M10.11a — contracts, applicability, provenance, and ownership.** Define
   immutable typed requests, property results, exactness/claim kinds,
   diagnostics, semantic domains, and separate realization/analysis/execution
   provenance. Assign every legacy component-analysis source and test
   assertion to M10.11 or M10.14, and retain the M10.8d disposition of
   solver-shaped wordwise branch-number models.
2. **M10.11b — semantic grouping and graph discovery.** Discover only semantic
   components in immutable primitive graphs and group equal operations by
   exact component type, typed parameters, input/output value types, and
   analysis domain. Structural joins, ordered views, PackBits, and UnpackBits
   remain bindings and component identifiers remain optional evidence only.
3. **M10.11c — lookup-table properties.** Provide dependency-free exact
   differential uniformity, nonlinearity, coordinate algebraic degree,
   balancedness, APN status, differential/linear branch numbers, and
   mathematically applicable boomerang uniformity by reusing lookup, trail,
   Boolean-polynomial, and boomerang semantics.
4. **M10.11d — linear, affine, permutation, and MixColumn properties.** Add
   validated rank, invertibility, order where meaningful, MDS status, and
   exact or explicitly bounded bit/word differential and linear branch
   numbers with row-major matrices, explicit field moduli and the required
   differential-versus-linear transpose rule.
5. **M10.11e — Boolean, word, and feedback properties.** Report justified ANF
   degree, term/variable structure, permutation/linearity facts, and typed
   feedback register/connection-polynomial properties without restoring
   legacy plot-oriented averages or requiring Sage.
6. **M10.11f — optional heavy drivers and bounded fallbacks.** Put optional
   algebra and MiniZinc execution behind explicit drivers consuming the same
   typed requests and returning the same result contracts. Bounded enumeration
   remains a proved bound or incomplete observation unless coverage proves
   exactness.
7. **M10.11g — public API, catalogue integration, documentation, and closure.**
   Expose concise primitive-oriented APIs, add conservative catalogue
   capability metadata, executable S-box/binary-linear/MixColumn examples,
   extension documentation, machine inventory closure, and the complete host,
   affected-external, documentation, wheel, and compatibility checkpoints.

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

M10.14 is delivered through these dependency-ordered slices. They remain
slices of the presentation milestone rather than independent milestones:

1. **M10.14a — contracts, evidence, provenance, and ownership.** Define
   immutable presentation evidence, applicability, citation, reproducibility,
   and diagnostic contracts; keep mathematical, primitive-realization, and
   execution/driver provenance separate; assign the legacy report records and
   every presentation deferral from catalogue, component, statistical,
   continuous, avalanche, and neural work to explicit destinations and fixed
   evidence.
2. **M10.14b — dependency-free tables and formatting.** Add immutable table,
   column, row, cell, section, and report-data models plus deterministic
   formatters for integers, hexadecimal values, bit/word vectors,
   probabilities, correlations, weights, bounds, booleans, unavailable values,
   and multiline diagnostics. Core imports must not load pandas, NumPy,
   Matplotlib, Plotly, Sage, scikit-learn, or a solver.
3. **M10.14c — typed result adapters.** Adapt trails, execution traces,
   component-property results, avalanche results, NIST STS and Dieharder
   parser artifacts, neural experiments, and conservative catalogue summaries
   without recomputing any analysis. Preserve semantic order and expose graph
   locations only as optional evidence references.
4. **M10.14d — deterministic text and report-data exports.** Render terminal
   and escaped Markdown tables, produce standard-library CSV, and expose
   recursively JSON-compatible report data. These are report exports, not the
   versioned graph/result serialization owned by M10.15.
5. **M10.14e — optional plotting drivers.** Add explicitly requested,
   headless-testable Matplotlib drivers for justified component-property radar
   views, avalanche matrices, and statistical summaries. Normalization must
   carry scale, direction, applicability, and evidence class and must omit
   incomparable or unavailable properties rather than inventing scores.
6. **M10.14f — composition, citations, files, and catalogue integration.**
   Compose immutable report artifacts from existing results, retain citations
   and reproducibility metadata, write only explicit validated formats through
   safe predictable paths and overwrite policies, add optional dataframe
   conversion, and publish presentation capabilities in catalogue metadata.
7. **M10.14g — public API, documentation, CI, and closure.** Centralize public
   exports and primitive-facing composition, add executable user/developer
   documentation and doctests, close the four report inventory records and all
   deferred presentation obligations, and run the complete host, affected
   optional/external, documentation, wheel, and compatibility-container
   checkpoints before marking M10.14 achieved.

#### M10.15: Serialization, diagrams, and code generation

- Migrate versioned serialization, diagrams, generated Python/C/CUDA where in
  release scope, and remaining compiler/export workflows.
- Keep human-facing diagrams and generated code independent of analysis
  backends and verify them with legacy semantic fixtures where applicable.
- Complete routed ASCII art or retain its explicit work-in-progress status;
  do not silently substitute a structural listing.

M10.15 is delivered through dependency-ordered slices. They are slices of
this tooling milestone, not new milestones:

1. **M10.15a — ownership, contracts, and fixed evidence.** Assign every
   legacy serialization, evaluator, generated-source, vectorized-helper, and
   native C/header surface to an explicit destination or supersession. Define
   schema/version policy, immutable artifact and diagnostic contracts, CUDA
   applicability, and a machine closure gate without reopening achieved
   evaluation, continuous-analysis, catalogue, or presentation semantics.
2. **M10.15b — canonical primitive serialization.** Add dependency-free
   canonical UTF-8 JSON for typed primitive graphs and strict deserialization
   with schema negotiation, a closed domain/component registry, stable field
   ordering, complete graph validation, and typed diagnostics.
3. **M10.15c — typed artifact serialization.** Version explicitly selected
   execution traces/results and reject unsupported result kinds. Keep these
   machine formats distinct from M10.14 report-data export.
4. **M10.15d — evaluation-helper closure.** Prove scalar, batch, structural,
   feedback, and continuous-helper ownership; use the dependency-free batch
   engine as the legacy NumPy-vectorized replacement and record removed helper
   APIs without duplicating component semantics.
5. **M10.15e — deterministic Python source.** Compile supported typed graphs
   to immutable Python source artifacts and execute them only through an
   isolated, bounded driver with source-digest and realization provenance.
6. **M10.15f — deterministic native source and drivers.** Compile the retained
   fixed-width scope to self-contained C, use validated argument-vector
   compiler/run drivers in isolated directories, report unavailable and failed
   tools honestly, and record CUDA as unsupported unless maintained legacy
   evidence establishes a release-scope backend.
7. **M10.15g — diagrams, public API, documentation, packaging, and closure.**
   Re-audit diagram IR/routing/TikZ/PDF, fill only genuine gaps, publish
   catalogue capabilities and executable guidance, verify wheel contents and
   CI, close every M10.15 obligation, and run the full checkpoint matrix.

#### M10.16: Documentation and static-quality enforcement

- Define one reviewable docstring and doctest convention for public modules,
  classes, functions, and methods, drawing on the useful legacy CLAASP and
  CLAASP-pro conventions without carrying Sage prompt syntax into v5.
- Audit the complete public API for meaningful docstrings and executable
  examples. Require every public class and user-facing callable to have an
  appropriately scoped doctest, with an explicit machine-readable exception
  only where executing an example would be intrinsically unsafe or dependent
  on unavailable external infrastructure.
- Add a CI gate which checks docstring presence and structure, runs Python and
  documentation doctests, and rejects untested examples, inconsistent section
  layouts, stale output, and undocumented public exports.
- Establish repository-wide formatting, linting, and static-typing checks in
  the same CI quality group. Pin tool versions and configuration, keep optional
  dependencies isolated, and adopt the gates through an explicit audited
  baseline rather than permanent blanket exclusions.

Exit criterion: every public v5 API entry has a conforming docstring and
executable example or a reviewed exception; the full tree passes the pinned
format, lint, type, docstring-structure, Python-doctest, and documentation-
doctest checks locally and in CI.

M10.16 is delivered through the following dependency-ordered slices. They are
slices of this documentation and quality milestone rather than new milestones:

1. **M10.16a — authority, convention, tools, and measured baseline.** Define
   the mechanical public-API boundary, one docstring/doctest convention, the
   reviewed exception schema, the v5 quality-tool scope, exact tool pins, and
   reproducible baseline measurements. Record why Ruff supplies formatting and
   linting and why mypy supplies static typing, without enabling a gate before
   its findings have been audited.
2. **M10.16b — public-API documentation audit and closure gate.** Enumerate
   package exports, dynamic ``__all__`` values, aliases, classes, constructors,
   methods, properties, inherited user-facing members, dataclass fields, enum
   members, and generated catalogue exports. Add a versioned machine authority,
   narrow reviewed exceptions, deterministic closure tooling, and negative
   fixtures for malformed documentation and stale authority data.
3. **M10.16c — foundational API documentation closure.** Complete conforming
   docstrings and executable examples for graph authoring, domains, components,
   semantics, provenance, annotations, and primitive-authoring foundations.
4. **M10.16d — processing API documentation closure.** Complete conforming
   documentation for representations, serialization, source compilers,
   drivers, analyses, transformations, presentation, catalogue discovery, and
   composite graphs without requiring optional packages or external tools.
5. **M10.16e — primitive catalogue and export closure.** Replace retained Sage
   prompts, document every primitive and remaining public export, verify fixed
   deterministic examples, and close every public alias and generated
   catalogue-facing API.
6. **M10.16f — pinned formatting and linting.** Apply Ruff formatting in an
   isolated mechanical change, audit correctness findings, retain only narrow
   justified suppressions, document fix/check commands, and enable the pinned
   check-only CI gate.
7. **M10.16g — pinned static typing.** Type-check the explicitly recorded v5
   source, test, tool, and documentation-configuration scope with pinned mypy;
   correct contracts first and, only where immediate strictness is impractical,
   retain a machine-readable diagnostic baseline which rejects new and stale
   entries.
8. **M10.16h — Sphinx, CI, packaging, and milestone closure.** Make the complete
   public API discoverable through warning-free autodoc, run Python and both
   guide doctest suites, enforce every documentation and quality gate on Python
   3.11--3.13, audit wheel contents and optional-import isolation, run all
   existing closure gates plus the M10.16 gate, and complete the host and
   compatibility-container checkpoint before marking M10.16 achieved.

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

#### M11a: Final bidirectional migration audit

- Produce one authoritative machine-readable matrix covering every legacy
  source module, test module, native source/header, bundled data/template, and
  other release-relevant artifact. Each row records its v5 destination or
  destinations, disposition (migrated, superseded, removed, or explicitly
  out of scope), rationale, owning milestone, evidence/tests, and any retained
  historical path needed for provenance.
- Audit the reverse direction as well: every shipped v5 module and material
  data asset must identify its legacy predecessor(s), or state that it is a
  new v5 artifact with its requirement, owner, and tests. This prevents new
  modules, split replacements, and shared abstractions from being invisible in
  a legacy-only checklist.
- Generate a concise human-readable old-to-new/new-to-old summary from the
  machine matrix. Record one-to-many splits, many-to-one consolidations,
  renamed modules, newly introduced modules, and legacy modules or assets that
  were deliberately unnecessary in v5.
- Make the audit gate fail on an unclassified legacy or v5 artifact, a missing
  destination, an undocumented removal, a stale path, an unowned new module,
  or a release-scope row whose required evidence has not passed. Package
  markers and generated files use explicit rules rather than silently
  disappearing from the counts.
- Re-run the audit after the final ``develop`` reconciliation and before the
  ``claasp_next`` to ``claasp`` package rename. Regenerate and validate it once
  more after the rename so published paths, documentation, and import examples
  match the release tree.

Exit criterion: both directions cover 100% of release-relevant artifacts;
every removal and out-of-scope decision has reviewed rationale; all referenced
destinations and evidence exist; and the generated summary matches the
machine-readable matrix exactly.

### Documentation throughout all milestones

- Treat the generated site as CLAASP documentation; v5 architecture is one
  section of it, not the organizing principle of the introductory material.
- Add user-oriented examples and API documentation with each public feature.
- Treat docstrings and executable doctests as mandatory parts of every new or
  changed public API. A feature is incomplete until its API-level example is
  available through ``help(...)`` and passes the Python-module doctest suite;
  guide-level examples complement rather than replace API docstrings.
- Write examples as executable doctests rather than unverified snippets.
- Follow the repository-wide docstring/doctest structure once M10.16 records
  it; until then, follow the established concise summary plus ``EXAMPLES::``
  convention used by the legacy public API.
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

The legacy ``tiicrc/claasp-base`` image is currently only a solver
compatibility environment for v5: it is amd64-only, provides Python 3.10
instead of the required Python 3.11+, and does not contain msolve. A dedicated
multi-architecture v5 image must pin supported Python and all baseline
external tools before it becomes the canonical release environment.

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

1. M10.9d11: complete the recorded catalogue-layout, metadata, reference
   authoring, and structural-wiring refinement; then complete the remaining
   general realization/provenance work in M10.9e and
   close the typed catalogue discovery/query API in M10.9f.
2. M10.15 and M10.16: serialization, diagrams, code generation, remaining
   tooling, and repository-wide documentation/static-quality enforcement.
   M10.10--M10.14 are already achieved.
3. Build and validate the queued canonical v5 image before M11 integration
   and release; run the M11a bidirectional migration audit before and after the
   final package rename. Image work is not a prerequisite for continuing
   M10.9e locally.

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
- M10.5d is achieved, including routed dependency-free ASCII art.
- M10.6a–M10.6d4 are achieved.
- M10.6, including its advanced exact and heuristic analyses, is achieved.
- M10.7 is achieved: the exhaustive inventory and filesystem gate include the
  reconciled ``develop`` changes.
- M10.8, M10.9a, M10.9b, and M10.9c are achieved. M10.9c1–M10.9c9 closed the
  inventoried reusable component catalogue; M10.9c10 adds immutable hierarchical
  composite graphs, reusable blocks, compositional AES variants, and scoped
  representation access. M10.9d provides readable Sage-independent native
  construction source for all 145 behavioral catalogue records, owns its data
  and evidence, and has no runtime frozen-graph artifacts. M10.9d11 is the
  current corrective refinement for family layout, metadata, reference-source
  ergonomics, and structural wiring.
- M10.9e and M10.9f are achieved, as are inversion/transformations (M10.10),
  component analysis (M10.11), datasets/statistics (M10.12), neural
  distinguishers (M10.13), reports/presentation (M10.14), and serialization,
  diagrams, and code generation (M10.15). M10.16 is the next open milestone.
- The canonical multi-architecture Python 3.11+ Docker image remains required
  before release, but is queued rather than the active migration workstream.
  Until then, local Python 3.11 and the legacy compatibility image are reported
  separately, including their skips and missing dependencies.

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
| Traditional primitive reference implementations | Representative slice achieved | AES-128/192/256, PRESENT-80/128, multiple Speck variants, and all standard Simon configurations use the final primitive terminology; the complete classified catalogue follows in M10.9d |
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
| Representation architecture (M10.5d) | Achieved | Graph construction, shared semantics, immutable annotated diagram IR, deterministic routed ASCII, TikZ, and optional PDF remain separated from execution engines |
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
| Diagram representation (M10.5d5) | Achieved | One annotated IR feeds deterministic routed box-and-connector ASCII art, TikZ, and optional LaTeX/PDF rendering while retaining input order and logical selections |
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
| Remaining mathematical/solver models (M10.8) | Achieved | Component semantics, whole-graph monomial composition, fixed algebraic evidence, and the complete 149-entry CP/SAT/CMS/SMT/MILP/algebraic inventory are closed through M10.8a–M10.8d |
| Boolean ANF/component monomial baseline (M10.8a) | Achieved | Sage-free Möbius ANF, symbolic cube coefficients, exact S-box transition tables, portable one-hot MILP, real GLPK SAT/UNSAT coverage, and user/developer doctests |
| Whole-graph division-property composition (M10.8b) | Achieved | Graph-derived PRESENT and generic component semantics compose across multiple rounds, lower to portable MILP, execute in GLPK, and decode through an independent checker |
| PRESENT round monomial composition (M10.8b1) | Achieved | Sixteen exact S-box relations compose through the typed p-layer; possible witness and impossible pair are independently checked |
| Generic monomial graph semantics (M10.8b2) | Achieved | Typed S-box, Boolean addition/XOR, identity, concatenation, permutation, and constant relations share one independently checked dispatcher |
| Multi-round monomial solver composition (M10.8b3) | Achieved | Complete reduced PRESENT regions use graph p-layers and 3SDP S-box relations; real GLPK witness is independently decoded and checked |
| ANF/degree/cube/superpoly evidence (M10.8c) | Achieved | Exact and proof-qualified reduced-graph ANFs, degrees, cube coefficients, superpolys, balanced bits, structural bounds, and complete open-solver parity fixtures are preserved |
| Exact symbolic Boolean graph evaluation (M10.8c1) | Achieved | Typed Word rotations/XOR/AND/addition recover Simon-1 ANF terms, Simon-2 degree vector and `k49` superpoly; symbolic evaluation matches a concrete vector |
| Exact parity and balanced-bit evidence (M10.8c2) | Achieved | Exact Simon-4 expansion preserves the legacy degree vector and fixed-public-input cube-degree array; proof-qualified results identify balanced bits and reject incomplete proof claims |
| Scalable algebraic bounds and parity (M10.8c3) | Achieved | Exact partial ANFs, cube-sum checks, qualified structural bounds, complete open-solver parity, and independently checked reduced-Trivium evidence are restored; uBlock/Gaston cases retain explicit M10.9d prerequisites |
| Exact partial-ANF evidence (M10.8c3a) | Achieved | Public cube coefficients retain exact Boolean polynomials; Simon-3 preserves all 14 legacy partial-ANF monomials |
| Exact cube-sum verification (M10.8c3a2) | Achieved | Dependency-free exhaustive cube evaluation independently verifies the legacy Simon-2 `k49` superpoly at deterministic key assignments |
| Scalable degree/parity encoding (M10.8c3b) | Achieved | Sound structural bounds, whole-graph portable MILP reachability, and complete no-good parity enumeration run with explicit soundness/completeness claims and open GLPK execution |
| Structural degree-bound baseline (M10.8c3b1) | Achieved | Bit/Word XOR, AND, rotation, constants, concatenation and modular addition propagate sound bounded degrees; Simon-4 documents exact 8 versus loose bound 16 and never claims completeness |
| Whole-graph monomial reachability solver (M10.8c3b2) | Achieved | Portable COPY/XOR/AND/rotation/concatenation/constant MILP plus GLPK recovers Simon reduced degrees 2/3/8 and the legacy Simon-13 31-variable cube bound 30 |
| Complete monomial-path parity solver (M10.8c3b3) | Achieved | Portable no-good enumeration reaches terminal UNSAT, matches all five exact Simon-2 degree-three ANF monomials, and rejects path-limited results as incomplete |
| Remaining scalable algebraic fixtures (M10.8c3c) | Achieved | Typed Trivium `block_function` with free clock/keystream parameters, five published eSTREAM vectors, exact 13-clock ANF and 200-clock `i53` superpoly `k39 + k40*k41 + k66`, and complete GLPK parity recovering the exact 160-/200-clock IV monomials; remaining license-skipped literals receive final evidence classification in M10.8d |
| Remaining model inventory closure (M10.8d) | Achieved | 149/149 model entries resolved with zero deferrals and a passing closure gate. Every executed fixed result is migrated or retained with an explicit exact/lower-bound/heuristic/empirical/legacy-regression claim kind; backend syntax, mutable registries, search-only heuristics and permanently skipped proprietary-only hypotheses are superseded or removed without being promoted to evidence. CP, SAT, CMS, SMT, MILP, algebraic and shared utility inventories are closed |
| Primitive terminology/public API (M10.9a) | Achieved | Generic graph class `Cipher`→`Primitive` and catalogue package `ciphers`→`primitives`; official bare catalogue class names (`AES`/`AES128`, `Present`/`Present80`, `Speck`, `Simon`, `MiMC`, `Poseidon`, `ChaCha`, `Salsa`); `CipherDiagram`→`PrimitiveDiagram` and its `cipher_name`→`primitive_name` field; generic vocabulary (cipher graph/input/output/evaluation, `cipher_output` sentinel) replaced by primitive-oriented terms throughout source, tests, and both guides; dependency-free `tools/terminology_guard.py` wired into `pytest tests/unit` blocks new generic `cipher`/`ciphers` usage outside the real `block_cipher(s)`/`tweakable_block_cipher(s)` taxonomy and `ciphertext` |
| Fixed-length primitive classification (M10.9b) | Achieved | All 149 legacy catalogue modules classified by fixed-length interface: 112 in the six semantic categories, 33 in orthogonal fixture folders, and four explicit non-primitive helpers. A dependency-free gate validates key/tweak roles, bijectivity obligations, official names, destinations, and removal of hash/MAC/stream as v5 categories |
| Complete reusable component catalogue (M10.9c) | Achieved | M10.9c1–M10.9c9 close all 75 inventoried behavioral records; M10.9c10 adds immutable hierarchical composite graphs, reusable blocks, compositional AES variants, scoped representations, and executable documentation |
| Component catalogue audit (M10.9c1) | Achieved | 77 owned records (44 source, 33 test), two package markers, 75 behavioral records, 252 legacy test functions, and 15 existing typed component baselines are machine checked and assigned without claiming semantic parity |
| Authoring/state/helper foundations (M10.9c2) | Achieved | All 17 owned records have concrete dispositions; immutable graph types supersede mutable DTO/base/input/round state, Sage/report/discovery leftovers are removed or reassigned, and dependency-free integer/word/sequence/layout helpers preserve fixed evidence |
| Structural and graph-boundary components (M10.9c3) | Achieved | All 12 records resolved: typed constants/permutations retain semantic values, generic logical-unit permutations supersede reverse/word subclasses, graph outputs/traces supersede output pseudo-operations, and explicit MSB-first bit/word bindings have scalar/batch round-trip checks; M10.9f6 later removed their temporary component representation |
| Boolean/logical/substitution components (M10.9c4) | Achieved | All 12 records resolved: typed multi-input XOR/AND/OR and unary NOT have exhaustive truth-table, scalar/batch, exact-ANF, and sound-degree checks; existing lookup S-box semantics retain fixed DDT/LAT evidence; the backend-bearing logical superclass is superseded |
| Word and ARX components (M10.9c5) | Achieved | All 18 records resolved: fixed/variable shifts and rotations, modular add/subtract/multiply, and IDEA zero-encoded multiplication have typed validation, exhaustive small-width arithmetic, boundary, and scalar/transposed-batch checks |
| Finite-field and linear-layer components (M10.9c6) | Achieved | All four records resolved: row-major typed `LinearMap` plus `BinaryExtensionField` supersede duplicate MixColumn classes with complete binary/GF(2^4), published AES-column, validation, and scalar/transposed-batch checks |
| Feedback-register components (M10.9c7) | Achieved | Both records resolved: immutable feedback terms/register specs provide binary, conditional-clock, multi-clock, and explicit binary-extension-field word semantics with exhaustive truth maps and scalar/transposed-batch parity |
| Permutation-specific reusable components (M10.9c8) | Achieved | All ten records resolved by composition: ShiftRows returns a generic logical-unit permutation, while Sigma and Gaston/Keccak/Xoodoo theta return typed binary `LinearMap` components; fixed legacy prefixes and independent Keccak diffusion are preserved without Sage or pickle caches |
| Reusable component catalogue closure (M10.9c9) | Achieved | Central `claasp_next.components` exports and `Primitive.add_component` authoring are documented; 75/75 behavioral records have final dispositions and existing evidence destinations; host 506 passed/78 external deselected; user/developer doctests 213/460; Python-3.10 compatibility Docker 503 passed/3 skipped/78 deselected and external 76 passed/2 skipped/506 deselected |
| Hierarchical composite graphs and reusable blocks (M10.9c10) | Achieved | Immutable definitions and scope overlays lower to the canonical flat DAG; parallel S-box, ChaCha-quarter-round, AES key-schedule, and AES-round blocks support scoped evaluation/modelling; explicit AES variants and executable documentation complete the slice |
| Immutable composite graph foundation (M10.9c10a) | Achieved | Frozen definitions and instances retain typed named boundaries and provenance; deterministic namespaced lowering preserves nested scope paths over the ordinary leaf DAG; definitions and instances project to the existing primitive representations; host 510 passed/78 external deselected |
| Reusable composite block catalogue (M10.9c10b) | Achieved | Generic 2^n-entry parallel S-box definitions support arbitrary counts, flat-bit SAT-ready lowering, and typed finite-domain units; ChaCha quarter rounds expose named and joined outputs and preserve the RFC 8439 vector; host 514 passed/78 external deselected |
| Compositional AES and variants (M10.9c10c) | Achieved | Reusable key-schedule, substitution-layer, and round definitions preserve AES-128/192/256 and lookup/algebraic vectors; the later M10.9d11 refinement reserves canonical `AES` for the direct reference source and renames research composition to `CustomAES` |
| Composite documentation and closure (M10.9c10d) | Achieved | User examples build AES from blocks, replace its S-box, omit MixColumns, evaluate ChaCha quarter rounds, and generate parallel-S-box/quarter-round CNF; developer docs specify immutable hierarchy and flat lowering; host 516 passed/78 external deselected; API/user/developer doctests 39/243/480; warning-free user/developer HTML; Python-3.10 compatibility Docker 513 passed/3 skipped/78 deselected and external 76 passed/2 skipped/516 deselected |
| Complete primitive implementations/evidence (M10.9d) | Achieved | Native-source/evidence closure plus M10.9d11 family packaging, typed primitive/input metadata, reference authoring sources, and structural-wiring refinement are complete; M10.9e may now resume |
| ChaCha permutation evaluation slice (M10.9d1) | Achieved | Official `ChaCha` class, standard round convention, typed ARX graph, full ChaCha20 and two legacy toy vectors, and scalar/batch parity; cryptanalytic fixture migration remains separately tracked |
| Salsa permutation evaluation slice (M10.9d2) | Achieved | Official `Salsa` class, standard full-round convention, typed ARX graph, both fixed legacy vectors, and scalar/batch parity; cryptanalytic fixtures remain separately tracked |
| Primitive catalogue audit (M10.9d3) | Achieved | Machine inventory assigns 149 source and 143 primitive-test records (265 functions) exactly once across M10.9d1–M10.9d8: 145 behavioral sources and four reviewed outside-scope helpers; the audit gate passes while the separate closure gate exposes every unimplemented destination |
| Single-component and toy primitives (M10.9d4) | Achieved | All 33 source and 31 test records are resolved by 26 typed one-operation primitives and seven toy families; fixed vectors, reduced/custom parameters, scalar semantics, and every ToyAES matrix MDS status are independently checked; host checkpoint: 548 passed, 78 external deselected |
| Word-oriented block primitives (M10.9d5) | Achieved | All 15 source and 15 test records are resolved by typed graphs for Aradi, CHAM, HIGHT, IDEA, LEA, Raiden, RC5, Simeck, Simon, SPARX, Speck, TEA, Threefish, TRAX, and XTEA; applicable fixed vectors, parameter variants, reduced rounds, and scalar/batch parity pass; host checkpoint: 602 passed, 78 external deselected |
| Substitution/linear and tweakable block primitives (M10.9d6) | Achieved | All 55 source and 55 test records have readable native typed-graph construction source; 242 audited parameter variants construct, all 267 fixed observations captured by the 198 legacy tests pass, and all 55 defaults have scalar/batch parity; neither Sage nor the legacy package is required at runtime; host checkpoint: 835 passed, 78 external deselected |
| Remaining permutations (M10.9d7) | Achieved | All 25 source and 25 test records have typed forward-graph destinations; 101 audited parameter variants construct, all 55 fixed observations captured by the 46 legacy tests pass, and all 25 families have scalar/batch parity; Keccak/Xoodoo invertible and Spongent FSR remain distinct realizations without claiming M10.10 graph inversion; host checkpoint: 899 passed, 78 external deselected |
| Fixed-length functions/block functions (M10.9d8) | Achieved | All 15 source and 15 test records have typed graph destinations; 41 fixed observations captured by the 20 legacy tests pass, all 15 families have scalar/batch parity, and conditional/word FSR plus explicit-modulus addition semantics are independently checked; host checkpoint: 941 passed, 78 external deselected |
| Primitive-owned parameters/data (M10.9d9) | Achieved | Poseidon owns its implementation, typed parameter schema, BN254 data, pinned vector, provenance, and MIT notice; LowMC owns its 11 vetted data files; `claasp_next.parameters` is a thin re-export; AES, LowMC, and Poseidon use same-import-path packages for multiple realizations or owned data, while simple primitives use readable modules; the built wheel contains every owned artifact |
| Complete primitive catalogue closure (M10.9d10) | Achieved | Machine closure reports 149/149 classified sources, 145/145 behavioral destinations, zero unresolved evidence, zero intermediate frozen graphs, and zero runtime frozen artifacts; 432 audited constructor configurations pass; host 946 passed/510 deselected; API/user/developer doctests 39/253/480; warning-free user/developer HTML; wheel 358 files/11 owned data files/zero graph artifacts; Python-3.10 compatibility Docker 943 passed/3 skipped/510 deselected and external 76 passed/2 skipped/1378 deselected |
| Catalogue layout/authoring refinement (M10.9d11) | Achieved | All five corrective slices are complete: families are packaged, inputs and primitive kinds are typed, AES/Speck/ChaCha are reference sources, public structural joins reconcile the legacy concatenate removal, and teaching fixtures mirror the v5 base-component API |
| Realization-family packages (M10.9d11a) | Achieved | All 16 audited multi-realization families use stable same-import-path packages; KTANTAN was added to the initial list and TinyJambu has three realizations. PRINCE and PRINCEv2 have separate module paths and primitive identities because they are distinct specifications. Legacy-derived Simon/Simeck/Gimli S-box forms remain explicitly non-canonical pending M10.9f authenticity metadata; 432-constructor audit retained |
| Primitive/input metadata (M10.9d11b) | Achieved | `PrimitiveKind`, `PrimitiveInput`, and `InputVisibility` distinguish mathematical interfaces from engines and make key secrecy an overridable study default; `input(name_or_position)` and `inputs(*selectors)` expose ordered graph ports without leaking their storage representation, while `input_ports` explicitly serves mapping-oriented graph consumers; all 26 single-component primitives contain exactly one round and one semantic component, carry conservative function/permutation kinds, and visibly demonstrate `add_round`, `add_component`, and `set_output` in their advertised operation module. Public constructors now expose only canonical v5 parameters: `LinearLayer(matrix)` infers its input width from one row-major matrix, `Fsr(parameters)` uses typed register data, permutations use direct output-to-input mappings, directions are explicit, and compatibility-only aliases, encodings, numeric sentinels, and ignored arguments are absent. Fifteen catalogue families now use `None` for omitted configuration and reject explicit zero rounds, steps, or S-box counts. The refinement checkpoint retains 432 catalogue constructor configurations and reports host 1416 passed/78 external deselected, API/user/developer doctests 41/284/498, warning-free HTML, and Python-3.10 compatibility Docker 1413 passed/3 skipped/78 deselected |
| Reference authoring implementations (M10.9d11c) | Achieved | Direct AES, Speck, and ChaCha sources follow specification pseudocode, omit incidental ids, retain semantic boundary references, and share Primitive configuration validation; semantic setters and incremental recorders publish round keys, states, key-schedule states, and named operation landmarks without author-visible storage conversions; ordered composite outputs support `key_schedule.output[n]`; `CustomAES` owns research variants separately from ToyAES |
| Structural wiring and closure (M10.9d11d) | Achieved | `Primitive.join`, `CompositeBuilder.join`, and multi-value `set_output` make joining an authoring-level typed wiring operation; M10.9f6 later replaced the temporary internal normalization node with a non-component typed binding. The corrected PRINCE identities and discoverable single-component sources retain the extended 432-constructor audit, and every semantic single-component source visibly demonstrates the complete authoring sequence without inline container normalization; host 966 passed/510 deselected; API/user/developer doctests 41/281/495; warning-free HTML; wheel 380 files/14 owned data files/zero graph artifacts; Python-3.10 compatibility Docker 963 passed/3 skipped/510 deselected and external 76 passed/2 skipped/1398 deselected |
| Base-component primitive alignment (M10.9d11e) | Achieved | A dedicated machine catalogue maps all 26 public base component classes one-to-one to same-named, same-module teaching primitives with one round, one component, class docstrings, and executable examples. `LinearMap` replaces legacy LinearLayer/MixColumn fixture types, all new algebraic/conversion components are represented, and `FeedbackRegister` uses `feedback_register.py`; legacy fixture records remain many-to-one migration evidence. Host: 980 passed/510 external deselected; API/user/developer doctests: 67/290/500; warning-free user/developer HTML; Python-3.10 compatibility Docker: 977 passed/3 skipped/510 deselected; Docker external: 76 passed/2 skipped/1412 deselected |
| Primitive realizations/task selection (M10.9e) | Achieved | M10.9e1–M10.9e5 provide generic stable realization metadata, explicit and deterministic task selection, audited family equivalence with canonical typed contracts, separate realization/driver provenance, executable guides, and machine-checkable closure for 16 families/36 graphs |
| AES realization vertical slice (M10.9e1) | Achieved | Lookup S-box and field-inverse-plus-binary-affine graphs share one public class and all AES-128/192/256 fixed vectors; deterministic capability selection is documented and tested |
| Realization audit and generic metadata (M10.9e2) | Achieved | Machine audit covers all 17 packaged implementation families plus the PRINCE/PRINCEv2 boundary; exact aliases, distinct parameterizations, and derived primitives are excluded explicitly. Generic descriptors carry stable primitive-qualified identity, capabilities, structural features, maturity, provenance, and priority; preferred and unique policies have typed unsupported/ambiguous failures. Host: 1425 passed/78 external deselected |
| Realization family selection/equivalence (M10.9e3) | Achieved | Fifteen additional canonical families expose 34 proved graph realizations through generic explicit/capability selection. Typed adapters preserve canonical word/bit shapes and declaration order for Aradi, Simon, Simeck, and TinyJambu; 45 seeded independent differential comparisons, published/fixed vectors, scalar/batch evidence, and exact boundary assertions pass. DESExactKeyLength, CustomAES/ToyAES, PRINCEv2, and exact alias modules remain outside interchangeable sets; Simon/Simeck/Gimli S-box graphs retain legacy-regression maturity. Host: 1446 passed/78 external deselected |
| Realization and engine provenance (M10.9e4) | Achieved | Typed `ResultProvenance` records the selected descriptor separately from a typed execution/solver driver identity. Scalar, ordinary-batch, transposed-batch, graph annotations, high-level SAT results, generic representation artifacts, neural runs, and statistical manifests preserve the two axes without treating engines as realizations. Statistical manifest schema v2 names `python_scalar`. Host: 1447 passed/78 external deselected; affected host solver group: 39 passed/8 Chuffed-only skipped. The aggregate host external run was stopped after macOS left Dieharder in uninterruptible I/O despite its 10-second timeout; isolated Docker external coverage remains required by M10.9e5 |
| Realization documentation and closure (M10.9e5) | Achieved | `realization_closure.py --check` validates 16 interchangeable families/36 graphs against the committed audit. Host Darwin arm64/Python 3.11.12: 1448 passed/78 external deselected; external except the host-stuck Dieharder case: 68 passed/9 skipped/1448 deselected. API/user/developer doctests: 68/307/517; both HTML sites warning-free. Wheel: 379 files/14 owned data files/zero frozen graph artifacts. amd64 Python 3.10.12 Docker: 1445 passed/3 skipped/78 deselected; Docker external: 76 passed/2 skipped/1448 deselected, including Dieharder and NIST STS. Docker tools: MiniZinc 2.9.4/Chuffed 0.13.2, GLPK 5.0, Z3 4.8.12, Singular 4.2.1, MiniSat 2.2.1, Dieharder 3.31.1. Host tools: MiniZinc 2.9.3 without Chuffed, GLPK 5.0, Z3 4.14.1, Singular 4.4.1; NIST STS absent. Generated Sphinx and package-build artifacts were removed |
| Catalogue discovery/query API (M10.9f) | Achieved | M10.9f1–M10.9f5 provide committed authoritative metadata, immutable typed records, category/component/design/capability/parameter/representation/analysis/driver queries, lazy availability probes, executable guidance, and machine-checkable closure without eager optional dependencies or presentation-layer coupling |
| Authoritative catalogue metadata (M10.9f1) | Achieved | Versioned committed metadata covers 145 public primitives, 26 public base components, and 14 drivers; it joins M10.9b classification, typed contracts, fixed-evidence paths, component/design tags, parameter sets, realization descriptors, and explicit non-canonical legacy-regression labels without runtime taxonomy inference. Host: 1451 passed/78 external deselected |
| Immutable catalogue discovery records (M10.9f2) | Achieved | `claasp_next.catalogue` returns frozen primitive, input, component, realization, parameter-set, and driver records from the packaged metadata resource. Category, component, ARX/AND-RX, S-box, FSR, tweak, and authenticity filters compose without importing primitive implementations; tables and rendering remain deferred to M10.14. Host: 1463 passed/78 external deselected |
| Capability, parameter, and availability queries (M10.9f3) | Achieved | Deterministic realization capability/structure/maturity and primitive parameter-set queries return immutable records. Driver declarations are queryable without probes; explicit availability returns typed results using executable lookup, MiniZinc solver registration, or Python module discovery without importing driver implementations or optional dependencies. Host: 1467 passed/78 external deselected; the host has MiniZinc 2.9.3 without Chuffed, plus GLPK, Z3, MiniSat, Singular, msolve, Dieharder, LaTeX, and scikit-learn; NIST STS is absent |
| Catalogue documentation and closure (M10.9f4) | Achieved | `catalogue_closure.py --check` validates all 145 primitives, 26 components, and 14 drivers against the classification, export, component, realization, evidence, and regenerated metadata authorities. Host Darwin arm64/Python 3.11.12: 1472 passed/78 external deselected; external excluding the known host-stuck Dieharder case: 68 passed/9 skipped/1472 deselected. API/user/developer doctests: 68/319/521; both HTML sites warning-free. Wheel: 383 files/15 data files including the catalogue resource/zero frozen graph artifacts. amd64 Python 3.10.12 Docker: 1469 passed/3 skipped/78 deselected; Docker external: 76 passed/2 skipped/1472 deselected, including Dieharder and NIST STS. Docker tools: MiniZinc 2.9.4/Chuffed 0.13.2, GLPK 5.0, Z3 4.8.12, Singular 4.2.1, MiniSat 2.2.1, Dieharder 3.31.1; msolve and scikit-learn are absent. Generated Sphinx and package-build artifacts were removed |
| Catalogue capability graph (M10.9f5) | Achieved | Schema v2 adds 13 conservative representation records and 9 public analysis records, with immutable component/domain/scope restrictions and bidirectional component↔representation and representation↔driver queries. Primitive analysis discovery requires full graph coverage except for explicitly component-scoped semantics, and reviewed reduced-round analyses retain visible restrictions. Host Darwin arm64/Python 3.11.12: 1043 passed/510 external deselected; affected external group: not applicable because no solver execution or provenance path changed. API/user/developer doctests: 72/323/521; both HTML sites warning-free. Wheel: 383 files/15 owned data files including the schema-v2 catalogue. amd64 Python 3.10.12 Docker: 1040 passed/3 dependency skips/510 external deselected. The closure gate validates 145 primitives, 26 components, 13 representations, 9 analyses, and 14 drivers; generated Sphinx and package-build artifacts were removed. |
| Semantic component boundary cleanup (M10.9f6) | Achieved | Concatenation, ordered views, and explicit MSB-first bit/word reinterpretation are immutable graph bindings shared by scalar/batch/symbolic execution, constraints, diagrams, composites, and realization normalization. Concatenate, PackBits, and UnpackBits are absent from the component and teaching-primitive catalogues; the only default catalogue graph containing Identity is the explicitly authored Identity teaching primitive. The closure gate validates 142 primitives, 23 components, 13 representations, 9 analyses, and 14 drivers. Host Darwin arm64/Python 3.11.12: 1476 dependency-free passed/78 external deselected; affected external group: 67 passed/8 Chuffed-only skipped/1479 deselected. API/user/developer doctests: 68/322/517; both HTML sites warning-free. Wheel: 378 files/15 owned data files/zero frozen graph artifacts. amd64 Python 3.10.12 compatibility Docker: 1041 passed/3 dependency skips/510 deselected; Docker external: 76 passed/2 optional-dependency skips/1476 deselected. Docker tools: MiniZinc 2.9.4/Chuffed 0.13.2, GLPK 5.0, Z3 4.8.12, Singular 4.2.1, MiniSat 2.2.1, and Dieharder 3.31.1. Generated documentation and package-build artifacts were removed. |
| Primitive inversion and graph transformations (M10.10) | Achieved | M10.10a–M10.10g delivered the immutable transformation layer; M10.10h1–M10.10h7 then audited every catalogue configuration, replaced repeated scans with dependency scheduling, added exact reversible-region and remaining component semantics, corrected retained-input obligations, achieved complete catalogue coverage, and closed performance/documentation checkpoints |
| Transformation contracts/traversal/provenance (M10.10a) | Achieved | Immutable results and typed failures; standard-library dependency traversal covers inputs, semantic components, structural bindings, and composite membership; execution provenance carries graph transformations separately from realization and driver identity. Darwin arm64/Python 3.11.12: 1479 passed/78 external deselected; public transformation/provenance doctests: 7 passed |
| Validated graph slicing/dependency closure (M10.10b) | Achieved | Explicit homogeneous boundaries, forward/backward closure, validated reconstruction, complete composite-scope overlays, structural-binding preservation, dependency splits, and published round-state slicing; incomplete boundaries fail as disconnected dependencies. Independent Speck trace comparisons pass. Darwin arm64/Python 3.11.12: 1484 passed/78 external deselected; focused tests/doctests: 15 passed |
| Component inverse semantics (M10.10c) | Achieved | Immutable exact-type registry covers bijective permutations, rotations, substitutions, linear/affine maps and finite-field powers plus retained-auxiliary recovery for XOR, additive, modular, and variable-rotation semantics; independent exhaustive evaluation verifies inverse behavior, generated components have no incidental IDs, and typed failures distinguish ambiguity, missing auxiliaries, information loss, and unsupported operations. Darwin arm64/Python 3.11.12: 1496 passed/78 external deselected; focused tests/doctest: 13 passed |
| Complete/partial primitive inversion (M10.10d) | Achieved | Solver-free complete and partial inverse construction consumes explicit known boundaries, retains auxiliary inputs, propagates equivalent wires across structural joins/views/PackBits/UnpackBits, forward-builds retained dependencies, and recovers exactly one predecessor at a time without Identity placeholders or preserved component IDs. Full Speck plus fixed Speck/PRESENT/Simon evidence and internal-wire/fanout/conversion tests use independent scalar evaluation; realization identity and transformation provenance remain separate. Darwin arm64/Python 3.11.12: 1504 passed/78 external deselected; focused tests/doctests: 30 passed |
| Editor transformations (M10.10e) | Achieved | Validated immutable reconstruction now provides round-prefix reduction, output-closure orphan pruning, explicit secret round-key boundaries with computed key schedules removed, optional bypass of recognized zero-neutral key injections, and exact permutation/permutation-matrix/word-rotation inlining as structural bindings. Independent Speck/PRESENT evaluation confirms semantics; non-permutation linear maps and explicitly authored Identity components remain semantic. Darwin arm64/Python 3.11.12: 1510 passed/78 external deselected; focused tests: 19 passed |
| Paired/XOR graph transformations (M10.10f) | Achieved | Single-key and related-key transformations instantiate two named composite scopes, preserve nested hierarchy, and publish typed characteristic-two input, round-state, round-key, and output differences without mutable ID suffixing or Identity wiring. Fixed four-round Speck differences, PRESENT bit-domain evaluation, source immutability, explicit unsupported-domain diagnostics, and an independently checked SAT witness pass. Darwin arm64/Python 3.11.12: 1516 passed/78 external deselected; focused tests/doctest: 7 passed; affected host solver integrations: 66 passed/8 Chuffed-only skipped/1 deselected with MiniSat 2.2.1, Z3 4.14.1, GLPK 5.0, MiniZinc 2.9.3, msolve 0.10.1, and Singular 4.4.1 |
| Transformation documentation and closure (M10.10g) | Achieved | User docs execute complete inversion, retained-auxiliary partial inversion, slicing, round reduction, key-schedule removal, and paired XOR examples; developer docs define reconstruction invariants, dependency closure, binding handling, provenance separation, diagnostics, and registry extension. The machine gate resolves all 9 M10.10 records (5 sources/4 tests), existing destinations, and fixed evidence, including direct MiniSat preservation of the legacy 10-round single-key compatible and 14-round related-key compatible/incompatible Speck trails. Darwin arm64/Python 3.11.12: 1518 dependency-free passed/81 external deselected; host external excluding the known stuck Dieharder executable: 71 passed/9 skipped/1519 deselected. API/user/developer doctests: 87/354/517; both HTML sites warning-free. Wheel: 386 files/15 owned data files/zero frozen graph artifacts. amd64 Linux/Python 3.10.12 compatibility Docker: 1083 passed/3 optional-dependency skips/513 external-or-extended deselected; Docker external: 79 passed/2 optional-dependency skips/1518 deselected, including the three paired constraints, Dieharder, and NIST STS. Docker tools: MiniZinc 2.9.4/Chuffed 0.13.2, GLPK 5.0, Z3 4.8.12, Singular 4.2.1, MiniSat 2.2.1, and Dieharder 3.31.1. Host affected solver tools: MiniZinc 2.9.3 without Chuffed, GLPK 5.0, Z3 4.14.1, Singular 4.4.1, MiniSat 2.2.1, and msolve 0.10.1; NIST STS is absent and the installed host Dieharder remains the pre-existing timeout-stuck environment case. Generated documentation and package-build artifacts were removed. |
| Catalogue-wide inversion coverage and performance (M10.10h) | Achieved | The committed 234-configuration audit, dependency-driven engine, exact reversible-region recovery, component/boundary semantics, reviewed realization contracts, corrected complete 208/208 retained-input-bijective coverage, bounded regressions, documentation, and host/container closure checkpoints are complete |
| Inversion audit and acceptance contract (M10.10h1) | Achieved | Reproducible isolated audit covers 142 primitives/234 official configurations, separately measures constructed one-round and full graphs, and verifies two deterministic scalar round trips. It repaired six invalid parameter declarations and added a signature gate. Baseline: 130 verified, 103 typed unsupported/stalled, one zero-input incidental error; 113/188 catalogue-bijective configurations currently verify. Slowest verified configurations are KATAN-FSR-64 at 140.0 s and KTANTAN-FSR-64 at 124.6 s. Host dependency-free: 1519 passed/81 deselected; audited constructor inventory: 432 passed. |
| Dependency-driven inversion engine (M10.10h2) | Achieved | Atom-indexed deterministic work scheduling revisits only components/bindings affected by newly equivalent wires while preserving forward reconstruction, inverse rules, structural bindings, provenance, and typed stalls. KATAN-FSR-64 improved from 140.0 s to 2.64 s and KTANTAN-FSR-64 from 124.6 s to 2.10 s in isolated semantic audits; a full KATAN-FSR-64 round trip is guarded below 10 s. Host dependency-free: 1520 passed/81 deselected. |
| Reversible-region recovery (M10.10h3) | Achieved | Deterministic exact Gaussian elimination recovers only uniquely isolated wires in reversible XOR regions, bit-blasts word rotations across structural PackBits/UnpackBits without turning bindings into components, and leaves underdetermined predecessors stalled. Reviewed equivalent realizations preserve source realization identity while recording a separate transformation step. Exhaustive three-word joint recovery plus independent IDEA, one-round KeccakSbox/XoodooSbox, AradiSBox, Ascon, and Gaston-family semantic checks pass; ordinary joint-recovery unit work remains below one second. Darwin x86_64/Python 3.11.12 dependency-free checkpoint: 1532 passed/81 external deselected. |
| Remaining inverse/boundary semantics (M10.10h4) | Achieved | IDEA zero-encoded group multiplication recovers any operand from retained auxiliaries, and explicitly pivoted unconditional binary/binary-field feedback transitions invert for multiple clocks while non-pivoted or conditionally clocked transitions retain typed information-loss diagnostics. Zero-input primitives now report an ambiguous boundary instead of an indexing failure. Exhaustive 4-bit three-operand IDEA recovery, complete eight-round IDEA recovery, binary and nonunit field-pivot feedback round trips, and focused diagnostics pass. Darwin x86_64/Python 3.11.12 dependency-free checkpoint: 1532 passed/81 external deselected. |
| Complete bijective catalogue coverage (M10.10h5) | Achieved | All 188/188 configurations carrying a catalogue bijectivity obligation construct and pass two independent scalar round trips. Exact solver-free recovery now covers reviewed compact/triangular realizations for Aradi, Gimli, Keccak, NORX, QARMAv2, Xoodoo, and TinyJambu FSR plus directly authored published inverses for Subterranean and ChiLow; SCARF's two public state halves are correctly bound. The complete 234-configuration audit records 207 verified, 21 typed unsupported, 5 timed out, and one zero-input not-applicable result, with every non-verified row outside the catalogue bijectivity obligation. Darwin x86_64/Python 3.11.12 dependency-free checkpoint: 1547 passed/81 external deselected; focused reviewed-realization/direct-inverse and SCARF checks: 20 passed. |
| Inversion performance/documentation closure (M10.10h6) | Achieved | The regenerated Markdown audit records 142 primitives/234 configurations, separate one-round and official full timings, 207 verified outcomes, and complete 188/188 catalogue-bijective semantic coverage; non-obligated lossy/stalled/timeout rows remain explicitly qualified. Full KATAN-FSR-64, Gimli, and NORX-32 regression cases each stay below the ten-second integration budget. Host Darwin x86_64/Python 3.11.12: 1549 dependency-free passed/81 external deselected; solver-facing external reruns were not applicable because M10.10h changed no solver representation or driver. API/user/developer doctests: 87/354/517; both HTML guides build warning-free. Inventory, catalogue, realization, and terminology gates pass; catalogue closure remains 142 primitives/23 components/13 representations/9 analyses/14 drivers. Wheel: 388 files/15 owned data files/zero frozen graph artifacts. amd64 Linux/Python 3.10.12 compatibility Docker: 1114 passed/3 optional-dependency skips/513 external-or-extended deselected; Docker external: 79 passed/2 optional-dependency skips/1549 deselected. Docker tools: MiniZinc 2.9.4 with Chuffed 0.13.2, GLPK 5.0, Z3 4.8.12, Singular 4.2.1, MiniSat 2.2.1, and Dieharder 3.31.1. Host tools: MiniZinc 2.9.3 without Chuffed, GLPK 5.0, Z3 4.14.1, Singular 4.4.1, and MiniSat 2.2.1; the installed host Dieharder remains broken by its pre-existing missing GSL dylib. The canonical multi-architecture Python 3.11+ image remains queued independently of this milestone. Generated documentation, wheel, build, egg-info, pytest, and project-source bytecode artifacts were removed. |
| Retained-input obligation correction (M10.10h7) | Achieved | A shared reviewed authority replaces folder-only inference and classifies the designated data/state map with auxiliaries retained: 6/7 named toy configurations, 16/23 single-component defaults, and ChaChaKeystreamBlock now carry precise positive obligations. Fixed collisions prove Fancy's lossy odd-round map and optional two-bit ToyAES variants are not permutations; the named eight-bit ToyAES configuration remains bijective. The regenerated 142-primitive/234-configuration report records 208 verified, 20 typed unsupported, 5 timed out, and one not-applicable result, with complete 208/208 obligated coverage and zero successful non-obligated full configurations. Host Darwin x86_64/Python 3.11.12: 1575 dependency-free passed/81 external deselected; routine host: 1143 passed/513 extended-or-external deselected; focused toy/inversion checks: 61 passed. API/user/developer doctests: 87/357/517; both HTML guides warning-free. Inventory and catalogue gates pass; wheel: 388 files/15 owned data files/zero frozen graph artifacts. amd64 Linux/Python 3.10.12 compatibility Docker: 1140 passed/3 optional-dependency skips/513 external-or-extended deselected; Docker external: 79 passed/2 optional-dependency skips/1575 deselected. Docker tools remain MiniZinc 2.9.4 with Chuffed 0.13.2, GLPK 5.0, Z3 4.8.12, Singular 4.2.1, MiniSat 2.2.1, and Dieharder 3.31.1; no solver representation or driver changed. |
| Component analysis (M10.11) | Achieved | M10.11a–M10.11g provide immutable typed contracts, semantic grouping, exact lookup/linear/Boolean/feedback properties, explicit bounded and MiniZinc drivers, concise primitive APIs, catalogue capability metadata, executable documentation, and machine-checked inventory closure |
| Component-analysis contracts and ownership (M10.11a) | Achieved | Immutable requests/results distinguish exact values, proved bounds, empirical observations, and typed unavailable diagnostics; semantic/realization provenance is separate from optional driver provenance. The two legacy records have explicit M10.11 destinations and evidence, while radar plots stay with M10.14 and M10.8d wordwise MILP dispositions remain closed. Darwin arm64/Python 3.11.12: 1579 dependency-free passed/81 external deselected; routine subset: 1147 passed/513 external-or-extended deselected. |
| Semantic component grouping (M10.11b) | Achieved | Immutable graph discovery excludes every structural binding and groups only exact semantic component types with typed parameters, input/output value types, and requested mathematical domains. Component ids never enter group identity; stable round/component locations are optional evidence. Darwin arm64/Python 3.11.12: 1583 dependency-free passed/81 external deselected. |
| Exact lookup-table properties (M10.11c) | Achieved | Dependency-free lookup analysis reuses exact DDT/LAT, sparse Boolean ANF, and bijective BCT semantics for differential uniformity, nonlinearity, algebraic degree, balancedness, APN status, differential/linear branch numbers, and boomerang uniformity. Rectangular/non-bijective applicability is explicit; fixed AES evidence is 4/112/7 and reduced-width checks use independent exhaustive definitions. Darwin arm64/Python 3.11.12: 1589 dependency-free passed/81 external deselected. |
| Linear/affine/MixColumn properties (M10.11d) | Achieved | Dependency-free finite-field elimination, all-minor MDS proofs, polynomial-basis bit expansion, exact matrix/affine/permutation order, and completeness-guarded branch enumeration preserve row-major orientation and explicitly transpose for linear masks. Fixed evidence includes identity/permutation branch 2, AES word branch 5/MDS, the ToyAES GF(4) state-size-4 non-MDS branch 3, and an asymmetric 4x4 differential-3/linear-2 map. Darwin arm64/Python 3.11.12: 1595 dependency-free passed/81 external deselected. |
| Boolean/word/feedback properties (M10.11e) | Achieved | Exact sparse component ANFs report degree, per-output term/variable counts, and linearity for XOR, AND, OR, NOT, rotate, shift, and modular add; invertibility/order is limited to justified word permutations. Feedback analysis retains immutable register terms, rule degrees, linearity, and typed connection-polynomial data only for unconditional linear rules. Reduced-width fixed evidence independently covers XOR/AND/NOT/rotate/shift/modular-add plus reversible and nonlinear/clocked registers. Darwin arm64/Python 3.11.12: 1599 dependency-free passed/81 external deselected. |
| Optional component-analysis drivers (M10.11f) | Achieved | An explicit dependency-free bounded-support driver returns exact results only after complete coverage or a proved mathematical lower bound and otherwise returns a proved upper bound. The optional MiniZinc driver consumes the same typed requests, performs exact binary optimization (including explicit linear transpose), records driver provenance, and returns a typed unavailable result when the executable is absent. Darwin arm64/Python 3.11.12: 1603 dependency-free passed/82 external deselected; host MiniZinc 2.9.3 with COIN-BC fixed differential-3/linear-2 evidence: 1 passed. |
| Component-analysis API and closure (M10.11g) | Achieved | `Primitive.analyze()` exposes semantic grouping plus single and batched typed property requests; driver results retain realization/evidence locations separately from driver provenance. Catalogue closure is 142 primitives/23 components/14 representations/10 analyses/16 drivers. The two M10.11 inventory records have final destinations and evidence, while both wordwise branch-number records remain `superseded-in-m10.8d`. Fixed user examples cover an S-box, binary map, and AES MixColumns; developer docs define contracts, applicability, conventions, evidence strength, provenance, diagnostics, and extensions without presentation APIs. Darwin arm64/Python 3.11.12: 1612 dependency-free passed/82 external deselected; routine host: 1180 passed/514 external-or-extended deselected; affected host MiniZinc 2.9.3/COIN-BC: 1 passed. API/user/developer doctests: 92/388/530; both HTML guides warning-free. Inventory, catalogue, realization, and terminology gates pass. Wheel: 392 files/15 owned data files/zero frozen graph artifacts. amd64 Linux/Python 3.10.12 compatibility Docker: 1177 passed/3 optional-dependency skips/514 deselected; Docker external: 80 passed/2 optional-dependency skips/1612 deselected. Docker tools: MiniZinc 2.9.4 with Chuffed 0.13.2, GLPK 5.0, Z3 4.8.12, Singular 4.2.1, MiniSat 2.2.1, and Dieharder 3.31.1. The canonical multi-architecture Python 3.11+ image remains queued independently. Generated documentation, wheel, build, egg-info, pytest, and project-source bytecode artifacts were removed. |
| Dataset/statistical testing (M10.12) | Achieved | Seeded dependency-free datasets, canonical streaming artifacts, result parsers, and optional shell-free Dieharder and NIST STS execution drivers, each with bounded dedicated CI against the real executable |
| Reproducible avalanche foundation (M10.12a) | Achieved | Immutable MSB-first paired bit-flip datasets, local seeded RNG, simple `primitive.analyze().avalanche(...)` API, fixed Speck evidence, and explicitly empirical result metadata |
| Streaming statistical dataset families (M10.12b) | Achieved | Lazy re-iterable correlation, zero-IV CBC, low-/high-density generators, deterministic weight-two sampling, streamed big-endian bytes, and fixed Speck evidence require no NumPy |
| Statistical stream serialization (M10.12c) | Achieved | Canonical raw fixed-width serialization, stable JSON manifests, SHA-256 identities, explicit MSB-first/big-endian/record ordering, and primitive realization provenance |
| Statistical suite result parsers (M10.12d) | Achieved | Dependency-free typed NIST STS and Dieharder result artifacts; every row in all five committed 188-row NIST summaries is preserved; empty Dieharder output is an error rather than fabricated evidence |
| Optional Dieharder driver (M10.12e1) | Achieved | Shell-free isolated execution consumes canonical streams and records the exact dataset hash, command, version, runtime, stdout/stderr, and typed report; bounded real-tool CI is dedicated and optional |
| Neural distinguishers (M10.13) | Achieved | Framework-independent seeded black-box/differential datasets, experiment/result/driver contracts, round/component trace projections (`component_output_dataset`, `xor_differential_component_dataset`, `round_component_ids`), and an optional scikit-learn `NeuralTrainingDriver` behind a dedicated bounded CI job (`neural-ml-execution`) are all in place |
| Neural experiment foundation (M10.13a) | Achieved | Pure-Python deterministic MSB-first datasets preserve legacy real/random and XOR-related label semantics; immutable training contracts import no ML framework |
| Neural split and provenance contracts (M10.13b) | Achieved | Deterministic optional stratification, explicit disjoint sample partitions, stable dataset SHA-256 identities, and realization/driver/version/seed/options provenance reject stale or incomplete runs |
| Reports and presentation (M10.14) | Achieved | M10.14a--M10.14g replace the legacy catch-all report with immutable dependency-free presentation contracts, typed result adapters, deterministic terminal/Markdown/CSV/report-data exports, optional plots/dataframes, safe explicit file output, citations, separated provenance, and reproducibility metadata. Presentation consumes existing results without recomputing analyses, training models, or invoking solvers. |
| Presentation contracts and ownership (M10.14a) | Achieved | Commit `3ac78f9e` defines evidence, applicability, diagnostics, citations, reproducibility, and separate mathematical/primitive/execution provenance contracts. A machine-readable obligation manifest assigns every audited legacy and deferred presentation surface to a destination and fixed evidence. Host dependency-free: 1618 passed/82 external deselected. |
| Immutable presentation tables (M10.14b) | Achieved | Commit `8a7bc879` adds frozen tables, rows, cells, sections, and report data plus deterministic formatting for numeric, vector, probability, correlation, weight, bound, Boolean, unavailable, and diagnostic values. Core imports remain isolated from optional plotting/dataframe/scientific packages. Host dependency-free: 1623 passed/82 external deselected. |
| Typed result presentation adapters (M10.14c) | Achieved | Commit `08d38004` adapts trails, traces, component properties, avalanche, NIST STS, Dieharder, neural experiments, continuous diffusion, and catalogue capabilities without recomputation. Ordering comes from typed semantics and graph locations remain optional evidence references. Host dependency-free: 1629 passed/82 external deselected. |
| Deterministic presentation exports (M10.14d) | Achieved | Commit `206d9225` adds aligned terminal and escaped Markdown output, standard-library CSV, and recursively JSON-compatible report data with deterministic ordering and formatting. These report-data exports are explicitly distinct from M10.15 versioned serialization. Host dependency-free: 1634 passed/82 external deselected. |
| Optional presentation renderers (M10.14e) | Achieved | Commit `bd179c75` adds lazy, explicitly requested Matplotlib component-radar, avalanche, NIST, and Dieharder renderers. Radar normalization is typed by domain, range, direction, applicability, and evidence; unavailable/incomparable properties are omitted and proved bounds remain visibly bounded. Headless tests inspect figure structure and deterministic data. Host dependency-free: 1639 passed/82 external deselected. |
| Report composition and safe output (M10.14f) | Achieved | Commit `e1a52e33` adds `present`, immutable report composition, explicit rendering, safe UTF-8 file writing with validated formats/extensions and overwrite policy, a lazy optional pandas adapter, and catalogue presentation capabilities. Catalogue closure: 142 primitives/23 components/15 representations/11 analyses/18 drivers. Host dependency-free: 1646 passed/82 external deselected. |
| Presentation API, documentation, CI, and closure (M10.14g) | Achieved | Public exports and docstrings, executable user examples, the presentation architecture guide, optional-renderer CI, all five committed 188-row NIST fixture summaries, and the M10.14 machine closure gate are complete. The four report inventory records are `superseded-in-m10.14g`; every retained deferred behavior has fixed evidence and all destinations exist. Darwin x86_64/Python 3.11.12: 1649 dependency-free passed/82 external deselected; routine host: 1217 passed/514 external-or-extended deselected; host external excluding the pre-existing broken Dieharder dylib: 72 passed/9 optional-tool skips/1649 deselected. API/user/developer doctests: 97/404/534; both HTML guides warning-free. Wheel: 402 files/15 owned data files/zero frozen graph artifacts. amd64 Linux/Python 3.10.12 compatibility Docker: 1214 passed/3 optional-dependency skips/514 deselected; Docker external: 80 passed/2 optional-dependency skips/1649 deselected. Host presentation packages: Matplotlib 3.9.3 and pandas 2.0.3. Docker tools: MiniZinc 2.9.4 with Chuffed 0.13.2, COIN-BC 2.10.12/1.17.10, GLPK 5.0, Z3 4.8.12, Singular 4.2.1, MiniSat 2.2.1, and Dieharder 3.31.1; msolve is absent. Host tools: MiniZinc 2.9.3 with COIN-BC, GLPK 5.0, Z3 4.14.1, Singular 4.4.1, MiniSat 2.2.1, and msolve 0.10.1; host Dieharder remains unusable because its installed binary references a missing GSL dylib. Generated documentation and package-build artifacts were removed. |
| Serialization, diagrams, code generation (M10.15) | Achieved | M10.15a--M10.15g provide explicit ownership and contracts, canonical primitive/artifact serialization, evaluator-helper closure, deterministic Python/C compilers and isolated drivers, and diagram/public-API/package closure. |
| Tooling ownership and contracts (M10.15a) | Achieved | Eleven Python records, three mixed-module surfaces, four C/header artifacts, the achieved diagram stack, schema/version policy, fixed evidence, and the evidence-based CUDA exclusion have explicit machine ownership. Darwin x86_64/Python 3.11.12 dependency-free: 1651 passed/82 external deselected. |
| Canonical primitive serialization (M10.15b) | Achieved | Dependency-free canonical UTF-8 JSON preserves typed domains, ordered inputs, components, bindings, rounds, composite scopes, outputs, realization and transformation provenance. A closed registry and typed diagnostics reject duplicate fields/identities, unknown schema versions/domains/components, malformed values, invalid references, type mismatches, inconsistent widths, and binding cycles; AES, PRESENT, Speck, KATAN, composite, and non-byte-aligned evidence round-trip and evaluate. Darwin x86_64/Python 3.11.12 dependency-free: 1666 passed/82 external deselected. |
| Typed artifact serialization (M10.15c) | Achieved | Separate versioned schemas serialize concrete execution traces and scalar evaluation results with canonical source ordering, primitive digests, realization/transformation/driver provenance, domain and output validation, and typed rejection for unregistered annotations or analysis results. These machine artifacts do not consume or redefine M10.14 report-data export. Darwin x86_64/Python 3.11.12 dependency-free: 1671 passed/82 external deselected. |
| Evaluation-helper closure (M10.15d) | Achieved | The existing scalar registry remains the oracle and both dependency-free batch drivers reuse its exact handlers. Legacy generic, evaluator, vectorized-bit, vectorized-byte, and their tests are explicitly superseded without a NumPy adapter; the stale continuous source/test records are closed under achieved M10.6d6/M10.14 ownership. Import isolation, AES/PRESENT/Speck, feedback, composite, structural-binding, and batch parity evidence remain fixed. Darwin x86_64/Python 3.11.12 dependency-free: 1673 passed/82 external deselected. |
| Deterministic Python source (M10.15e) | Achieved | `compile_source(..., target="python")` produces a validated immutable artifact from canonical graph bytes with stable source/digests and separate compiler provenance. Explicit safe writing refuses mismatched extensions, unsafe basenames, missing parents, and implicit overwrite. The bounded isolated driver uses an argument vector without a shell, validates typed graph-order output, and records command/runtime/stdout/stderr/status/source digest plus separate realization and execution provenance. Fixed Speck and PRESENT outputs and trace order match scalar evaluation. Darwin x86_64/Python 3.11.12 dependency-free: 1678 passed/82 external deselected. |
| Deterministic native source (M10.15f) | Achieved | The typed Bit/Word subset compiles to deterministic self-contained C11 with explicit unsupported-domain/component results; no legacy C/header ABI is shipped. Compilation and execution are separate bounded, shell-free, isolated operations with option allowlisting, safe predictable names, compiler absence/failure/timeout statuses, exact command/version/options/runtime/stdout/stderr/return status, source and binary digests, and separate realization/execution provenance. Fixed PRESENT bit and Speck word graphs match scalar evaluation under Apple clang 16.0.0; AES field components are honestly unsupported. CUDA is out of scope because the audit found no maintained source, driver, or result-bearing tests. Host external native: 4 passed; Darwin x86_64/Python 3.11.12 dependency-free: 1681 passed/86 external deselected. |
| Tooling documentation and closure (M10.15g) | Achieved | Public user/developer guidance separates canonical graph/result serialization, generated source, optional native execution, and diagrams. The catalogue now declares 19 representations and 24 drivers; diagram routing/round/annotation/TikZ-escaping evidence is complete; dedicated generated-C CI and package/wheel ownership checks are present. The M10.15 closure gate reports 11/11 final Python records, four native artifacts, three mixed surfaces, and retained M10.6d6 continuous ownership. Darwin x86_64/Python 3.11.12: 1686 dependency-free passed/86 external deselected; routine host: 1254 passed/518 external-or-extended deselected; native Apple clang 16.0.0: 4 passed; LaTeX/PDF: 1 passed. API/user/developer doctests: 100/424/534; both HTML guides warning-free. Wheel: 412 entries with required owned data and source modules, zero binaries/caches/legacy C-header ABI. amd64 Linux/Python 3.10.12 compatibility Docker: 1251 passed/3 optional-dependency skips/518 deselected; Docker external: 84 passed/2 optional-dependency skips/1686 deselected, including generated C under GCC 11.4.0 and PDF rendering. Inventory, catalogue, realization, terminology, and tooling gates pass. The canonical multi-architecture Python 3.11+ image remains queued independently. |
| Documentation and static-quality enforcement (M10.16) | In progress | M10.16a--M10.16h standardize and close public documentation, formatting, linting, typing, Sphinx, CI, and packaging quality |
| Documentation authority and measured baseline (M10.16a) | Achieved | The mechanical boundary covers 123 ``__all__`` modules, 1,179 qualified exports, 671 canonical objects, and 1,224 canonical public members; the developer policy records the section/example convention, reviewed exception schema, v5-only quality scope, Ruff 0.16.8 and mypy 2.3.1 selection, and explicit adoption measurements. Darwin x86_64/Python 3.11.12: 1686 dependency-free passed/86 external deselected. |
| Public-API documentation audit (M10.16b) | Achieved | A deterministic runtime/AST audit records 3,524 entries: 123 public modules, 1,179 qualified exports and aliases, plus canonical constructors, methods, properties, 808 dataclass fields, and 168 enum members. Its reviewed boundary includes constructors and methods inherited from exported public bases while excluding implementation-only inheritance. The closure tool rejects malformed/dynamic exports, missing or trivial docstrings, section-order errors, Sage prompts, missing examples, duplicate/stale/unregistered identities, and invalid or stale exceptions with missing evidence. Negative fixtures cover the failure modes; the starting live debt is retained as measured evidence rather than an exemption. Darwin x86_64/Python 3.11.12: 1690 dependency-free passed/86 external deselected. |
| Foundational API documentation closure (M10.16c) | Achieved | All public graph, domain, component, semantic, provenance, annotation, encoding, utility, and primitive-authoring entries pass the structural documentation and scoped executable-example audit with zero exceptions. Fixed examples cover graph construction, validation, typed transitions, immutable evidence, propagation, and exact or explicitly heuristic weights. |
| Processing API documentation closure (M10.16d) | Achieved | All public representation, serialization, source-compiler, driver, analysis, transformation, presentation, catalogue, and composite entries pass the structural documentation audit. Their 315 dependency-free module doctests cover typed records, exact model construction, diagrams, catalogue discovery, serialization round trips, generated-source contracts, transformations, analyses, and presentation data. The machine authority contains 38 narrow executable-example exceptions: 8 abstract protocol entries, 23 external-executable entries, and 7 environment-owned optional-framework entries, each with an owner, rationale, and fixed test evidence. |
| Primitive/export documentation closure (M10.16e) | Achieved | Every primitive catalogue class, constructor, public authoring method, generated export, alias, and remaining public callable passes the 3,524-entry structural audit. The dependency-free primitive module suite executes 152 deterministic doctests, including fixed primitive evaluations and catalogue/parameter discovery; no v5 public docstring retains a Sage prompt. The 38 reviewed M10.16d infrastructure exceptions remain the complete exception set. |
| Pinned formatting and linting (M10.16f) | Achieved | Ruff 0.16.8 is pinned as the sole formatter/linter over ``src``, ``tests``, ``tools``, and ``docs/conf.py``. All 572 scoped Python files are formatter-clean and the explicit correctness rule set passes with zero findings. Safe fixes plus review closed import/name errors, unsafe defaults, loop captures, accidental variable/argument shadowing, stale suppressions, and Python 3.11 annotation debt; two narrow E402 exceptions record required import/bootstrap ordering. Exact-version/configuration and generated primitive-export freshness tests make local and CI behavior reproducible. |
| Pinned static typing (M10.16g) | Next | Enforce pinned mypy over the recorded v5 source/test/tool/docs scope with an audited regression baseline only if required |
| Documentation and quality closure (M10.16h) | Queued | Integrate autodoc, doctests, CI, packaging, isolation, all closure gates, and the full host/container checkpoint |
| Canonical v5 Docker/CI environment | Queued | Before release, replace the amd64 Python-3.10 compatibility image with a multi-architecture Python-3.11+ image containing Chuffed, GLPK, Z3, MiniSat, Singular, msolve and LaTeX; do not block the current M10.9c/M10.9d migration workstream on image construction |
| Integration and release (M11) | Planned | Reconcile the latest `develop`, run the complete release matrix in the canonical environment, accept the public API, rename `claasp_next` to `claasp`, publish prereleases, and release 5.0 |
| Final bidirectional migration audit (M11a) | Planned | Machine matrix and generated human summary map every legacy artifact to v5 migrated/superseded/removed/out-of-scope ownership and every shipped v5 artifact back to legacy predecessors or an explicit new-v5 rationale; enforce 100% coverage before and after the package rename |
