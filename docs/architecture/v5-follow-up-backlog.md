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

Status: **In progress**

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

Implementation inventory notes:

- SAT currently has functional component encodings only; no SAT-local
  differential, linear, truncated, or boomerang component model exists to
  rename or move.
- The SMT Speck and generic word models assemble complete trails, so their
  implementation belongs in ``trails.py`` even though compatibility modules
  retain the previous import paths.
- CP ``WordwiseDifferenceCPModel`` and ``ImpossibleBoundaryCPModel`` describe
  fixed search boundaries rather than component encodings, so they remain in
  ``trails.py``. The local S-box and probabilistic-truncated modular-add models
  move under ``components/``.
- Generic S-box selector names remain compatibility exports; new code can use
  explicit XOR-differential and XOR-linear class names.

## Constraint-model provenance infrastructure PR

Status: **Complete**

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

Implementation discoveries:

- Existing clause-level ``provenance`` values describe generated constraints
  and solver diagnostics, so structured model provenance is carried separately
  as ``constraint_models`` rather than changing their meaning.
- One model declaration may apply to many graph component IDs. Lowering records
  that relationship explicitly so reports do not reconstruct it from class or
  component names.
- SAT-to-SMT, SAT-to-MILP, and SAT-to-MiniZinc translations preserve the
  originating component-model declarations.
- Direct truth-table, full-adder, wiring, and exhaustive finite-relation
  encodings are marked ``N/A``. The infrastructure PR initially left every
  modular-add correspondence ``TBD``; the audited statuses are recorded below.

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

Modular-addition audit discoveries:

- The exact SMT XOR-differential support and unary-weight relation matches
  Lipmaa--Moriai, Section 4, Algorithm 2 and Theorem 1. Legacy CLAASP also
  identifies its equivalent SAT and SMT helpers as the Lipmaa--Moriai
  algorithm.
- The exact SMT and MILP XOR-linear relations both encode Liu--Wang--Rijmen,
  Section 3.1, Proposition 1 and Equation (1). The backend-specific clauses
  and inequalities are two representations of the same mask recurrence,
  support conditions, and Hamming-weight objective. Legacy CLAASP cites that
  construction for both SAT and SMT and points its Boolean inequality helper
  directly to Equation (1).
- The probabilistic-truncated CP model remains `TBD`. Legacy CLAASP contains
  the counter-based predicate and scaled cost table, but no primary-source
  attribution or derivation was found; a later audit must establish the exact
  origin before attaching a citation.

S-box, linear-layer, and monomial audit discoveries:

- The CP S-box boomerang model computes the BCT entry exactly as defined by
  Cid--Huang--Peyrin--Sasaki--Song, Section 3.1, Definition 3.1, before exposing
  the nonzero rows through a generic MiniZinc table constraint. Legacy CLAASP
  includes the same BCT paper in its bibliography, although its surviving BCT
  implementation targets a different modular-add search.
- The local S-box monomial-transition table and the complete PRESENT monomial
  trail implement the monomial-trail relation of Hu--Sun--Wang--Wang, Section 3,
  Definition 1. The Boolean graph MILP uses the COPY, AND, XOR, and direct
  bit-permutation rules given in Section 4.2. Legacy CLAASP's Gurobi monomial
  model builds the same transition relation from products of output-coordinate
  ANFs but does not carry the paper citation.
- The current CP, SMT, and MILP XOR-differential and XOR-linear S-box models
  remain `N/A`: they enumerate their DDT or LAT relation directly and then use
  generic table, forbidden-assignment, or one-hot row selection. Legacy CLAASP
  cites Sun et al., Abdelkhalek et al., and Sasaki--Todo for convex-hull and
  inequality-reduction encodings, but those are not the encodings implemented
  by these CLAASP 5 models.
- Functional permutations, rotations, identities, and the PRESENT permutation
  layer remain `N/A` where they are direct wiring. The monomial-prediction
  lowering is separately verified because its COPY and bit-permutation
  propagation rules are part of the audited monomial-trail construction.
- CLAASP 5 currently exposes a typed differential-linear trail container but no
  backend differential-linear constraint model to which a model reference can
  be attached. Legacy CLAASP associates its continuous MiniZinc operations with
  Bellini--Gérault--Grados--Makarim--Peyrin, including an explicit pointer to
  Equation (5). Treat that implementation as a candidate for the legacy
  backend recovery program below rather than as evidence of an incomplete v5
  migration, and do not cite the representation-only trail type.

## Legacy constraint-backend recovery and benchmarking program

Status: **S-box and bitwise-AND MILP strategies plus SAT/CMS recovery slices implemented; next: remaining CP, MILP, boomerang, and monomial strategies**

The repository-wide inventory is recorded in
[`audits/legacy-constraint-backend-inventory.md`](audits/legacy-constraint-backend-inventory.md).
It covers every legacy backend search-model class, the component/backend
encoding surface, formulation generators, and relevant unmerged legacy
branches. The inventory identifies recovery candidates; it does not certify
correctness or performance.

The CLAASP 5 migration is complete. This program does not reopen the migration:
it deliberately preserves established constraint-generation methods that were
implemented in legacy CLAASP but are not represented by an equivalent v5
backend strategy. The portable, dependency-free v5 implementations remain
supported baselines. Recovered methods must be added as explicitly named
alternative strategies until like-for-like evidence justifies any change of
default.

The inventory classifies every legacy component/backend/model combination as:

- already represented equivalently in CLAASP 5;
- superseded by a documented CLAASP 5 strategy;
- absent from CLAASP 5 and a candidate for recovery; or
- obsolete, incorrect, or out of scope, with the supporting evidence.

The inventory covers:

- S-box differential and linear MILP convex-hull, impossible-point, reduced
  inequality, and large-S-box encodings, including the legacy strategies
  associated with Sun et al., Abdelkhalek et al., and Sasaki--Todo;
- alternative SAT, SMT, CP, and MILP S-box differential and linear encodings,
  rather than assuming that direct DDT/LAT enumeration is universally best;
- bitwise and wordwise deterministic, semi-deterministic, probabilistic
  truncated, and impossible models for S-boxes, modular operations, linear
  layers, and mix-column or branch-number constraints;
- differential-linear SAT and MiniZinc models, including the legacy continuous
  predicates associated with Bellini et al. Equation (5);
- boomerang and BCT-based models for S-box and ARX components;
- monomial-prediction and division-property models, including the legacy
  Gurobi implementations, alongside the portable MILP models; and
- solver-specific inequality generators, caches, and preprocessing paths that
  materially change the generated formulation.

The first recovery PR adds the legacy small-S-box full convex hull, greedy
reduction, and minimum-cardinality facet cover as explicit MILP alternatives
to the portable one-hot baseline. Differential and signed-linear propagation
are checked exhaustively over every PRESENT input/output pair. A committed
ten-run GLPK benchmark records construction time, formulation size, solve time,
memory, validity, and optimal status in the canonical Docker image. The
reproducible offline generator uses cddlib's exact-GMP executable and GLPK
directly from ordinary Python; generated inequalities have no runtime generator
dependency. The portable one-hot formulation remains the default.
Direct GLPK preserves the legacy minimum cardinalities but can select a
different co-optimal facet cover than Sage's GLPK wrapper. The pinned generator
output and exhaustive relation checks therefore define the reproducible v5
artifact without treating one tied optimum as a mathematical requirement.

The immediately following recovery PR adds explicit AES differential and
signed-linear Espresso strategies with independent exhaustive eight-bit parity
tests and comparable GLPK benchmarks. Espresso remains an offline generator;
the generated bundle has no runtime tool dependency. Recovery also repairs a
legacy parser assumption: ``espresso -epos -okiss`` emits no header in the
Docker image, so slicing away four presumed header lines silently yielded no
clauses. The recovered generator parses ordinary ``-epos`` records, rejects
empty output, and validates the complete accepted relation.

The first SAT recovery slice adds explicitly named differential and linear SAT
models for S-boxes and modular addition. It exhaustively checks PRESENT support,
small modular-add support and weights, and focused MiniSat solving. The modular
addition classes reuse the already verified backend-neutral Boolean clauses but
publish SAT provenance and SAT containers; they do not duplicate a competing
formula. Generic graph-wide trail assembly, the optional n-window heuristic,
and their like-for-like solver benchmarks remain in the immediately following
slices.

The native-XOR slice adds an immutable mixed CNF/parity container, explicit
functional component strategies, an independently checkable ordinary-CNF
expansion, and the CryptoMiniSat extended-DIMACS exporter. Functional Speck and
Simon formulas expand exactly to their ordinary CNF baselines. The canonical
image now pins CryptoMiniSat 5.11.15 on both supported architectures and tests
signed native-XOR clauses through the public command-line driver. The committed
benchmark compares ordinary CNF under Kissat with native-XOR output under
CryptoMiniSat, and separately compares ordinary and native-XOR input under
CryptoMiniSat. All runs use identical primitives, fixed inputs, repeat counts,
and validity checks. The benchmark reports unavailable CryptoMiniSat
peak-memory data as not reported and makes no formulation-only speed claim
from the cross-solver runs.

The SAT trail-assembly slice adds explicitly named whole-graph differential and
linear models that reuse the reviewed backend-neutral Boolean relations but
return SAT containers and SAT provenance. Exact toy-Speck counts are preserved
under MiniSat, Kissat, and CryptoMiniSat, and the committed ten-run benchmark
uses identical formulas and restrictions across the three solvers.

The optional n-window slice recovers uniform, per-round, and per-component
selection plus global overlapping full-window counts. Its direct parity and
conjunction CNF is generated in pure Python rather than restoring the legacy
SymPy/joblib/pickle generation path. Exhaustive four-bit fixtures match the
carry-difference definition, solver fixtures independently recheck complete
trails, and the committed exact-versus-window benchmark records the encoding
overhead without claiming a generally faster strategy.

The native-XOR trail slice adds explicitly named differential and linear
alternatives on the existing mixed container. It replaces only complete
canonical parity clause groups, proves exact recovery by expanding every
native record back to the ordinary formula, preserves exact trail counts, and
requires the CryptoMiniSat driver for direct enumeration. Its committed
ordinary-versus-native benchmark uses identical restrictions and leaves
ordinary CNF as the portable default. SAT truncated and impossible models are
the next recovery slice.

The deterministic-truncated native-XOR slice adds
``WordDeterministicTruncatedNativeXorSATModel``. Legacy
``CmsSatDeterministicTruncatedXorDifferentialModel`` did not contain a distinct
encoding: it printed a warning and reused ordinary SAT unchanged. The v5
alternative instead replaces only complete canonical parity groups and checks
exact recovery through ordinary-CNF expansion. On the fixed ToySpeck-2
fixture it uses 733 CNF clauses and 48 native records instead of 829 ordinary
clauses. The ten-run CryptoMiniSat comparison records lower median solve time
but higher construction time, so ordinary CNF remains the default.

The first truncated-SAT slice recovers the legacy two-bit paired-carry clauses
for deterministic-truncated modular addition as the explicitly named
``ModularAddDeterministicTruncatedSATModel``. It retains the legacy redundant
unknown representation, projects it to the typed ternary semantics when
decoding, and exhaustively checks every two-bit input/output pattern against
the independent paired-carry implementation. MiniSat, Kissat, and
CryptoMiniSat fixtures agree on a four-bit accepted and rejected boundary.
The following deterministic-truncated SAT slice adds
``WordDeterministicTruncatedSATModel`` for constants, identities, permutations,
rotations, XOR, and modular addition over Word graphs. Port trits are canonical
while the local recovered addition retains its legacy internal representation.
Decoded trails are independently propagated with typed semantics; MiniSat,
Kissat, and CryptoMiniSat agree on accepted and rejected ToySpeck-2 boundaries.
The committed ten-run benchmark uses an identical fixed propagation for all
three solvers and makes no general performance claim. Impossible and
semi-/probabilistic truncated SAT variants remain next.

The first impossible-SAT slice recovers the legacy six-clause per-bit
incompatibility indicator from ``utils.incompatibility`` at commit
``3aacc2758059de85682a9c6d0eda2cd75940e747`` as the explicitly named
``ImpossibleBoundarySATModel``. Exhaustive Boolean-encoding tests prove each
indicator is true exactly for two known opposite trits, including both legacy
encodings of an unknown value bit. Solver fixtures reproduce the typed
``ImpossiblePropagationBoundary`` contradiction positions under MiniSat,
Kissat, and CryptoMiniSat and reject a compatible boundary. Whole-graph
forward/backward assembly and a comparable benchmark remain separate next
steps.

The modular-subtraction prerequisite for backward ARX graphs is recovered as
``ModularSubtractDeterministicTruncatedSATModel``. Legacy CLAASP deliberately
used the same paired-carry clauses for ``MODADD`` and ``MODSUB``; CLAASP 5
retains that formula but gives subtraction separate provenance and validates
decoding against ``truncated_modular_subtract``. Exhaustive two-bit patterns
and all three SAT solvers establish parity, and
``WordDeterministicTruncatedSATModel`` now lowers inverse graphs containing
``ModularSubtract``.

The whole-graph impossible-SAT slice adds ``SpeckImpossibleSATModel``. It uses
the public round-slicing and inversion transformations to compose a forward
prefix and backward suffix rather than maintaining a second hand-written
round recurrence. Both directions reuse ``WordDeterministicTruncatedSATModel``
with zero key difference and meet through ``ImpossibleBoundarySATModel``.
Decoded witnesses independently recheck both transformed graphs and the typed
``ImpossiblePropagationBoundary``. MiniSat, Kissat, and CryptoMiniSat agree on
the Speck32/64-3 fixture; the committed ten-run benchmark uses the identical
formula for all three and makes no general solver-performance claim.

The first probabilistic-truncated SAT slice adds the local
``ProbabilisticTruncatedModularAddSATModel``. Instead of copying the legacy
generated clauses, it emits ordinary CNF directly from the reviewed typed
counter-based recurrence already shared with CP: explicit carry differences,
zero-run lengths, and the fixed-point costs 0, 4, 9, 19, 41, and 100. An
exhaustive width-two test checks every canonical input, output, carry, and cost
combination against ``check_probabilistic_truncated_modular_add``; all three
SAT solvers reproduce a nonzero-cost fixture.

The following whole-graph slice adds
``SpeckProbabilisticTruncatedSATModel``. It composes one reviewed local relation
per round, direct ternary rotations and XOR wiring, fixed external boundaries,
and an optional maximum scaled-weight constraint. The established two-round CP
fixture is satisfiable at its minimum bound of 100 under MiniSat, Kissat, and
CryptoMiniSat, and every decoded round is independently rechecked. The
committed ten-run benchmark also records the portable CNF cost—554,782
variables and 1,327,845 clauses for this bounded fixture—so compact legacy
semi-deterministic windows remain a performance-recovery target rather than
being treated as equivalent without measurement.

The local semi-deterministic slice recovers look-ahead windows 0 through 3 as
``ModularAddSemiDeterministicTruncatedSATModel``. A repository tool reads only
the four static generators from the legacy GPL source at commit
``3aacc2758059de85682a9c6d0eda2cd75940e747``, rejects a source whose SHA-256
has changed, validates every emitted literal, and writes dependency-free
templates. The model retains the legacy redundant value bit for unknown trits
and the three-bit probability codes, while canonicalizing the unconstrained
least-significant weight code to zero. All three SAT solvers reproduce the
shared 16-bit weight-100 fixture. On that fixture the window strategy uses 144
variables and 1,037 clauses versus 495 and 107,350 for the counter-based
baseline; the committed ten-run benchmark records construction, solver, and
memory data without generalizing from one transition.

The whole-graph comparison adds ``SpeckSemiDeterministicTruncatedSATModel`` and
uses the same two-round graph, fixed boundaries, weight bound, solver settings,
and host as ``SpeckProbabilisticTruncatedSATModel``. The recovered formulation
uses 554,272 variables, 1,116,019 clauses, and 2,790,799 literals versus
554,782, 1,327,845, and 4,877,959 for the portable counter formulation. Both
decode and independently validate a weight-100 witness under MiniSat, Kissat,
and CryptoMiniSat. The committed ten-run benchmark records construction,
solve, and peak-memory measurements; default selection remains deferred until
broader primitive and round-count coverage exists.

The next MILP component slice recovers the compact two-input bitwise-AND
differential and linear inequalities as
``BitwiseAndXorDifferentialMILPModel`` and
``BitwiseAndXorLinearMILPModel``. The audited legacy generator is
``generate_inequalities_for_and_operation_2_input_bits.py`` at ``3aacc275``
(SHA-256 ``29aedacefb55ac192ed22e5123c0ee40829593e991ac1e4ca6e254615df4d85e``).
The new ``BitwiseAndOneHotMILPModel`` supplies an explicit portable baseline.
Exhaustive one-bit GLPK tests match independent DDT/LAT semantics, and the
committed 32-bit benchmark compares construction and solve time without
changing a default. Literature provenance remains TBD until the exact legacy
inequalities are matched to a primary-source construction.

The deterministic-truncated SMT slice adds
``ModularAddDeterministicTruncatedSMTModel`` and
``WordDeterministicTruncatedSMTModel``. The immutable SMT formula preserves the
same paired-carry Boolean relation already checked exhaustively in SAT, while
publishing SMT provenance and executing through Z3. Accepted and rejected
local additions and complete ToySpeck-2 boundaries match the typed semantics.
The committed ten-run benchmark uses the identical 200-variable, 829-assertion
fixture as the SAT benchmark and makes no cross-solver ranking claim.

The matching deterministic-truncated CP slice adds
``ModularAddDeterministicTruncatedCPModel`` and
``WordDeterministicTruncatedCPModel``. Exact Boolean-to-MiniZinc lowering keeps
the recovered paired-carry relation and graph wiring unchanged. Chuffed accepts
and rejects the same local and complete ToySpeck-2 boundaries as SAT and SMT;
decoded trails are checked again through typed semantics. The committed ten-run
benchmark records the identical 200-variable, 829-constraint fixture without
replacing the specialized Speck CP model or ranking unlike solvers.

The portable generic CP trail slice adds ``WordDifferentialCPModel`` and
``WordLinearCPModel``. Both translate the complete reviewed Boolean Word-graph
relation to MiniZinc with stable logical names, then reuse independent typed
decoding. Chuffed solves fixed/bounded-weight ToySpeck fixtures for both
semantics. The committed ten-run benchmark characterizes this compatibility
baseline; the distinct legacy ARX-optimized carry formulation remains a
separate candidate and no default changes.

The matching portable generic MILP slice adds ``WordDifferentialMILPModel``
and ``WordLinearMILPModel``. Each exact CNF clause becomes one binary linear
inequality, while semantic weight variables define the minimization objective.
GLPK solves and independently validates fixed/bounded-weight ToySpeck fixtures;
the committed ten-run benchmark characterizes this portable baseline. It does
not replace recovered component-specific convex hulls or the still-optional
Gurobi capability.

The optional solver slice adds ``GurobiSolver`` for every portable ``MILPModel``.
It imports ``gurobipy`` only when queried or used, never changes the GLPK
default, maps all portable domains, bounds, senses, and objectives, and
independently rechecks returned assignments and objective values. Translation
is covered with an API-compatible test double because the canonical image has
no Gurobi installation or license. Legacy monomial-specific searches remain a
separate recovery target above this solver boundary.

The portable CP differential-linear slice adds
``WordDeterministicDifferentialLinearCPModel``. Exact MiniZinc translation
preserves the reviewed differential, deterministic-truncated, connector, and
linear clauses; decoded Chuffed witnesses are independently rechecked by the
typed composition. The continuous legacy search remains explicitly heuristic
and outside this proof-producing model.

The matching semi-deterministic CP slice adds
``WordSemiDeterministicDifferentialLinearCPModel``. It preserves the recovered
look-ahead-window middle and its deliberately separate estimated weight while
translating the complete composition exactly to MiniZinc. Chuffed solves and
independently decodes the reviewed Speck32/64-3 fixture; the middle relation's
literature correspondence remains unaudited and is not strengthened here.

The standalone CP slice adds ``SpeckSemiDeterministicTruncatedCPModel`` for
complete Speck32/64 trails. It exposes fixed typed boundaries and decodes every
look-ahead-window transition independently after Chuffed solves the exact
MiniZinc translation. This recovers the reviewed legacy search strategy without
claiming provenance that the earlier SAT recovery deliberately left unaudited.

The first deterministic-truncated MILP component slice recovers the legacy
indicator-based AND abstraction as
``BitwiseAndDeterministicTruncatedMILPModel`` and adds
``BitwiseAndDeterministicTruncatedOneHotMILPModel`` as an explicit portable
baseline. All nine pairs of one-bit ternary inputs pass GLPK and independent
typed decoding. The committed 32-bit comparison records formulation size,
construction, and solve time; remaining truncated MILP components and generic
graph assembly stay separate recovery slices.

The portable graph-level MILP slice adds
``WordDeterministicTruncatedMILPModel``. It translates the same exhaustively
checked ternary clauses used by the SAT model into exact linear inequalities,
then decodes and independently rechecks the complete Word graph. GLPK solves
the reviewed fixed-boundary ToySpeck fixture without Sage or a proprietary
solver; specialized activity and impossible-search strategies remain separate.

The deterministic-middle MILP composition adds
``WordDeterministicDifferentialLinearMILPModel``. The complete reviewed Boolean
composition becomes exact clause inequalities, while its minimization objective
includes only semantic differential weights with coefficient one and linear
correlation weights with coefficient two. Counter and complement auxiliaries
remain feasibility variables. GLPK decodes and independently validates all
three sections on Speck32/64-3.

The matching semi-deterministic MILP composition adds
``WordSemiDeterministicDifferentialLinearMILPModel``. It translates the
recovered look-ahead-window middle exactly but deliberately excludes that
unaudited estimate from the historical outer objective. The decoded result
continues to expose ``middle_weight`` separately, and GLPK independently
validates the differential, middle, and linear sections.

The standalone MILP slice adds ``SpeckSemiDeterministicTruncatedMILPModel``.
It assigns recovered fixed-point costs only to the six explicit per-bit choice
selectors—never to the local three-bit weight code—and minimizes their sum.
GLPK solves the fixed two-round Speck boundary, after which typed decoding
rechecks every look-ahead-window transition and the complete round wiring.

The first differential-linear SAT slice recovers the local upper and lower
boundary clauses as ``DifferentialToTruncatedSATModel`` and
``TruncatedToLinearSATModel``. Exhaustive Boolean tests establish the complete
one-bit truth tables, while MiniSat, Kissat, and CryptoMiniSat accept and reject
the same fixed boundaries. The canonical 32-bit benchmark compares the direct
relations with exhaustive forbidden-assignment CNF under identical solvers and
inputs. The direct upper relation halves the clause count and the direct lower
relation removes one third of the clauses. Both models retain ``TBD``
literature provenance. The audited ``origin/develop`` source has SHA-256
``d980c748168ab6387d07cec786a73831472c7c6185b2c04c4e86783fa478958e``;
the corrective branch at ``af85330e`` has SHA-256
``ed77f50a89bfc502598f847fddd1ee8ece92e63c3ce059def2c401e8b0fdca8b``.
The later develop model incorporates the relevant corrections plus additional
fixes, so the branch is archaeological evidence rather than the sole oracle.
Whole-graph differential/truncated/linear composition remains a separate
recovery slice.

The following whole-graph slice adds
``WordDeterministicDifferentialLinearSATModel``. It uses public round slicing
to compose independently decodable exact-differential,
deterministic-truncated, and XOR-linear submodels, joining them with the two
recovered boundary relations. The output witness retains all three typed
characteristics, rechecks both boundaries without consulting the clauses, and
reports the legacy deterministic-middle objective without assigning a
probability to the middle. MiniSat, Kissat, and CryptoMiniSat solve and decode
the same Speck32/64-3 fixture. The committed ten-run benchmark uses one
identical 2,543-variable, 7,151-clause formula under all three solvers and
makes no longer-round performance claim. Paired-input variants and the
semi-deterministic middle remain separate recovery work.

The shared-difference paired-input slice adds
``SharedDifferencePairedWordDifferentialSATModel`` and a typed paired result.
The legacy relation is two differential characteristics with one shared
external difference plus mutual exclusion of corresponding modular-add output
bits; it is not concrete four-copy evaluation. Independent decoding and fixed
summed weight pass under all three SAT solvers. The committed ToySpeck-2
benchmark compares the shared-input formula with and without the exclusion
layer. Literature provenance remains ``TBD``.

The paired-input differential-linear slice adds
``SharedDifferencePairedWordDifferentialLinearSATModel``. It composes the
recovered paired differential prefix with one XOR-linear suffix, preserving the
legacy boundary rule that an active suffix mask requires both prefix output
differences to be zero. The fixed objective is both differential weights plus
twice the linear weight. MiniSat and Kissat solve and independently decode the
same fixed-weight Speck32/64-3 fixture. CryptoMiniSat 5.11.15 exceeded the
30-second local timeout on this sequential-counter formula, so the committed
ten-run benchmark reports only the two completing solvers rather than hiding
or generalizing from that limitation. The high-order interpretation and
precise source of the boundary remain ``TBD``.

The semi-deterministic-middle slice adds
``WordSemiDeterministicDifferentialLinearSATModel``. It replaces the exact
three-valued middle with the recovered look-ahead-window modular-add relation
while retaining independently decoded exact-differential and XOR-linear
sections. The upper and lower connectors are rechecked from typed values.
Because the legacy search did not consistently combine the middle fixed-point
cost with its differential-plus-twice-linear objective, the v5 result reports
``legacy_objective_weight`` and ``middle_weight`` separately. MiniSat and
Kissat solve the same unbounded-middle Speck32/64-3 fixture; the ten-run
benchmark records both without selecting a new default. Literature provenance
for the semi-deterministic relation remains ``TBD``.

Recover each selected strategy in a small component- or backend-scoped PR.
Before copying code, generated inequalities, or data, verify its license and
provenance. Keep optional solver dependencies isolated, give each formulation
an explicit public name, and add compatibility imports only where an existing
public import requires them. Restore or reconstruct focused fixtures and test
behavioral parity independently of performance.

The recovery ledger was reconciled after the cross-backend slices: native-XOR
functional SAT, probabilistic and semi-deterministic truncated SAT, and both
differential-linear SAT compositions are implemented and benchmarked. Their
older table rows no longer remain false-positive TODOs; broader component
coverage and unaudited provenance stay explicitly open.

The SMT differential/linear audit confirms that the generic Word models are
the source Boolean formulations used by their SAT counterparts: variables,
assertions/clauses, and provenance labels match exactly. Z3 solves and the
typed independent checkers validate fixed-weight differential and bounded-
weight linear ToySpeck-2 trails. This closes parity for the reviewed Word
subset without duplicating it; legacy component kinds outside that subset
remain explicit recovery work.

The monomial parity follow-up adds ``CubeSuperpolyQuery`` as an exact bounded
oracle. It evaluates the selected cube and symbolic-key subspace, XORs the cube
values, and applies the Boolean Möbius transform to report the superpoly ANF
and individual key-monomial coefficients. This is deliberately separate from
MILP reachability: feasibility cannot detect even cancellation. The explicit
dimension guard makes the exponential cost visible; the optional Gurobi
driver remains available for a future scalable solution-pool strategy and is
not selected by default.

The boomerang assembly follow-up adds
``ModularAddBoomerangTrailCPModel``. It namespaces complete top and bottom
``WordDifferentialCPModel`` formulas, links their exposed switch word to the
exact carry/borrow automaton, and minimizes the recovered upper-plus-lower
characteristic cost. Decoding independently checks both trails and recomputes
the switch quartet count; the result reports the search weight separately from
the exact decoded weight including that switch. Automatic legacy graph
partitioning and S-box-switch graph assembly remain distinct work.

The wordwise-impossible MILP boundary slice adds
``WordwiseImpossibleBoundaryMILPModel``. It restores the legacy four-state
middle rule exactly: only ``(0,1)``, ``(0,2)``, ``(1,0)``, and ``(2,0)`` can
be selected as contradictions, state 3 never proves impossibility, and the
default formulation selects exactly one contradictory position. GLPK decodes
and rechecks the preserved reduced-AES abstract fixture. This does not relabel
that fixture as a concrete differential proof; whole-graph four-state
propagation remains the next layer.

The functional component coverage slice extends the shared Boolean lowering
with direct OR and NOT truth-table clauses plus zero-filling fixed shifts.
Because SMT, CP, and MILP derive from the same named CNF relation, one composed
OR/NOT/left-shift/right-shift graph is solved and validated under MiniSat, Z3,
Chuffed, and GLPK. Multi-input OR witnesses retain their auxiliary values.
Modular subtraction/multiplication and variable shifts/rotations remained
explicit rather than being silently skipped at that checkpoint.

The modular-subtraction follow-up adds explicit
``ModularSubtractFunctionalSATModel`` and
``ModularSubtractNativeXorSATModel`` strategies. A sequential ripple-borrow
circuit supports every declared operand, not only the binary case; all 512
three-bit, three-input assignments are checked against scalar execution.
Native-XOR expansion reproduces ordinary CNF exactly, and the cross-backend
functional benchmark now includes the subtraction stage.

The variable-wiring follow-up adds
``VariableWiringFunctionalSATModel`` for exact data-dependent rotations and
shifts. Rotations use a power-of-two barrel network. Shifts additionally use
an exact remainder-state network because CLAASP reduces the supplied amount
modulo the word width, including for non-power-of-two widths. Exhaustive
five-bit tests cover every value and every three-bit amount in both
directions; the shared functional benchmark exercises the resulting CNF under
MiniSat, Z3, Chuffed, and GLPK. Modular multiplication and specialized
components remain.

The first active-S-box recovery adds ``PresentActiveSBoxesMILPModel``. It keeps
the exact two-round PRESENT DDT feasible region byte-for-byte identical to the
weighted trail model and changes only the objective to count selectors with a
nonzero input difference. GLPK proves the optimum of two active S-boxes, and
the decoded trail passes the independent shared-semantics checker.

The MILP second stage adds ``PresentFixedActiveSBoxesMILPModel``. It fixes the
first-stage optimum through one exact selector-sum equality and restores the
DDT weight objective without changing any transition or wiring constraint.
GLPK proves weight four at two active S-boxes, and independent decoding checks
both the requested activity and the exact characteristic weight.

The wordwise activity recovery adds
``WordwiseBranchNumberActiveSBoxesMILPModel``. It uses one binary activity
variable per typed scalar unit, exact activity propagation through bijective
S-boxes and structural wiring, and branch-number relaxations for XOR and
invertible linear maps. Typed decoding validates the complete MILP assignment.
GLPK reproduces the reviewed four-round ToyAES sequence 1, 5, 9, 25. The API
deliberately calls these results lower bounds unless the retained relations are
known to be exact; it does not promote the relaxation to the default exact
differential model.

The first MILP impossible-differential slice adds ``SpeckImpossibleMILPModel``.
It translates the reviewed transformed forward/backward deterministic-truncated
graphs and exact middle incompatibility indicators clause-for-clause. GLPK
returns a split-round contradiction whose two directional trails and
contradictory positions are independently decoded and checked.

The generic impossible-differential follow-up factors that construction into
``WordImpossibleSATModel``, ``WordImpossibleCPModel``, and
``WordImpossibleMILPModel``. Callers now select the active input and any other
inputs whose differences are fixed to zero. The original Speck SAT and MILP
classes remain compatibility specializations with unchanged defaults. This
closes generic forward/backward assembly for reversible graphs built from the
reviewed deterministic-truncated Word component subset; unsupported component
encodings and legacy automatic-boundary heuristics remain separate work.

The corresponding CP slice adds ``PresentActiveSBoxesCPModel`` over the same
two-round exact DDT relation. Native MiniZinc Boolean activity indicators are
equivalent to nonzero four-bit S-box inputs; Chuffed proves the same optimum of
two and the inherited typed decoder independently checks the resulting trail.

The continuous CP recovery adds ``SpeckContinuousHeuristicCPModel`` for fixed
numerical inputs. It restores the legacy nonlinear XOR, majority/carry, and
modular-add propagation in MiniZinc and checks the resulting float vectors
against the independent Python implementation with an explicit accumulated
tolerance. The public result remains ``ContinuousHeuristicResult`` with
``claim_kind='heuristic'``; it cannot report satisfiability or optimality as a
cryptanalytic proof. Legacy mask optimization and broader component dispatch
remain separate work.

The CP second stage adds ``PresentFixedActiveSBoxesCPModel``. It fixes the
first-stage Boolean activity sum, restores minimization of the exact table
weights, and keeps the same native DDT constraints. Chuffed reaches weight four
at activity two, matching the independently checked MILP result.

The ARX-optimized differential audit establishes that the legacy model's
distinct behavior is its optional per-round n-window pruning; with the switch
disabled, its modular-add predicate is the exact relation already used by
``SpeckDifferentialCPModel``. ``SpeckARXWindowDifferentialCPModel`` restores the
heuristic explicitly without changing the default. Chuffed solves and typed
decoding rechecks a three-round Speck32/64 fixture with window size three.

The first ARX-boomerang recovery adds ``ModularAddBoomerangCPModel``. Its
six-column per-bit table is generated from the exact sixteen-state
carry/borrow automaton rather than copied as an opaque legacy table. Exhaustive
three-bit testing checks all 4,096 switch tuples against direct quartet
counting; decoded 16-bit witnesses are independently counted by the scalable
semantic automaton. This is the local switch needed by the legacy top/bottom
search, not yet the complete boomerang trail assembler or weight objective.

The first high-level monomial-query recovery adds ``MonomialDegreeMILPModel``
and ``CubeMonomialFeasibilityMILPModel`` over the verified portable Boolean
monomial graph. GLPK recovers a degree-two witness for a one-round Simon output
bit, accepts its selected two-bit cube, and rejects an excluded cube. These
queries do not pretend to recover parity: superpoly coefficients and tightness
by solution-pool parity still need an explicit complete-enumeration strategy.

The conditional deterministic-truncated ARX audit found no second formulation
to port. The legacy
``MznDeterministicTruncatedXorDifferentialModelARXOptimized`` at
``origin/develop`` (SHA-256
``c8e612618b636fb5cfc5a8342a7caba97fe266446b2a12df74b1994419d6bc1d``)
dispatches only ROTATE and SHIFT and reports modular addition and XOR as
unimplemented. The complete v5 Word/Speck models supersede that incomplete
wrapper; adding an alias would falsely imply preserved behavior.

Benchmark recovered and portable strategies under the same primitive, round
count, boundary conditions, trail objective, solver and version, solver
settings, hardware, and timeout. Record at least model-construction time,
variables, clauses or constraints, solve time, peak memory, result validity,
and optimality or timeout status. Do not describe either implementation as
better based only on formulation size or results from incomparable runs.

The inventory and every recovery PR must update a shared comparison matrix
with the strategy name, supported semantics, source provenance, dependencies,
parity-test status, and benchmark coverage. Do not remove the portable model or
switch a default in a recovery PR. If benchmarks establish a consistent winner
or a workload-dependent tradeoff, make the default-selection policy a separate
reviewed PR; retain both strategies when each has a practical advantage.

## Repository migration-audit test PR

Status: **Complete**

The constraint-layout follow-up exposed that the committed bidirectional
migration and license-provenance inventories no longer match the shipped tree,
which already contains the new backend component packages, Kissat driver, and
trail-reporting support. The review-release-plan path-order check and the
terminology guard also fail on the current stacked base. These repository-wide
authority updates remain deliberately deferred to that dedicated PR rather
than being folded into constraint-model provenance work.

The unit-test layout check also expects
``tests/unit/representations/constraints/test_provenance.py`` to mirror a
``constraints/provenance.py`` source module, although the provenance contract
currently lives in the package ``__init__.py``. Resolve that ownership mismatch
in the same repository-audit cleanup rather than moving public modules during a
literature audit.

The full module-doctest run also exposes a stale catalogue example: its
expected supported-tool list predates the Kissat driver now shipped by the
repository. Update that generated or documented expectation in the
repository-audit cleanup rather than mixing it into a constraint-model audit.

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

Resolution: retain the bidirectional audit as a repository/release contract.
Its generated matrix remains the authority for legacy and shipped-artifact
coverage, while the review-plan closure now validates the live matrix summary
rather than duplicating fixed counts that become stale after every recovery
module. The focused committed-audit test completes in under one second on the
development host, so it remains in the ordinary repository suite. Unit tests
whose scope spans multiple implementation modules now use the established
``test_<owner>__<topic>.py`` naming convention, making package ownership
explicit without inventing empty source modules. The four accidental generic
``cipher-state`` phrases in user documentation now use ``data-state``.
