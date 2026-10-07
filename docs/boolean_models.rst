Boolean CNF models
==================

Bit-oriented primitive graphs can be lowered to a solver-independent conjunctive
normal form without installing SageMath or a SAT solver. The initial lowering
supports constants, identity, permutation, structural bindings, bitwise addition
(XOR), and bit-vector S-boxes. Word graphs additionally support XOR, AND,
rotation and exact modular addition. Unsupported domains and components fail
explicitly instead of silently changing their semantics.

The following reduced PRESENT model is large enough to exercise both its
linear and nonlinear layers:

.. doctest::

   >>> from claasp import bits_from_int
   >>> from claasp.representations.constraints.sat import BooleanCNFModel
   >>> from claasp.primitives import Present80
   >>> from claasp.representations.execution import ScalarEvaluator
   >>> primitive = Present80(number_of_rounds=1)
   >>> model = BooleanCNFModel(primitive)
   >>> formula = model.cnf_formula()
   >>> formula.variable_count > 400, formula.clause_count > 1000
   (True, True)
   >>> evaluation = ScalarEvaluator().evaluate(primitive, {
   ...     "plaintext": bits_from_int(0, 64),
   ...     "key": bits_from_int(0, 80),
   ... })
   >>> formula.is_satisfied(model.witness(evaluation))
   True

``CNFFormula`` uses signed DIMACS literals internally while retaining ordered
variable names and one component provenance label per clause. Its
``is_satisfied`` method is a dependency-free consistency check, not a SAT
search algorithm.

DIMACS export
-------------

The exporter returns text so callers retain control over files and solver
processes. Variable-map comments make solver assignments traceable to graph
wires.

.. doctest::

   >>> from claasp.representations.constraints.sat.exporters import DimacsExporter
   >>> dimacs = DimacsExporter().export(formula)
   >>> [line for line in dimacs.splitlines() if line.startswith("p ")]
   ['p cnf 494 1913']
   >>> dimacs.splitlines()[0]
   'c 1 plaintext_0'

Any command-line or Python SAT engine that accepts DIMACS can consume this
text. Solver adapters live outside the typed primitive graph and can be added
incrementally; the Boolean IR itself has no third-party dependency.

Solving with MiniSat
--------------------

The optional command-line adapter invokes a locally installed ``minisat``
executable. No Python solver package is required. Named assumptions add unit
clauses for one solve without modifying the original formula; they are useful
for fixing plaintext, key, or ciphertext bits.

.. doctest::

   >>> from claasp.drivers.solvers import MinisatSolver
   >>> solver = MinisatSolver(timeout_seconds=30)
   >>> solver.executable
   'minisat'

With MiniSat installed, a caller can run ``result = solver.solve(formula,
{"plaintext_0": 0})``. A satisfiable result contains an assignment keyed by
the original graph-derived variable names. ``result.status`` distinguishes
``SATISFIABLE`` from ``UNSATISFIABLE``, and ``runtime_seconds``, ``stdout``,
and ``stderr`` retain execution diagnostics. Missing executables, timeouts,
malformed output, and nonstandard exit codes are reported explicitly.

Weighted SAT trails
-------------------

``WordDifferentialSATModel`` and ``WordLinearSATModel`` compose local
component relations, graph wiring, boundary conditions, and weight bounds into
complete ordinary-CNF searches. They reuse the same backend-neutral Boolean
relations as the SMT forms, while publishing SAT constraint provenance and a
``CNFFormula`` accepted by MiniSat, Kissat, or CryptoMiniSat.

For example, the two-round toy Speck graph has six nonzero single-key
characteristics of exact weight one:

.. doctest::

   >>> from claasp.primitives import ToySpeck
   >>> from claasp.representations.constraints.sat import WordDifferentialSATModel
   >>> trail_model = WordDifferentialSATModel(
   ...     ToySpeck(2), fixed_weight=1, nonzero_input="plaintext",
   ...     fixed_input_differences={"key": 0},
   ... )
   >>> trail_formula = trail_model.cnf_formula()
   >>> (trail_formula.variable_count, trail_formula.clause_count)
   (187, 501)
   >>> sorted({item.model.backend.value for item in trail_formula.constraint_models})
   ['sat']

With a canonical solver installed, use
``trail_model.enumerate_trails(solver, limit=10).require_complete()``. Each
solver assignment is projected to a typed characteristic and independently
rechecked against the component semantics and graph wiring. ``require_complete``
accepts a count only after the solver reaches terminal UNSAT; hitting the caller
limit is explicitly incomplete.

The ten-run canonical ARM64 benchmark in
``architecture/audits/data/sat_trail_assembly_benchmark.json`` uses identical
formulas and restrictions for every solver. Times below are medians in
milliseconds. MiniSat and CryptoMiniSat do not report peak memory through their
current drivers; no claim of a generally faster solver follows from these toy
workloads.

.. list-table::
   :header-rows: 1

   * - Semantics
     - Solver
     - Variables
     - Clauses
     - Build ms
     - Solve ms
     - Peak MiB
   * - Differential
     - MiniSat 2.2.1
     - 187
     - 501
     - 1.114
     - 0.883
     - not reported
   * - Differential
     - Kissat 4.0.4
     - 187
     - 501
     - 1.142
     - 1.567
     - 27.4
   * - Differential
     - CryptoMiniSat 5.11.15
     - 187
     - 501
     - 1.092
     - 0.897
     - not reported
   * - Linear
     - MiniSat 2.2.1
     - 296
     - 706
     - 2.541
     - 0.855
     - not reported
   * - Linear
     - Kissat 4.0.4
     - 296
     - 706
     - 2.394
     - 0.389
     - 27.4
   * - Linear
     - CryptoMiniSat 5.11.15
     - 296
     - 706
     - 2.562
     - 0.879
     - not reported

Deterministic-truncated SAT trails
----------------------------------

``WordDeterministicTruncatedSATModel`` composes deterministic three-valued
propagation across the ARX Word subset: constants, identities, permutations,
rotations, XOR, and modular addition. ``0`` and ``1`` are known XOR
differences; ``?`` means that both differences remain possible. Modular
addition uses the recovered paired-carry clauses, and decoded solver witnesses
are independently propagated again with the typed truncated semantics.

The following complete ToySpeck-2 search fixes the plaintext and key patterns.
Its output is not supplied to the model, so ``???0????`` is computed by the
assembled component constraints:

.. doctest::

   >>> from claasp.representations.constraints.sat import (
   ...     WordDeterministicTruncatedSATModel,
   ... )
   >>> truncated_model = WordDeterministicTruncatedSATModel(
   ...     ToySpeck(2),
   ...     fixed_input_patterns={"plaintext": "00000001", "key": "0" * 16},
   ... )
   >>> truncated_formula = truncated_model.cnf_formula()
   >>> (truncated_formula.variable_count, truncated_formula.clause_count)
   (200, 813)

Call ``enumerate_trails(solver, limit=...)`` to obtain typed
``WordDeterministicTruncatedCharacteristic`` values. Enumeration blocks the
canonical port trits, rather than internal carry witnesses, so one semantic
trail is not counted more than once. ``fixed_input_patterns``,
``output_pattern``, and ``nonzero_input`` provide explicit search boundaries.
Components outside the documented ARX/structural subset are rejected instead
of receiving an approximate encoding.

The reproducible ten-run ARM64 benchmark in
``architecture/audits/data/sat_truncated_trail_benchmark.json`` uses the same
fixed ToySpeck-2 propagation for all three solvers. It establishes solver
parity for this workload, not a general performance ranking.

.. list-table:: Median time in milliseconds
   :header-rows: 1

   * - Solver
     - Variables
     - Clauses
     - Build ms
     - Solve ms
     - Peak MiB
   * - MiniSat 2.2.1
     - 200
     - 829
     - 1.246
     - 0.935
     - not reported
   * - Kissat 4.0.4
     - 200
     - 829
     - 1.261
     - 0.444
     - 27.9
   * - CryptoMiniSat 5.11.15
     - 200
     - 829
     - 1.306
     - 0.944
     - not reported

Impossible-differential SAT trails
-----------------------------------

``SpeckImpossibleSATModel`` turns a round split into two ordinary-CNF graph
searches. The prefix propagates a nonzero plaintext difference forward. The
suffix is inverted and propagates a nonzero ciphertext difference backward.
Both use zero key difference. At the shared state, the search requires at
least one bit that the forward trail fixes to ``0`` and the backward trail
fixes to ``1``, or vice versa. Such a contradiction proves that the two
partial propagations cannot belong to one complete differential trail.

This example builds a three-round Speck32/64 search split after round one:

.. doctest::

   >>> from claasp.primitives import Speck
   >>> from claasp.representations.constraints.sat import SpeckImpossibleSATModel
   >>> impossible_model = SpeckImpossibleSATModel(
   ...     Speck(number_of_rounds=3), middle_round=1,
   ... )
   >>> impossible_formula = impossible_model.cnf_formula()
   >>> (impossible_formula.variable_count, impossible_formula.clause_count)
   (1568, 5674)
   >>> "truncated_incompatibility_exists" in impossible_formula.provenance
   True

Solve ``impossible_formula`` with MiniSat, Kissat, or CryptoMiniSat, then call
``impossible_model.decode_trail(result.assignment)``. The returned
``SpeckImpossibleSATTrail`` contains both independently rechecked directional
characteristics and an ``ImpossiblePropagationBoundary``. Its
``contradictory_positions`` identifies the exact middle-state bits that prove
incompatibility. Optional ``input_pattern`` and ``output_pattern`` arguments
fix either external difference when reproducing a particular search.

The ten-run ARM64 benchmark in
``architecture/audits/data/sat_impossible_trail_benchmark.json`` uses the same
Speck32/64-3 formula for all three solvers. Median build times are 10.96,
10.71, and 10.70 milliseconds for MiniSat, Kissat, and CryptoMiniSat;
corresponding solve times are 2.85, 1.14, and 2.10 milliseconds. These results
establish solver parity for this small workload and do not establish a general
performance ranking.

Probabilistic-truncated SAT trails
----------------------------------

``SpeckProbabilisticTruncatedSATModel`` composes the counter-based partial
addition relation over complete Speck32/64 rounds. Unlike deterministic
truncation, a partial modular addition can choose a compatible carry
difference and records its probability cost. Costs use the historical CLAASP
fixed-point scale: 100 units are one bit of probability weight.

The established two-round fixture has minimum scaled weight 100. Supplying
that value as an upper bound turns the SAT query into a reproducible decision
problem:

.. doctest::

   >>> from claasp.representations.constraints.sat import (
   ...     SpeckProbabilisticTruncatedSATModel,
   ... )
   >>> probabilistic_model = SpeckProbabilisticTruncatedSATModel(
   ...     Speck(number_of_rounds=2),
   ...     "00000000011111001110000000000000",
   ...     "???????????????1???????????????1",
   ...     maximum_scaled_weight=100,
   ... )
   >>> probabilistic_formula = probabilistic_model.cnf_formula()
   >>> (probabilistic_formula.variable_count, probabilistic_formula.clause_count)
   (554782, 1327845)

After solving, ``probabilistic_model.decode_trail(result.assignment)`` returns
a ``ProbabilisticTruncatedTrail``. Its ``scaled_weight`` and ``weight`` are 100
and 1.0 for this boundary. Decoding checks every modular-add transition against
the independent counter-based semantics and checks the round rotations and XOR
wiring again.

The ten-run ARM64 benchmark in
``architecture/audits/data/sat_probabilistic_trail_benchmark.json`` records the
same bounded formula under all three canonical SAT solvers. The formulation is
large—554,782 variables and 1,327,845 clauses—and Kissat reported a median
692.6 MiB peak. The data establishes correctness and a concrete optimization
target; it does not make a general solver-performance claim.

The recovered alternative, ``SpeckSemiDeterministicTruncatedSATModel``, uses
the historical look-ahead-window clauses while preserving the same graph,
boundary, and scaled-weight interface:

.. doctest::

   >>> from claasp.representations.constraints.sat import (
   ...     SpeckSemiDeterministicTruncatedSATModel,
   ... )
   >>> recovered_model = SpeckSemiDeterministicTruncatedSATModel(
   ...     Speck(number_of_rounds=2),
   ...     "00000000011111001110000000000000",
   ...     "???????????????1???????????????1",
   ...     maximum_scaled_weight=100,
   ... )
   >>> recovered_formula = recovered_model.cnf_formula()
   >>> (recovered_formula.variable_count, recovered_formula.clause_count)
   (554272, 1116019)

Solving and passing the assignment to ``recovered_model.decode_trail`` returns
a ``SpeckSemiDeterministicTruncatedTrail``. Decoding projects the legacy
two-bit unknown representation to canonical trits, checks rotations and XOR
wiring independently, and reports the sum of the recovered per-bit costs.

The like-for-like ten-run ARM64 benchmark in
``architecture/audits/data/sat_semi_deterministic_trail_benchmark.json`` found
median solve times of 0.258, 0.308, and 0.251 seconds for the recovered model
under MiniSat, Kissat, and CryptoMiniSat. The portable model took 3.139, 0.564,
and 0.640 seconds respectively. These results justify retaining the recovered
strategy, but cover only one workload and do not establish a new default.

Optional n-window strategy
--------------------------

``NWindowSATStrategy`` recovers the legacy modular-add carry-difference
heuristic without adding SymPy, joblib, Sage, or generated pickle files. It is
strictly opt in: omitting ``n_window`` leaves the exact differential formula
unchanged. A window of size ``n`` rejects ``n + 1`` consecutive ones in
``left_difference XOR right_difference XOR output_difference`` for each
modular addition.

For example, applying a two-bit window to every addition adds a separately
identified constraint layer:

.. doctest::

   >>> from claasp.representations.constraints.sat import NWindowSATStrategy
   >>> bounded_model = WordDifferentialSATModel(
   ...     ToySpeck(2), fixed_weight=1, nonzero_input="plaintext",
   ...     fixed_input_differences={"key": 0},
   ...     n_window=NWindowSATStrategy(2),
   ... )
   >>> bounded_formula = bounded_model.cnf_formula()
   >>> (bounded_formula.variable_count, bounded_formula.clause_count)
   (202, 594)
   >>> "n_window_run_bound" in bounded_formula.provenance
   True

Use ``by_round=(...)`` or ``by_component={...}`` when additions need different
windows. The component mapping deliberately names every modular addition so a
graph change cannot silently leave one unconstrained. Optional
``number_of_full_windows`` and ``full_window_operator`` (``"at_least"``,
``"at_most"``, or ``"exactly"``) constrain the global count of overlapping
full windows.

The ten-run ARM64 comparison in
``architecture/audits/data/sat_n_window_benchmark.json`` uses the same
ToySpeck-4 boundaries and maximum weight for every row. The heuristic adds
21--42 variables and 189--224 clauses on this small workload. Median solve
times vary by strategy and solver, so these data do not establish a generally
faster formulation; they establish reproducibility and show that pruning must
offset real encoding overhead on the intended larger searches.

.. list-table:: Median solve time in milliseconds
   :header-rows: 1

   * - Strategy
     - Variables
     - Clauses
     - MiniSat
     - Kissat
     - CryptoMiniSat
   * - Exact
     - 239
     - 830
     - 1.009
     - 2.596
     - 1.098
   * - Window 0
     - 260
     - 1,019
     - 0.961
     - 1.501
     - 0.960
   * - Window 1
     - 281
     - 1,054
     - 0.873
     - 3.165
     - 1.088
   * - Window 2
     - 274
     - 1,047
     - 0.871
     - 3.133
     - 1.013

Native-XOR trail formulas
-------------------------

``WordDifferentialNativeXorSATModel`` and ``WordLinearNativeXorSATModel`` are
explicit CryptoMiniSat alternatives to the portable ordinary-CNF trail
models. The lowering replaces a clause group only after proving that the whole
group is one canonical even- or odd-parity relation. Its independent
``expanded_cnf()`` oracle therefore reconstructs the ordinary formula exactly.

.. doctest::

   >>> from claasp.representations.constraints.sat import WordDifferentialNativeXorSATModel
   >>> native_model = WordDifferentialNativeXorSATModel(
   ...     ToySpeck(2), fixed_weight=1, nonzero_input="plaintext",
   ...     fixed_input_differences={"key": 0},
   ... )
   >>> native_formula = native_model.cnf_formula()
   >>> (native_formula.clause_count, native_formula.native_xor_count)
   (327, 60)
   >>> native_formula.expanded_cnf().clause_count
   501

Enumeration requires ``CryptoMiniSatSolver`` so a driver that understands only
ordinary DIMACS cannot silently ignore parity records. Use the ordinary model
or explicitly call ``expanded_cnf()`` for another solver.

The ten-run ARM64 benchmark in
``architecture/audits/data/native_xor_trail_benchmark.json`` compares both
formulations through the same CryptoMiniSat 5.11.15 driver and identical
boundaries. Native XOR reduced median solving time on these two toy workloads,
but construction took longer and the sample is too small to establish a
general default. Ordinary CNF remains the portable default.

.. list-table:: Ordinary CNF versus native XOR under CryptoMiniSat
   :header-rows: 1

   * - Semantics
     - Formulation
     - CNF clauses
     - XOR records
     - Build ms
     - Solve ms
   * - Differential
     - Ordinary CNF
     - 501
     - 0
     - 1.043
     - 0.962
   * - Differential
     - Native XOR
     - 327
     - 60
     - 2.998
     - 0.836
   * - Linear
     - Ordinary CNF
     - 706
     - 0
     - 2.426
     - 1.857
   * - Linear
     - Native XOR
     - 138
     - 197
     - 4.216
     - 0.916

``WordDeterministicTruncatedNativeXorSATModel`` provides the corresponding
opt-in formulation for deterministic-truncated trails:

.. doctest::

   >>> from claasp.representations.constraints.sat import (
   ...     WordDeterministicTruncatedNativeXorSATModel,
   ... )
   >>> truncated_native = WordDeterministicTruncatedNativeXorSATModel(
   ...     ToySpeck(2),
   ...     fixed_input_patterns={"plaintext": "00000001", "key": "0" * 16},
   ...     output_pattern="???0????",
   ... )
   >>> truncated_formula = truncated_native.cnf_formula()
   >>> (truncated_formula.clause_count, truncated_formula.native_xor_count)
   (733, 48)

The legacy CryptoMiniSat subclass only printed a warning and reused ordinary
CNF unchanged. The v5 strategy finds complete parity groups in graph wiring
and proves equivalence by expanding every native record back to the ordinary
formula. The ten-run ARM64 comparison in
``architecture/audits/data/native_xor_truncated_trail_benchmark.json`` uses
the same fixed ToySpeck-2 propagation and CryptoMiniSat 5.11.15. Native XOR
reduced 829 ordinary clauses to 733 plus 48 parity records; median solve time
was 0.948 ms instead of 1.219 ms, while median construction time increased
from 1.275 ms to 4.115 ms. Ordinary CNF remains the default because this one
small fixture does not establish a general performance policy.

Differential-linear SAT boundaries
----------------------------------

``DifferentialToTruncatedSATModel`` and ``TruncatedToLinearSATModel`` expose
the two boundary relations recovered from the legacy differential-linear SAT
model. The upper relation keeps an incoming XOR difference exact in the
truncated representation. The lower relation permits an active linear mask
only where the truncated difference is known.

.. doctest::

   >>> from claasp.representations.constraints.sat import (
   ...     DifferentialToTruncatedSATModel, TruncatedToLinearSATModel,
   ... )
   >>> from claasp.semantics.cryptanalysis import XorDifference, XorMask
   >>> upper = DifferentialToTruncatedSATModel(
   ...     4, difference=XorDifference(10, 4), truncated_pattern="1010"
   ... )
   >>> (upper.cnf_formula().variable_count, upper.cnf_formula().clause_count)
   (12, 24)
   >>> lower = TruncatedToLinearSATModel(
   ...     4, truncated_pattern="?010", mask=XorMask(2, 4)
   ... )
   >>> (lower.cnf_formula().variable_count, lower.cnf_formula().clause_count)
   (12, 20)

These are connector models, not a complete trail search. Their decoded
assignments return typed differences, truncated patterns, and masks. Literature
provenance remains ``TBD`` until a primary source is matched to these exact SAT
clauses.

The ten-run ARM64 comparison in
``architecture/audits/data/sat_differential_linear_boundary_benchmark.json``
uses the same 32-bit truth tables, assignments, and three canonical SAT
solvers. The direct upper connector uses 96 clauses and 160 literals instead
of 192 and 576 for exhaustive forbidden assignments; the direct lower
connector uses 64 clauses and 128 literals instead of 96 and 288. Median solve
times are recorded for reproducibility, but this local benchmark does not
establish whole-trail performance or change a default.

Complete deterministic-middle composition is available as
``WordDeterministicDifferentialLinearSATModel``. Round counts explicitly split
the primitive into a differential prefix, deterministic-truncated middle, and
linear suffix. Each section reuses its standalone model, and a decoded result
contains all three independently checked characteristics:

.. doctest::

   >>> from claasp.primitives import Speck
   >>> from claasp.representations.constraints.sat import (
   ...     WordDeterministicDifferentialLinearSATModel,
   ... )
   >>> composed = WordDeterministicDifferentialLinearSATModel(
   ...     Speck(number_of_rounds=3), prefix_rounds=1, middle_rounds=1,
   ...     differential_maximum_weight=16, linear_maximum_weight=16,
   ... )
   >>> composed_formula = composed.cnf_formula()
   >>> (composed_formula.variable_count, composed_formula.clause_count)
   (2543, 7151)

The model fixes auxiliary/key differences and masks to zero, requires a
nonzero differential input unless one is supplied, and requires a nonzero
linear output unless an output mask is supplied. Its ``total_weight`` follows
the legacy deterministic-middle SAT objective: differential weight plus twice
the linear weight. It does not assign a probability to the truncated middle.

The complete Speck32/64-3 benchmark in
``architecture/audits/data/sat_differential_linear_trail_benchmark.json`` uses
the identical 2,543-variable, 7,151-clause formula for MiniSat, Kissat, and
CryptoMiniSat. Median solve times were 2.593, 1.150, and 2.013 milliseconds.
This is a reproducibility fixture, not a solver ranking or a claim about
longer-round search performance.
