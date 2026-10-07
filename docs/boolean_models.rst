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
