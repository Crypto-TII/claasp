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
