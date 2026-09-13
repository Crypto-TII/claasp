Boolean CNF models
==================

Bit-oriented cipher graphs can be lowered to a solver-independent conjunctive
normal form without installing SageMath or a SAT solver. The initial lowering
supports constants, identity, permutation, concatenation, bitwise addition
(XOR), and bit-vector S-boxes. Unsupported domains and components fail
explicitly instead of silently changing their semantics.

The following reduced PRESENT model is large enough to exercise both its
linear and nonlinear layers:

.. doctest::

   >>> from claasp_next import bits_from_int
   >>> from claasp_next.boolean import BooleanCNFModel
   >>> from claasp_next.ciphers import Present80BlockCipher
   >>> from claasp_next.representations.execution import ScalarEvaluator
   >>> cipher = Present80BlockCipher(number_of_rounds=1)
   >>> model = BooleanCNFModel(cipher)
   >>> formula = model.cnf_formula()
   >>> formula.variable_count > 500, formula.clause_count > 1000
   (True, True)
   >>> evaluation = ScalarEvaluator().evaluate(cipher, {
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

   >>> from claasp_next.boolean.exporters import DimacsExporter
   >>> dimacs = DimacsExporter().export(formula)
   >>> [line for line in dimacs.splitlines() if line.startswith("p ")]
   ['p cnf 718 2361']
   >>> dimacs.splitlines()[0]
   'c 1 plaintext_0'

Any command-line or Python SAT engine that accepts DIMACS can consume this
text. Solver adapters live outside the typed cipher graph and can be added
incrementally; the Boolean IR itself has no third-party dependency.

Solving with MiniSat
--------------------

The optional command-line adapter invokes a locally installed ``minisat``
executable. No Python solver package is required. Named assumptions add unit
clauses for one solve without modifying the original formula; they are useful
for fixing plaintext, key, or ciphertext bits.

.. doctest::

   >>> from claasp_next.boolean.solvers import MinisatSolver
   >>> solver = MinisatSolver(timeout_seconds=30)
   >>> solver.executable
   'minisat'

With MiniSat installed, a caller can run ``result = solver.solve(formula,
{"plaintext_0": 0})``. A satisfiable result contains an assignment keyed by
the original graph-derived variable names. ``result.status`` distinguishes
``SATISFIABLE`` from ``UNSATISFIABLE``, and ``runtime_seconds``, ``stdout``,
and ``stderr`` retain execution diagnostics. Missing executables, timeouts,
malformed output, and nonstandard exit codes are reported explicitly.
