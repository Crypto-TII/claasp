Constraint-programming representations
======================================

M10.6a introduces the Sage-independent CP foundation. ``MiniZincModel`` is a
small immutable representation that owns MiniZinc language items; external
process execution belongs to ``MiniZincSolver`` under ``drivers``. Neither the
core graph nor the representation imports the MiniZinc Python package.

.. doctest::

   >>> from claasp_next.representations.constraints.cp import MiniZincModel
   >>> model = MiniZincModel(
   ...     declarations=("var 0..3: x;",),
   ...     constraints=("constraint x = 2;",),
   ...     provenance=("documentation example",),
   ... )
   >>> print(model.source())
   var 0..3: x;
   constraint x = 2;
   solve satisfy;
   <BLANKLINE>

The optional command-line driver requests MiniZinc's JSON output mode and
returns named logical values in ``CPResult``. For example, on a machine with
MiniZinc and Gecode installed:

.. code-block:: python

   from claasp_next.drivers.solvers import MiniZincSolver

   result = MiniZincSolver(solver="gecode").solve(model)
   assert result.is_satisfied
   assert result.values["x"] == 2

Cipher solving and key recovery
-------------------------------

The CP representation can lower the portable Boolean formula already produced
from supported typed cipher components. MiniZinc-safe encoded identifiers are
kept internal and results are mapped back to stable graph names. Consequently
the ordinary analysis API works unchanged:

.. code-block:: python

   from claasp_next.ciphers import SpeckBlockCipher
   from claasp_next.drivers.solvers import MiniZincSolver

   cipher = SpeckBlockCipher(number_of_rounds=1)
   plaintext = 0x6574694C
   ciphertext = cipher.evaluate(plaintext, 0x1918111009080100)
   result = cipher.analyze().recover_input(
       "key",
       known_inputs={"plaintext": plaintext},
       output=ciphertext,
       solver=MiniZincSolver(),
   )
   assert cipher.evaluate(plaintext, result.value("key")) == ciphertext

A dedicated external test also reproduces the legacy full 22-round
Speck32/64 fixed-input result ``0xa86842f2``. Both recovery and the legacy
fixture are checked with scalar evaluation rather than trusting solver status.

Shared differential trails
--------------------------

``PresentDifferentialCPModel`` consumes a backend-neutral
``PropagationProblem`` and emits native MiniZinc table constraints. The table
rows come from the selected component semantic provider, so per-component
research overrides are honored consistently with SMT and MILP.

The reviewed PRESENT-2 differential regression proves weight bound 3
unsatisfiable and weight bound 4 satisfiable using a real MiniZinc solver. Its
decoded 32-step trail is checked independently against every DDT transition
and permutation boundary.

``PresentLinearCPModel`` applies the same design to signed LAT semantics. The
PRESENT-3 regression proves the legacy weight-4 optimum, reconstructs the
sign of each of its 48 correlations, and independently checks all transitions
and graph boundaries. Deterministic-truncated and impossible propagation form
the final M10.6c checkpoint.

Truncated and impossible propagation
------------------------------------

Three-valued ``TruncatedXorDifference`` and paired-carry addition now belong
to ``claasp_next.semantics.cryptanalysis`` rather than the analysis facade. The
initial ``SpeckTruncatedCPModel`` compiles a fixed input-pattern propagation
to conventional CP values 0, 1, and 2 (unknown). Its external regression
reproduces the legacy first-round result
``????100000000000????100000000011`` and independently compares the decoded
projection with shared paired-carry semantics.

``SBoxDifferenceCPModel`` constructs an exact table from the semantic provider
selected by ``PropagationProblem``. A real MiniZinc solver proves PRESENT
transition ``1 -> 1`` impossible and ``1 -> 3`` feasible; the latter's weight
is independently obtained from the exhaustive DDT semantics.

These are the reviewed M10.6c slices. Multi-round bidirectional impossible
search and the legacy wordwise, semi-deterministic, and ARX-specialized models
remain explicitly in M10.6d.

Advanced-suite migration
------------------------

M10.6d is organized by cryptanalytic semantics rather than by the legacy class
hierarchy. Its complete model-and-fixture inventory is maintained in
``docs/architecture/cp-advanced-migration.md``. Exact ARX differential
optimization is the first implementation checkpoint, followed by generalized
truncated domains, multi-round impossible search, composed attacks, and
continuous heuristics.

The distinction between exact and heuristic results is intentional. Exact
models must provide a solver witness plus an independent semantic checker; an
optimality claim also needs an unsatisfiable lower bound. Continuous models
must instead state numerical precision and tolerances and cannot certify an
exact impossibility result on their own.

Exact ARX differential optimization
-----------------------------------

``SpeckDifferentialCPModel`` composes the exact bit relation for modular-add
XOR differences with rotations and XOR wiring read from the typed Speck graph.
It currently supports the reviewed Speck32/64 slice with zero key difference.
The external regression uses Chuffed to prove weight 8 unsatisfiable and
weight 9 satisfiable for five rounds, reproducing the legacy optimized-CP
result. The decoded five additions are then recounted with independent
paired-carry semantics; no solver-reported probability is trusted.

.. automodule:: claasp_next.representations.constraints.cp
   :members:

.. automodule:: claasp_next.drivers.solvers.minizinc
   :members:
