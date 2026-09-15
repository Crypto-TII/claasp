SMT models
==========

CLAASP's SMT layer has no Python solver dependency. Supported Bit and Word
graphs lower to a small solver-independent representation which can be
exported as SMT-LIB 2:

.. doctest::

   >>> from claasp_next.primitives import Speck
   >>> from claasp_next.representations.constraints.smt import BooleanSMTModel
   >>> from claasp_next.representations.constraints.smt.exporter import SMTLibExporter
   >>> primitive = Speck(number_of_rounds=1)
   >>> formula = BooleanSMTModel(primitive).smt_formula()
   >>> formula.assertion_count > 400
   True
   >>> SMTLibExporter().export(formula).startswith("(set-logic QF_UF)\n")
   True

Solving with Z3
---------------

The optional command adapter invokes a local ``z3`` executable. It is usable
through the same graph-level recovery API as MiniSat:

.. code-block:: python

   from claasp_next.drivers.solvers import Z3Solver

   plaintext = 0x6574694C
   ciphertext = primitive.evaluate(plaintext, 0x1918111009080100)
   result = primitive.analyze().recover_input(
       "key",
       known_inputs={"plaintext": plaintext},
       output=ciphertext,
       solver=Z3Solver(timeout_seconds=30),
   )
   assert primitive.evaluate(plaintext, result.value("key")) == ciphertext

Z3 is optional and remains outside the core package. Dedicated integration
tests solve the complete 22-round Speck32/64 legacy ``find_missing_bits``
fixture and independently confirm the returned ciphertext by evaluation.

Transition relations
--------------------

Shared component semantics can be lowered independently of a full primitive.
For example, Z3 can establish whether a PRESENT S-box differential transition
is possible:

.. doctest::

   >>> from claasp_next.analysis import TrailKind
   >>> from claasp_next.primitives.block_ciphers.present import PRESENT_SBOX
   >>> from claasp_next.representations.constraints.smt import SBoxTransitionSMTModel
   >>> relation = SBoxTransitionSMTModel(PRESENT_SBOX, TrailKind.XOR_DIFFERENTIAL)
   >>> possible = relation.smt_formula(input_pattern=1, output_pattern=3)
   >>> impossible = relation.smt_formula(input_pattern=1, output_pattern=1)
   >>> possible.assertion_count == impossible.assertion_count
   True

The formula encodes the complete DDT support, not one hand-written fixture.
Unit tests exhaustively compare all satisfying assignments with the shared
transition semantics. The same model supports the LAT relation and projects a
solver assignment back to an exact weight and correlation sign.

Weighted full trails
--------------------

The first composed trail model connects 32 exact S-box relations through both
PRESENT permutation layers, requires a nonzero input difference, and bounds
the sum of unary transition weights with a sequential counter:

.. doctest::

   >>> from claasp_next.primitives import Present
   >>> from claasp_next.representations.constraints.smt import PresentDifferentialSMTModel
   >>> model = PresentDifferentialSMTModel(Present(number_of_rounds=2), 4)
   >>> formula = model.smt_formula()
   >>> (len(formula.variables) < 700, formula.assertion_count < 30000)
   (True, True)

The Z3 integration proves the model with weight at most 3 unsatisfiable, then
extracts a weight-4 trail from the satisfiable bound. A separate checker
recomputes all transition weights and both permutation boundaries.

The corresponding three-round linear model composes complete LAT support,
unary absolute-correlation weights, and all permutation wiring. Its decoded
trail retains the independently recomputed correlation sign of every S-box:

.. doctest::

   >>> from claasp_next.representations.constraints.smt import PresentLinearSMTModel
   >>> linear = PresentLinearSMTModel(Present(number_of_rounds=3), 4)
   >>> linear_formula = linear.smt_formula()
   >>> (len(linear_formula.variables) < 1000, linear_formula.assertion_count < 40000)
   (True, True)

Dedicated Z3 tests prove bound 3 unsatisfiable and extract the weight-4
optimum at bound 4, followed by independent checking of all 48 transitions
and three permutation boundaries.

The primitive-first constructors above are conveniences. Representation-explicit
code may supply a shared propagation problem instead:

.. doctest::

   >>> from claasp_next.semantics import XOR_DIFFERENTIAL
   >>> from claasp_next.semantics.cryptanalysis import PropagationProblem
   >>> problem = PropagationProblem(Present(number_of_rounds=2), XOR_DIFFERENTIAL, maximum_weight=4)
   >>> PresentDifferentialSMTModel(problem).problem is problem
   True

Component semantics, including per-component researcher overrides, are read
from this problem rather than reconstructed by the SMT compiler.

ARX linear transitions
----------------------

Modular addition uses an exact word-level linear-mask relation.  The SMT
encoding exposes the two input masks, output mask, and unary weight bits while
the shared Walsh semantics remains the independent oracle:

.. doctest::

   >>> from claasp_next.representations.constraints.smt import ModularAddLinearSMTModel
   >>> addition = ModularAddLinearSMTModel(16)
   >>> formula = addition.smt_formula(
   ...     left_mask=0x6081, right_mask=0x40c1, output_mask=0x4081
   ... )
   >>> formula.assertion_count > 0
   True

The Z3 integration restores all four modular-add transitions of CLAASP's
four-round Speck32/64 weight-3 linear characteristic.  It verifies transition
weights ``2 + 0 + 0 + 1`` and correlation signs ``+,+,+,-`` with the exact
Walsh checker after solving.  This fixture was regenerated with the legacy
``SatXorLinearModel`` and MiniSat 2.2.1; it is not merely copied from solver
output without semantic validation.

Speck data-path composition
---------------------------

``SpeckLinearSMTModel`` wires each round's exact addition relation through
the graph's rotations and XOR mask rules. It assumes zero round-key masks,
requires a nonzero plaintext mask, and accepts either an upper weight bound
or an exact weight (not both). Execution remains a separate ``Z3Solver``
operation; decoding independently recounts all correlations and wiring.

.. doctest::

   >>> from claasp_next.primitives import Speck
   >>> from claasp_next.representations.constraints.smt import SpeckLinearSMTModel
   >>> model = SpeckLinearSMTModel(Speck(number_of_rounds=3), maximum_weight=1)
   >>> formula = model.smt_formula()
   >>> "nonzero_linear_input" in formula.provenance
   True
   >>> exact = SpeckLinearSMTModel(Speck(number_of_rounds=3), fixed_weight=7)
   >>> "weight_complement" in exact.smt_formula().provenance
   True

The bounded Z3 regression preserves the legacy three-round Speck32/64
optimum: weight zero is UNSAT and weight one is SAT. It also preserves the
legacy feasible weight seven without calling it an optimum. The nonstandard
Speck8/16 eight-trail fixture is separate: it requires a toy primitive and
nonzero key-mask propagation, which this zero-key-mask model does not claim.
