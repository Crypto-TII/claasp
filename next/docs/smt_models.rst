SMT models
==========

CLAASP's SMT layer has no Python solver dependency. Supported Bit and Word
graphs lower to a small solver-independent representation which can be
exported as SMT-LIB 2:

.. doctest::

   >>> from claasp_next.ciphers import SpeckBlockCipher
   >>> from claasp_next.smt import BooleanSMTModel
   >>> from claasp_next.smt.exporter import SMTLibExporter
   >>> cipher = SpeckBlockCipher(number_of_rounds=1)
   >>> formula = BooleanSMTModel(cipher).smt_formula()
   >>> formula.assertion_count > 400
   True
   >>> SMTLibExporter().export(formula).startswith("(set-logic QF_UF)\n")
   True

Solving with Z3
---------------

The optional command adapter invokes a local ``z3`` executable. It is usable
through the same graph-level recovery API as MiniSat:

.. code-block:: python

   from claasp_next.smt.solvers import Z3Solver

   plaintext = 0x6574694C
   ciphertext = cipher.evaluate(plaintext, 0x1918111009080100)
   result = cipher.analyze().recover_input(
       "key",
       known_inputs={"plaintext": plaintext},
       output=ciphertext,
       solver=Z3Solver(timeout_seconds=30),
   )
   assert cipher.evaluate(plaintext, result.value("key")) == ciphertext

Z3 is optional and remains outside the core package. Dedicated integration
tests solve the complete 22-round Speck32/64 legacy ``find_missing_bits``
fixture and independently confirm the returned ciphertext by evaluation.

Transition relations
--------------------

Shared component semantics can be lowered independently of a full cipher.
For example, Z3 can establish whether a PRESENT S-box differential transition
is possible:

.. doctest::

   >>> from claasp_next.analysis import TrailKind
   >>> from claasp_next.ciphers.block_ciphers.present import PRESENT_SBOX
   >>> from claasp_next.smt import SBoxTransitionSMTModel
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

   >>> from claasp_next.ciphers import PresentBlockCipher
   >>> from claasp_next.smt import PresentDifferentialSMTModel
   >>> model = PresentDifferentialSMTModel(PresentBlockCipher(number_of_rounds=2), 4)
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

   >>> from claasp_next.smt import PresentLinearSMTModel
   >>> linear = PresentLinearSMTModel(PresentBlockCipher(number_of_rounds=3), 4)
   >>> linear_formula = linear.smt_formula()
   >>> (len(linear_formula.variables) < 1000, linear_formula.assertion_count < 40000)
   (True, True)

Dedicated Z3 tests prove bound 3 unsatisfiable and extract the weight-4
optimum at bound 4, followed by independent checking of all 48 transitions
and three permutation boundaries.
