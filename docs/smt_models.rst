SMT models
==========

CLAASP's SMT layer has no Python solver dependency. Supported Bit and Word
graphs lower to a small solver-independent representation which can be
exported as SMT-LIB 2:

.. doctest::

   >>> from claasp.primitives import Speck
   >>> from claasp.representations.constraints.smt import BooleanSMTModel
   >>> from claasp.representations.constraints.smt.exporter import SMTLibExporter
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

   from claasp.drivers.solvers import Z3Solver

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

Fixed Speck data-path masks are explicit constructor arguments, separate
from execution inputs. The external regression preserves the legacy CP
weight-five witness:

.. doctest::

   >>> from claasp.representations.constraints.smt import SpeckLinearSMTModel
   >>> fixed = SpeckLinearSMTModel(Speck(number_of_rounds=3), fixed_weight=5,
   ...     input_mask=0x03805224, output_mask=0x40A000C1)
   >>> fixed.input_mask == 0x03805224 and fixed.output_mask == 0x40A000C1
   True

The decoder independently checks both masks and the exact weight.

Whole-word differential composition
-----------------------------------

``WordDifferentialSMTModel`` connects forward differences through XOR,
rotation, identity, concatenation, constants, AND, and modular addition.
Fanout shares the producer difference; unlike linear masks, consumer
differences are not XORed back into a producer mask. The complete key
schedule is included, enabling explicit related-key searches.

.. doctest::

   >>> from claasp.primitives import ToySpeck
   >>> from claasp.representations.constraints.smt import WordDifferentialSMTModel
   >>> differential = WordDifferentialSMTModel(ToySpeck(2), fixed_weight=1,
   ...     nonzero_input="plaintext", fixed_input_differences={"key": 0})
   >>> "fixed_difference" in differential.smt_formula().provenance
   True

For simple enumeration, use the analysis facade:

.. code-block:: python

   result = ToySpeck(2).analyze().enumerate_xor_differential_trails(
       1, solver=Z3Solver(timeout_seconds=10), limit=10,
   ).require_complete()
   assert len(result.trails) == 7  # six weight-one, one weight-zero

The default sets key difference zero. Selecting ``nonzero_input="key"``
instead searches related-key characteristics. Addition support and declared
weights are independently recounted through paired carry semantics, tested
against exhaustive small integer truth tables. Enumeration blocks semantic
assignments and claims completion only after terminal UNSAT. Limits and
unknown solver outcomes are incomplete results.

``result.cluster_probability()`` sums exact rational component products only
for a complete common-boundary cluster. It is a bounded characteristic-model
sum, not a measured concrete-primitive probability or an unrestricted
differential. The dedicated fixed nine-round Speck regression retains all 27
legacy trails at weights 30 through 39 and cluster weight 29.47; it is excluded
from the routine dependency-free suite.

Transition relations
--------------------

Shared component semantics can be lowered independently of a full primitive.
For example, Z3 can establish whether a PRESENT S-box differential transition
is possible:

.. doctest::

   >>> from claasp.analysis import TrailKind
   >>> from claasp.primitives.block_ciphers.present import PRESENT_SBOX
   >>> from claasp.representations.constraints.smt import SBoxTransitionSMTModel
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

   >>> from claasp.primitives import Present
   >>> from claasp.representations.constraints.smt import PresentDifferentialSMTModel
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

   >>> from claasp.representations.constraints.smt import PresentLinearSMTModel
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

   >>> from claasp.semantics import XOR_DIFFERENTIAL
   >>> from claasp.semantics.cryptanalysis import PropagationProblem
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

   >>> from claasp.representations.constraints.smt import ModularAddLinearSMTModel
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

   >>> from claasp.primitives import Speck
   >>> from claasp.representations.constraints.smt import SpeckLinearSMTModel
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
Speck8/16 fixture is handled separately by ``ToySpeck`` and whole-graph
``WordLinearSMTModel``, including nonzero key masks.

The same graph-wired model preserves the CMS suite's four-round Speck32/64
optimum of three: Z3 proves bound two UNSAT and bound three SAT. This is a
proof of the shared data-path characteristic model, not a claim to execute
CryptoMiniSat or reproduce a whole-primitive linear hull. Native XOR clauses
are an optional encoding optimization; they do not define separate semantics.

Whole-word linear composition and enumeration
---------------------------------------------

``WordLinearSMTModel`` composes two-input modular addition, bitwise AND, XOR, rotation,
identity, concatenation, and constants over arbitrary typed Word graphs.
Input selections retain logical-unit order; fanout XORs consumer masks back
to each producer, including the key schedule. Constants contribute a sign,
not weight. Unsupported operations fail explicitly.

.. doctest::

   >>> from claasp.primitives import ToySpeck
   >>> from claasp.representations.constraints.smt import WordLinearSMTModel
   >>> toy = ToySpeck()
   >>> toy.family_name
   'toy_speck'
   >>> model = WordLinearSMTModel(toy, maximum_weight=2, nonzero_input="key")
   >>> "nonzero_external_mask" in model.smt_formula().provenance
   True

With a separate ``Z3Solver``, ``model.enumerate_trails(solver)`` returns
typed characteristics and proof-completeness metadata. Blocking excludes
semantic masks rather than auxiliary counter multiplicity; terminal UNSAT
is required by ``require_complete()``. A caller-imposed trail limit cannot
be reported as exhaustive. Each result is independently checked using integer
mask pullbacks, graph fanout, constant signs, and exact Walsh correlations.

The legacy Speck8/16 four-round nonzero-key fixtures contain exactly eight
characteristics at weights at most two and 73 at weights at most three.
Both counts are retained. These are component characteristics, not a sum over
trails or a whole-primitive linear hull. ``ToySpeck`` is an explicitly toy,
four-bit-word keyed bijection with legacy rotations 8 modulo 4 and 3; official
``Speck`` continues to reject these nonstandard block/key sizes.

Concrete fixed inputs and zero masks are distinct: ``fixed_inputs={"key": 0}``
folds exactly the subgraph depending only on that concrete key, retaining its
constant signs without charging key-schedule correlations. By contrast,
``fixed_input_masks={"key": 0}`` leaves key-schedule variables in the model
and imposes an external mask constraint. The simple facade defaults to the
former for single-key analysis. The CP legacy toy's three-round fixed-key
fixtures retain exactly 12 weight-one and 13 weight-at-most-one results.

Z3 enumeration uses one isolated incremental process, appending only no-good
clauses. The driver rejects changed declarations/assertion prefixes, enforces
per-query timeouts, checks complete named assignments, and always closes the
process. Other drivers may still use ordinary independent solves.

The AND provider retains the legacy one-bit DDT counts
``[4, 0, 2, 2, 2, 2, 2, 2]`` and half-Walsh LAT
``[2, 1, 0, 1, 0, 1, 0, -1]``, and factors independent word bits exactly:

.. doctest::

   >>> from claasp.semantics.cryptanalysis import BitwiseAndSemantics
   >>> entry = BitwiseAndSemantics(1).xor_linear(1, 1, 1)
   >>> (entry.numerator, entry.denominator, entry.sign, entry.weight)
   (2, 4, -1, 1.0)
