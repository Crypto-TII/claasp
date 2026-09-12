Analyzing a cipher
==================

Analysis constraints refer to cipher inputs, outputs, components, and indexed
logical units—not DIMACS or backend variable names. Problems and projected
results therefore remain meaningful when the solver changes.

.. doctest::

   >>> from claasp_next import Bit, Cipher, ValueType
   >>> from claasp_next.analysis import AnalysisProblem, FixedValue
   >>> from claasp_next.components import Add
   >>> cipher = Cipher("xor", {
   ...     "plaintext": ValueType(Bit(), (1,)),
   ...     "key": ValueType(Bit(), (1,)),
   ... })
   >>> cipher.add_round()
   Round(number=0)
   >>> output = cipher.add_component(Add((cipher.input("plaintext"), cipher.input("key"))))
   >>> cipher.set_output(output)
   >>> problem = AnalysisProblem(
   ...     cipher,
   ...     constraints=(
   ...         FixedValue(cipher.input("plaintext"), 1),
   ...         FixedValue(cipher.output, 0),
   ...     ),
   ...     projections={"key": cipher.input("key")},
   ... )
   >>> [type(item).__name__ for item in problem.constraints]
   ['FixedValue', 'FixedValue']

With the optional ``minisat`` executable installed, the common key-recovery
workflow is deliberately shorter:

.. code-block:: python

   result = cipher.analyze().recover_input(
       "key",
       known_inputs={"plaintext": 1},
       output=0,
   )
   assert result.is_satisfiable
   assert result.value("key") == 1

``Equal``, ``NotEqual``, ``Nonzero``, and ``HammingWeight`` provide reusable
backend-neutral constraints. ``MinimizeWeight`` records an objective, while a
backend that cannot optimize rejects it explicitly. Results retain status,
runtime, backend name, model statistics, projections, and the raw solver
result for reproducibility.

Word-oriented recovery
----------------------

The same API lowers word-native ARX operations to Boolean constraints. Inputs
and projections remain ordinary packed integers; users do not manually split
words into solver bits. For example, MiniSat can recover a key consistent with
a one-round Speck32/64 plaintext/ciphertext pair:

.. code-block:: python

   from claasp_next.ciphers import SpeckBlockCipher

   cipher = SpeckBlockCipher(number_of_rounds=1)
   plaintext = 0x6574694C
   ciphertext = cipher.evaluate(plaintext, 0x1918111009080100)
   result = cipher.analyze().recover_input(
       "key",
       known_inputs={"plaintext": plaintext},
       output=ciphertext,
   )
   assert result.is_satisfiable
   assert cipher.evaluate(plaintext, result.value("key")) == ciphertext

A reduced-round pair may admit several keys. Build an ``AnalysisProblem`` with
the desired key projection and call ``enumerate_solutions(problem, limit=N)``
to request distinct projected solutions. The facade adds blocking clauses and
stops either at ``N`` or when the model becomes unsatisfiable.

Differential and linear semantics
---------------------------------

Trail objects and component transition probabilities are independent of any
SAT, SMT, MILP, or CP syntax. This also gives analysis results a second,
solver-independent checker. For the published PRESENT S-box, for example:

.. doctest::

   >>> from claasp_next.analysis import SBoxTransitionSemantics
   >>> from claasp_next.ciphers.block_ciphers.present import PRESENT_SBOX
   >>> semantics = SBoxTransitionSemantics(PRESENT_SBOX)
   >>> transition = semantics.xor_differential(0x1, 0x3)
   >>> (transition.numerator, transition.denominator, transition.weight)
   (4, 16, 2.0)
   >>> semantics.check(transition)
   True

Linear transitions retain their correlation sign as well as their absolute
weight. Impossible transitions have zero numerator and infinite weight.

SPN trail search
----------------

The first reviewed graph-level search slice reproduces the legacy two-round
PRESENT XOR-differential optimum. The result distinguishes a proven optimum
from a mere feasible trail and records its provenance:

.. doctest::

   >>> from claasp_next.ciphers import PresentBlockCipher
   >>> cipher = PresentBlockCipher(number_of_rounds=2)
   >>> result = cipher.analyze().find_lowest_weight_xor_differential_trail()
   >>> (result.trail.total_weight, result.lower_bound, result.is_optimal)
   (4.0, 4.0, True)

The search reads the S-box and permutation semantics from the typed graph.
Every returned transition and the wiring between both substitution layers are
recomputed by an independent checker in the regression suite.

ARX trail search
----------------

Modular-add transitions are counted exactly with a paired-carry automaton;
they are not approximated by random sampling. The graph-facing API also
reproduces the preserved two-round Speck32/64 optimum:

.. doctest::

   >>> from claasp_next.ciphers import SpeckBlockCipher
   >>> cipher = SpeckBlockCipher(number_of_rounds=2)
   >>> result = cipher.analyze().find_lowest_weight_xor_differential_trail()
   >>> (result.trail.total_weight, result.is_optimal)
   (1.0, True)
   >>> hex(result.trail.input_pattern.value)
   '0x400000'

The regression checker independently recomputes both modular-add
probabilities and the rotations/XOR wiring through both Speck rounds.

Truncated and impossible differences
------------------------------------

Deterministic truncated differences use the explicit symbols ``0``, ``1``,
and ``?``. Modular addition propagates them with a sound paired-carry
reachability computation:

.. doctest::

   >>> from claasp_next.analysis import TruncatedXorDifference, truncated_modular_add
   >>> left = TruncatedXorDifference.parse("1000")
   >>> zero = TruncatedXorDifference.parse("0000")
   >>> str(truncated_modular_add(left, zero))
   '1000'

For exact S-box differences, impossibility can be queried directly through
the graph facade:

.. doctest::

   >>> from claasp_next.ciphers import PresentBlockCipher
   >>> cipher = PresentBlockCipher(number_of_rounds=1)
   >>> cipher.analyze().is_xor_differential_transition_possible("sbox_1_0", 1, 1)
   False

Linear trail search
-------------------

Linear search uses the same graph facade and retains each LAT correlation
sign. The initial SPN slice restores the preserved three-round PRESENT
weight-4 fixture:

.. doctest::

   >>> from claasp_next.ciphers import PresentBlockCipher
   >>> result = PresentBlockCipher(number_of_rounds=3).analyze().find_lowest_weight_xor_linear_trail()
   >>> (result.trail.total_weight, result.is_optimal)
   (4.0, True)
   >>> any(step.transition.sign == -1 for step in result.trail.steps)
   True
