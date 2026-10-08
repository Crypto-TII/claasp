Analyzing a primitive
======================

Analysis constraints refer to primitive inputs, outputs, components, and indexed
logical units—not DIMACS or backend variable names. Problems and projected
results therefore remain meaningful when the solver changes.

.. doctest::

   >>> from claasp import Bit, PrimitiveBuilder, ValueType
   >>> from claasp.analysis import AnalysisProblem, FixedValue
   >>> from claasp.components import Add
   >>> builder = PrimitiveBuilder("xor", {
   ...     "plaintext": ValueType(Bit(), (1,)),
   ...     "key": ValueType(Bit(), (1,)),
   ... })
   >>> builder.add_round()
   Round(number=0)
   >>> output = builder.add_component(Add((builder.input("plaintext"), builder.input("key"))))
   >>> primitive = builder.build(output)
   >>> problem = AnalysisProblem(
   ...     primitive,
   ...     constraints=(
   ...         FixedValue(primitive.graph.input("plaintext"), 1),
   ...         FixedValue(primitive.graph.output, 0),
   ...     ),
   ...     projections={"key": primitive.graph.input("key")},
   ... )
   >>> [type(item).__name__ for item in problem.constraints]
   ['FixedValue', 'FixedValue']

With the optional ``minisat`` executable installed, the common key-recovery
workflow is deliberately shorter:

.. code-block:: python

   result = primitive.analysis.recover_input(
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

   from claasp.primitives import Speck

   primitive = Speck(number_of_rounds=1)
   plaintext = 0x6574694C
   ciphertext = primitive.evaluate(plaintext, 0x1918111009080100)
   result = primitive.analysis.recover_input(
       "key",
       known_inputs={"plaintext": plaintext},
       output=ciphertext,
   )
   assert result.is_satisfiable
   assert primitive.evaluate(plaintext, result.value("key")) == ciphertext

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

   >>> from claasp.analysis import SBoxTransitionSemantics
   >>> from claasp.primitives.block_ciphers.present import PRESENT_SBOX
   >>> semantics = SBoxTransitionSemantics(PRESENT_SBOX)
   >>> transition = semantics.xor_differential(0x1, 0x3)
   >>> (transition.numerator, transition.denominator, transition.weight)
   (4, 16, 2.0)
   >>> semantics.check(transition)
   True

Linear transitions retain their correlation sign as well as their absolute
weight. Impossible transitions have zero numerator and infinite weight.

Use ``primitive.analysis.find_optimal_trail(kind=...)`` for the common trail kinds.
The string values ``"xor_differential"`` and ``"xor_linear"`` are also the
values of ``claasp.analysis.TrailKind``, so editors can offer a typed enum
without making the beginner-facing call verbose. ``backend="auto"`` preserves
the established search for each reviewed primitive slice. Advanced callers
can select ``claasp.analysis.TrailSearchBackend`` and pass ``solver=``
where the selected solver-backed search supports it. Unsupported combinations
raise an explicit exception; CLAASP never substitutes a different backend or
search meaning silently.

The longer
``find_lowest_weight_xor_differential_trail()`` and
``find_lowest_weight_xor_linear_trail()`` methods also retain their existing
defaults, while new examples use the common typed entry point.

For two-round Speck32/64 XOR-differential search, the explicit
``backend="dependency_free"`` selection runs an exact Matsui-style
branch-and-bound search. It uses rational transition probabilities and a
monotone partial-carry bound, and independently checks the returned weight-one
trail. The default ``backend="auto"`` continues to select Kissat; choosing the
dependency-free implementation never changes the default solver policy.

.. doctest::

   >>> from claasp.primitives import Speck
   >>> result = Speck(number_of_rounds=2).analysis.find_optimal_trail(
   ...     kind="xor_differential", backend="dependency_free")
   >>> (result.trail.total_weight, result.is_optimal, result.metadata.solver)
   (1.0, True, None)

SPN trail search
----------------

The graph-level search finds the two-round PRESENT XOR-differential optimum.
The result distinguishes a proven optimum from a mere feasible trail and
records structured search metadata and the complete data-state propagation:

.. doctest::

   >>> from claasp.primitives import Present
   >>> primitive = Present(number_of_rounds=2)
   >>> result = primitive.analysis.find_optimal_trail(kind="xor_differential")
   >>> (result.trail.total_weight, result.lower_bound, result.is_optimal)
   (4.0, 4.0, True)
   >>> (result.metadata.solver, len(result.component_transitions))
   (None, 37)

The search reads the S-box and permutation semantics from the typed graph.
Every returned transition and the wiring between both substitution layers are
recomputed by an independent checker in the regression suite.

ARX trail search
----------------

Modular-add transitions are counted exactly with a paired-carry automaton;
they are not approximated by random sampling. The graph-facing API also
reproduces the preserved two-round Speck32/64 optimum:

.. doctest::

   >>> from claasp.primitives import Speck
   >>> primitive = Speck(number_of_rounds=2)
   >>> result = primitive.analysis.find_optimal_trail(kind="xor_differential")
   >>> (result.trail.total_weight, result.is_optimal)
   (1.0, True)
   >>> len(result.component_transitions)
   10

The ten reported transitions cover every rotation, modular addition, and XOR
on the two-round data-state path. The default search fixes the key difference
to zero, so its all-zero key schedule is omitted. An independent checker
recomputes both modular-add probabilities and the rotations/XOR wiring.
The default method uses Kissat and binary search over the maximum permitted
weight. The particular optimum returned may change when several trails have
the same minimum weight.

Truncated and impossible differences
------------------------------------

Deterministic truncated differences use the explicit symbols ``0``, ``1``,
and ``?``. Modular addition propagates them with a sound paired-carry
reachability computation:

.. doctest::

   >>> from claasp.analysis import TruncatedXorDifference, truncated_modular_add
   >>> left = TruncatedXorDifference.parse("1000")
   >>> zero = TruncatedXorDifference.parse("0000")
   >>> str(truncated_modular_add(left, zero))
   '1000'

For exact S-box differences, impossibility can be queried directly through
the graph facade:

.. doctest::

   >>> from claasp.primitives import Present
   >>> primitive = Present(number_of_rounds=1)
   >>> primitive.analysis.is_xor_differential_transition_possible("sbox_1_0", 1, 1)
   False

Linear trail search
-------------------

Linear search uses the same graph facade and retains each LAT correlation
sign. The initial SPN slice restores the preserved three-round PRESENT
weight-4 fixture:

.. doctest::

   >>> from claasp.primitives import Present
   >>> result = Present(number_of_rounds=3).analysis.find_optimal_trail(kind="xor_linear")
   >>> (result.trail.total_weight, result.is_optimal)
   (4.0, True)
   >>> any(step.transition.sign == -1 for step in result.trail.steps)
   True

ARX linear masks use an exact signed carry automaton as well. The restored
four-round Speck32/64 reference characteristic is exposed by the identical
facade call:

.. doctest::

   >>> from claasp.primitives import Speck
   >>> result = Speck(number_of_rounds=4).analysis.find_optimal_trail(kind="xor_linear")
   >>> (result.trail.total_weight, result.is_optimal)
   (3.0, True)
   >>> (hex(result.trail.input_pattern.value), hex(result.trail.output_pattern.value))
   ('0x40b010c1', '0x2c102010')

Word-graph characteristics can also be enumerated with
``primitive.analysis.enumerate_xor_linear_trails(maximum_weight, solver=solver)``.
The default fixes the key value to zero and folds its dependent subgraph;
``nonzero_input="key"`` includes key-schedule masks instead. Results retain graph/realization identities, solver
version, signed component correlations, and proof-completeness metadata.
``require_complete()`` rejects a caller-limited enumeration. Characteristics
are not a sum over trails or a whole-primitive linear-hull claim.

.. doctest::

   >>> from claasp.primitives import ToySpeck
   >>> toy = ToySpeck()
   >>> toy.family_name
   'toy_speck'
   >>> hex(toy.evaluate(0x53, 0x1234))
   '0xe2'

Word-graph differential enumeration is available through
``primitive.analysis.enumerate_xor_differential_trails(maximum_weight,
solver=...)``. The default fixes key difference zero; choose
``nonzero_input="key"`` for related-key propagation. Supply ``fixed_weight``
instead of a maximum for an exact-weight search. Always call
``require_complete()`` before using an exhaustive count. Component-product
probabilities and bounded cluster sums are not experimental whole-primitive
probabilities.
