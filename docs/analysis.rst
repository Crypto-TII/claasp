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

Use ``primitive.analysis.find_optimal_trail(kind=...)`` for the common trail
kinds. The string values ``"xor_differential"`` and ``"xor_linear"`` are also
the values of ``claasp.analysis.TrailKind``, so editors can offer a typed enum
without making the beginner-facing call verbose. ``backend="auto"`` chooses
the default exact search available for that primitive and trail kind. Advanced
callers can select ``claasp.analysis.TrailSearchBackend`` and pass ``solver=``
where the selected solver-backed search supports it. Unsupported combinations
raise an explicit exception; CLAASP never substitutes a different backend or
search meaning silently.

The more explicit ``find_lowest_weight_xor_differential_trail()`` and
``find_lowest_weight_xor_linear_trail()`` methods are also available when code
benefits from naming the trail kind directly in the method call.

For two-round Speck32/64 XOR-differential search, the explicit
``backend="dependency_free"`` selection runs an exact Matsui-style
branch-and-bound search. It uses rational transition probabilities and a
monotone partial-carry bound, and independently checks the returned weight-one
trail. The default ``backend="auto"`` selects this dependency-free
implementation, so the search requires no external solver.

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
   >>> result = primitive.analysis.find_optimal_trail(
   ...     kind="xor_differential", backend="dependency_free"
   ... )
   >>> (result.trail.total_weight, result.lower_bound, result.is_optimal)
   (4.0, 4.0, True)
   >>> (result.metadata.solver, len(result.component_transitions))
   (None, 37)

The search reads the S-box and permutation semantics from the typed graph.
Every returned transition and the wiring between both substitution layers are
recomputed by an independent checker in the regression suite.

Generic exact trail search
--------------------------

``primitive.analysis.find_optimal_trail()`` defaults to XOR-differential
search.  The facade inspects domains and components and uses the generic exact
SAT optimizer for supported Word graphs; it never sends an unrelated graph to
a PRESENT- or Speck-specific validator.  String and typed kinds are accepted:

.. code-block:: python

   from claasp.primitives import Simon

   differential = Simon(number_of_rounds=3).analysis.find_optimal_trail()
   linear = Simon(number_of_rounds=3).analysis.find_optimal_trail(kind="xor_linear")
   assert differential.trail.total_weight == 4
   assert linear.trail.total_weight == 2

The result separates the trail from the evidence used to prove it:

* ``result.trail.total_weight`` is :math:`-\log_2` of the trail probability
  (or absolute correlation for a linear trail).
* ``result.lower_bound`` is the best proved lower bound. When it equals the
  trail weight, ``result.is_optimal`` is true.
* ``result.round_transitions`` contains the values and probabilities shown by
  the default report; ``result.component_transitions`` contains the individual
  graph operations used by the detailed report.
* ``result.metadata`` records the search method, solver, version, runtime, and
  memory measurement when available.

``backend="auto"`` selects deliberately optimized dependency-free PRESENT
and Speck slices and otherwise selects generic SAT when the graph is supported.
``backend="sat"`` accepts a custom solver.  ``backend="dependency_free"``
raises a capability error when no specialized implementation exists.

The default input policy activates ``plaintext`` for a keyed block cipher,
the sole input of a permutation or function, and fixes key/tweak differences
or masks according to single-key/single-tweak semantics.  Use
``nonzero_input``, ``fixed_input_differences``, ``fixed_input_masks``, and
``fixed_inputs`` to override that policy.  Ambiguous multi-input functions
require an explicit active input.

ARX trail search
----------------

Modular-add transitions are counted exactly with a paired-carry automaton;
they are not approximated by random sampling. The graph-facing API finds the
two-round Speck32/64 optimum:

.. doctest::

   >>> from claasp.primitives import Speck
   >>> primitive = Speck(number_of_rounds=2)
   >>> result = primitive.analysis.find_optimal_trail(
   ...     kind="xor_differential", backend="dependency_free"
   ... )
   >>> (result.trail.total_weight, result.is_optimal)
   (1.0, True)
   >>> len(result.component_transitions)
   10

The ten reported transitions cover every rotation, modular addition, and XOR
on the two-round data-state path. The default search fixes the key difference
to zero, so its all-zero key schedule is omitted. An independent checker
recomputes both modular-add probabilities and the rotations/XOR wiring.
The explicit dependency-free method uses exact Matsui branch-and-bound and is
also the automatic choice for this reviewed Speck configuration. Selecting
``backend="sat"`` uses MiniSat and binary search over the maximum permitted
weight. Either backend may return a different representative when several
trails have the same minimum weight.

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

The public facade also exposes multi-round workflows. Sound
deterministic propagation is dependency-free for the supported Speck and
Simon graphs; probabilistic-truncated Speck optimization, impossible middle
boundaries, and exact S-box boomerang transitions use the CP driver and decode
through independent semantic checkers::

   boundaries = Speck(number_of_rounds=3).analysis \
       .propagate_truncated_xor_difference(
           "00000000011000000000000000000000"
       )
   assert len(boundaries.boundaries) == 4

These are capability-checked operations. An unsupported graph raises an error
that names the primitive, analysis kind, backend, and first missing semantic
rule; it is never redirected to a different primitive family's model.

Continuous diffusion
--------------------

``Analysis.continuous_evaluate`` propagates MUR2020 continuous
correlations through the typed graph. The dependency-free implementation
covers constants, structural wiring, XOR, AND, OR, NOT, modular add/subtract,
fixed and data-dependent shifts/rotations, S-boxes, binary linear maps, and
binary-extension-field mixing. It is exercised on Speck, Simon, and AES graphs. Results are explicitly
``heuristic`` and never carry SAT or optimality status. Components without a
defined continuous rule fail at the exact graph node.

Linear trail search
-------------------

Linear search uses the same graph facade and retains each LAT correlation
sign. For three-round PRESENT, the minimum trail weight is 4:

.. doctest::

   >>> from claasp.primitives import Present
   >>> result = Present(number_of_rounds=3).analysis.find_optimal_trail(kind="xor_linear")
   >>> (result.trail.total_weight, result.is_optimal)
   (4.0, True)
   >>> any(step.transition.sign == -1 for step in result.trail.steps)
   True

ARX linear masks use an exact signed carry automaton as well. The same facade
call finds a minimum-weight characteristic for four-round Speck32/64:

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
