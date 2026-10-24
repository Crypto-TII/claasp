Differential trail search: advanced
===================================

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
trail. The default ``backend="auto"`` uses the reviewed solver-backed Speck
search with Kissat; select ``backend="dependency_free"`` when no external
solver should be required.

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
search.  The facade inspects unit types and components and uses the generic exact
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

``backend="auto"`` selects an exact SAT search with Kissat when the graph is
supported, including a specialized solver-backed path for reviewed Speck
configurations. ``backend="sat"`` selects the generic SAT representation and
accepts a custom solver. ``backend="dependency_free"`` explicitly selects a
reviewed implementation that needs no external solver and raises a capability
error when none exists.

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
The explicit dependency-free method uses exact Matsui branch-and-bound.
Automatic selection uses the reviewed Speck SAT adapter with Kissat; explicit
SAT selection uses the generic SAT representation. Both solver-backed paths
use binary search over the maximum permitted weight. Either backend may return
a different representative when several trails have the same minimum weight.

Differential trail enumeration
------------------------------

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
