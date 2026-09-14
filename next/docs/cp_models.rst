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
search and the legacy wordwise, probabilistic-truncated, and ARX-specialized models
remain explicitly in M10.6d.

Advanced-suite migration
------------------------

M10.6d is organized by cryptanalytic semantics rather than by the legacy class
hierarchy. Its complete model-and-fixture inventory is maintained in
``docs/architecture/cp-advanced-migration.md``. Exact ARX differential
optimization is the first implementation checkpoint, followed by generalized
truncated domains, multi-round impossible search, composed attacks, and
continuous heuristics.

Composed attacks use backend-neutral result contracts before they acquire a CP
lowering. ``BoomerangTrail`` joins two XOR-differential trails through an
explicit four-difference ``BoomerangSwitchBoundary``. A
``DifferentialLinearTrail`` keeps its differential prefix,
probabilistic-truncated connector, and linear suffix separate and reports the
legacy exact objective rather than the cheaper search approximation. Solver
status and statistical corroboration therefore remain distinct evidence.

Exact bijective switches use ``SBoxBoomerangSemantics``, which evaluates the
standard boomerang connectivity table definition exhaustively.
``SBoxBoomerangCPModel`` lowers all nonzero entries and their quartet counts;
its decoder recomputes the selected entry independently.

.. doctest::

   >>> from claasp_next.ciphers import PresentBlockCipher
   >>> from claasp_next.semantics.cryptanalysis import SBoxBoomerangSemantics
   >>> cipher = PresentBlockCipher(number_of_rounds=1)
   >>> sbox = next(item for item in cipher.components if item.component_id == "sbox_1_0")
   >>> bct = SBoxBoomerangSemantics(sbox.table)
   >>> bct.connectivity(1, 1).is_possible
   False
   >>> bct.connectivity(1, 2).count
   4
   >>> bct.connectivity(1, 2).weight
   2.0

The legacy Speck modular-add ``onlyLargeSwitch`` predicate is a separate
ARX-specific approximation, not a standard bijective S-box BCT. It remains the
next submilestone and must expose its approximation contract explicitly.

``ModularAddBoomerangSemantics`` defines that switch using quartet equations
and exhaustively counts all pairs of input words. It is intentionally limited
to widths up to eight: this is an independent correctness oracle for testing a
scalable bit automaton, not the 16-bit Speck lowering itself.

.. doctest::

   >>> from claasp_next.semantics.cryptanalysis import ModularAddBoomerangSemantics
   >>> switch = ModularAddBoomerangSemantics(4)
   >>> switch.connectivity(1, 0, 1, 0).count
   128
   >>> switch.connectivity(1, 0, 1, 0).weight
   1.0
   >>> switch.connectivity(3, 5, 7, 9).is_possible
   False

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

Probabilistic truncated addition
--------------------------------

``ProbabilisticTruncatedModularAddCPModel`` represents the legacy counter-based
partial-difference relation without hiding its fixed-point convention. A cost
of 100 represents one bit of probability weight; ``scaled_weight`` retains the
exact integral solver value and ``weight`` exposes the corresponding value in
bits. Unknown bits are members of ``TruncatedXorDifference``, not magic values
in the public API.

.. doctest::

   >>> from claasp_next.semantics.cryptanalysis import TruncatedXorDifference
   >>> from claasp_next.representations.constraints.cp import ProbabilisticTruncatedModularAddCPModel
   >>> partial = TruncatedXorDifference.parse("000?")
   >>> model = ProbabilisticTruncatedModularAddCPModel(
   ...     TruncatedXorDifference.parse("0000"),
   ...     TruncatedXorDifference.parse("0001"),
   ...     partial,
   ... )
   >>> "counter_based_probabilistic_truncated_modadd" in model.cp_model().source()
   True

Docker/Chuffed integration tests preserve the two result-bearing local legacy
fixtures with scaled costs 309 and 700. Returned carries and costs are checked
again by ``check_probabilistic_truncated_modular_add`` rather than trusted from the
solver.

``SpeckProbabilisticTruncatedCPModel`` composes that strategy using rotations
and XOR wiring read from the typed graph. Its Docker/Chuffed regressions retain
the exact legacy two-round output
``???????????????1???????????????1`` at weight 1.0 and three-round output
``???????????????0???????????????1`` at weight 0.0. The portable
``ProbabilisticTruncatedTrail`` retains every transition, while decoding checks
each addition and graph boundary independently. Wordwise propagation remains
the next separate checkpoint.

Wordwise truncated values
-------------------------

``WordwiseXorDifference`` replaces the legacy public pair of an ``active``
integer and a sentinel ``value``. Its four meanings are explicit:
``ZERO``, ``KNOWN``, ``NONZERO``, and ``UNKNOWN``. Concrete values are accepted
only for ``KNOWN`` and must be nonzero and fit the word width.

.. doctest::

   >>> from claasp_next.semantics.cryptanalysis import WordwiseDifferenceKind, WordwiseXorDifference
   >>> difference = WordwiseXorDifference.known(8, 0x53)
   >>> difference.through_bijection()
   WordwiseXorDifference(width=8, kind=<WordwiseDifferenceKind.NONZERO: 2>, value=None)
   >>> difference.xor(difference).kind is WordwiseDifferenceKind.ZERO
   True

``WordwiseDifferenceCPModel`` uses a native MiniZinc enum with the same four
names and projects solver values back to these types. It has no activity
integers or negative value sentinels. The old test asserting exactly
1,359 generated lines is superseded by semantic-invariant and Docker roundtrip
tests. The enabled legacy suite contains no fixed wordwise trail, so it is not
misrepresented as containing one.

The new, explicitly labelled v5 fixture starts with one nonzero plaintext-byte
difference and zero key difference. ``propagate_single_active_aes_byte`` reads
ShiftRows and MixColumns directly from the typed AES graph. Bijective SubBytes
preserves nonzero activity; ShiftRows selects the affected column; and the one
nonzero summand in each of its four MixColumns rows guarantees four nonzero
output bytes without assuming that unknown terms cannot cancel.

.. doctest::

   >>> from claasp_next.ciphers import AESBlockCipher
   >>> from claasp_next.semantics.cryptanalysis import propagate_single_active_aes_byte
   >>> output = propagate_single_active_aes_byte(AESBlockCipher(number_of_rounds=1), 0)
   >>> [word.kind.name for word in output]
   ['NONZERO', 'NONZERO', 'NONZERO', 'NONZERO', 'ZERO', 'ZERO', 'ZERO', 'ZERO', 'ZERO', 'ZERO', 'ZERO', 'ZERO', 'ZERO', 'ZERO', 'ZERO', 'ZERO']

Docker then projects this fixed semantic result through
``WordwiseDifferenceCPModel`` and checks that the solver cannot change any
typed boundary value.

Impossible-suite migration
--------------------------

The legacy result inventory retains the seven-round Speck UNSAT search and
the exact Simon-32/64 eleven-round input, output, and two middle-boundary
patterns. The latter requires a typed Simon cipher before its model can be
migrated honestly. Generated declaration counts are excluded. The next
checkpoint introduces a typed forward/backward contradiction boundary and
independent checker; hybrid models will use component semantic overrides
rather than a separate solver-class hierarchy.

``ImpossiblePropagationBoundary`` holds the two partial patterns and reports
only positions fixed to opposite Boolean differences; unknown values never
create a false contradiction. ``ImpossibleBoundaryCPModel`` proves that such a
position exists and decodes the solver assignment through the same typed
boundary, which is checked independently.

.. doctest::

   >>> from claasp_next.semantics.cryptanalysis import ImpossiblePropagationBoundary, TruncatedXorDifference
   >>> boundary = ImpossiblePropagationBoundary(
   ...     TruncatedXorDifference.parse("01??0"),
   ...     TruncatedXorDifference.parse("00?11"),
   ... )
   >>> boundary.contradictory_positions
   (1, 4)
   >>> boundary.is_impossible
   True

Backward ARX propagation uses ``truncated_modular_subtract`` and
``propagate_two_word_speck_inverse_round``. Both enumerate paired borrow states
in pure Python, independently of the MiniZinc boundary encoding.

``SpeckImpossibleCPModel`` composes the directional forward and inverse Speck
dataflows around a selected middle round. Its Docker/Chuffed regression
preserves the legacy Speck32/64 result: with seven rounds, a split after round
three, zero key difference, and nonzero external differences, no contradictory
deterministic-truncated middle boundary exists. The inverse dataflow is
compiled explicitly because deterministic truncated propagation is not a
reversible relation.

``SimonImpossibleCPModel`` preserves the legacy fully-automatic Simon32/64
fixture without relying on generated declaration counts. Starting from
``00000000000000000000000000000001``, six forward rounds produce
``22222222222222220222222122222202``; starting from the recorded inverse
output ``00000020200000000000000000000000``, five inverse rounds produce
``22222222002222202222222022222222``. Here ``2`` denotes unknown. The two
middle patterns contradict at bit 23. MiniZinc reproduces both patterns, while
the decoder recomputes them through independent Python semantics.

.. automodule:: claasp_next.representations.constraints.cp
   :members:

.. automodule:: claasp_next.drivers.solvers.minizinc
   :members:
