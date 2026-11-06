Circle-differential trails: advanced
====================================

The :doc:`basic guide <basic_circle_differential>` searches a single-layer
example. This guide separates exact local transition tables, concrete round
trails and full endpoint probabilities. All numerical probabilities below fix
the key and any other inputs; they are not averages over keys.

Operations, coordinates and supported primitives
------------------------------------------------

Use ``primitive.analysis.circle_differential(bibrace=operation)`` to repeat
one operation across equal-size cells at the input and output. Omitting the
operation selects XOR. For different layouts, pass ``input_basis`` and
``output_basis`` as ``CircleBasis`` objects instead. Cells are packed with
the first cell most significant; each cell numbers bits least significant
first. Differences always use the original packed elements. In particular,
pass :math:`a`, rather than :math:`\theta(a)`, to the public probability,
trail and DDT interfaces.

The relation :math:`\theta(x\circ y)=\theta(x)\oplus\theta(y)` lets CLAASP
reuse its XOR-DDT implementation on the transformed function
:math:`\theta_{out}\circ F\circ\theta_{in}`. Here the compositions around
:math:`F` mean function composition; the bibrace coordinate maps are involutions.
DDT indices are converted back to original packed differences before returning.
The :doc:`advanced circle-linear guide <advanced_circle_linear>` describes
how ``BinaryBibrace`` constructs these coordinates.

Concrete execution supports binary words and binary extension fields, including
modular arithmetic, field multiplication/powers, variable rotations/shifts and
unrolled feedback whenever their ordinary evaluator supports them. There is no
SPN-only assumption in probability evaluation. This binary-bibrace module excludes
odd-prime fields, including prime-field arithmetization-oriented primitives.
Binary-field arithmetization is supported.

Reproduce the published four-bit differential
---------------------------------------------

Section 3.1, Figures 2–5 of `Calderini, Civino and Invernizzi (2024)
<https://doi.org/10.1515/jmc-2023-0030>`_ specifies the operation and S-box below.
**Differential uniformity** is the largest DDT count over nonzero input
differences. This example has XOR uniformity 4 and circle uniformity 16.

.. doctest::

   >>> from claasp.primitives import BitVectorSBox
   >>> from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace, CircleBasis
   >>> table = (0, 14, 11, 1, 7, 12, 9, 6, 13, 3, 4, 15, 2, 8, 10, 5)
   >>> operation = BinaryBibrace(4, ((0, 0, 8, 4),), (1,))
   >>> primitive = BitVectorSBox(4, table)
   >>> circle = primitive.analysis.circle_differential(bibrace=operation, input_name="input")
   >>> ordinary = primitive.analysis.circle_differential(input_name="input")
   >>> ddt = circle.lookup_semantics().difference_distribution_table()
   >>> xor_ddt = ordinary.lookup_semantics().difference_distribution_table()
   >>> max(max(row) for row in xor_ddt[1:]), max(max(row) for row in ddt[1:])
   (4, 16)
   >>> ddt[7][6], circle.probability(7, 6).probability
   (16, Fraction(1, 1))
   >>> best = circle.best_differential()
   >>> best.probability, best.complete
   (Fraction(1, 1), True)

``best_differential()`` searches all nonzero input differences and all output
differences in the bounded full DDT. Output difference zero remains eligible,
which matters for nonpermutations. Ties select the smallest input difference,
then the smallest output difference. ``lookup_semantics()`` evaluates the graph
once per input and retains a complete truth table; no primitive-specific
transition implementation is used.

Changing the operation changes the experiment. For example, XOR can be selected
explicitly with ``BinaryBibrace(4)``. A different valid ``BinaryBibrace`` can be
passed in the same way. The finite operation-family comparison recipe in
:doc:`advanced_circle_linear` can also be used with ``best_differential()``;
compare probabilities instead of absolute correlations, keeping the same
primitive and fixed inputs throughout. This is a bounded comparison of supplied
operations, not a built-in global operation optimiser.

Tested catalogue configurations
--------------------------------

The following reduced-round configurations are covered by regression tests
using the generic scalar engine and the four-bit operation defined above.
All keys and tweaks are fixed to zero. These checks establish that circle
pair generation, evaluation and probability verification work on the listed
graphs. Assessing a useful distinguisher requires a suitable operation and
sufficient evidence for its probability at the target round count.

.. list-table:: Tested circle-differential experiments
   :header-rows: 1
   :widths: 45 20 35

   * - Configuration
     - Domain
     - Verification performed
   * - ``ToySpeck(number_of_rounds=2)``
     - 8-bit inputs
     - Complete endpoint enumeration and concrete-trail search/checking.
   * - ``ToyAES(number_of_rounds=2, word_size=2, state_size=2)``
     - 8-bit inputs; two-bit field elements
     - Complete endpoint enumeration and concrete-trail search/checking.
   * - ``AES(number_of_rounds=2)``
     - 128-bit inputs
     - Seeded endpoint sampling, including binary-field diffusion.
   * - ``Present(number_of_rounds=2)``
     - 64-bit inputs
     - Seeded endpoint sampling through its S-box and bit-permutation layers.
   * - ``Craft(number_of_rounds=2)``
     - 64-bit inputs
     - Seeded endpoint sampling with both key and tweak fixed.
   * - ``Speck(number_of_rounds=2)``
     - 32-bit inputs
     - Seeded endpoint sampling through modular addition and rotations.
   * - ``Simon(number_of_rounds=2)``
     - 32-bit inputs
     - Seeded endpoint sampling through AND, XOR and rotations.

The sampling tests use input difference seven, 64 pairs and seed 17. Each
output difference is defined before sampling, using the output of the fixed
pilot pair :math:`(0,7)`. Observed counts are checked against an independent
packed-bit implementation of the circle operation around ordinary primitive
evaluations. The small-domain tests enumerate all 256 initial inputs and check
both the endpoint counts and the selected trail's probability.

For example, the two-round ToySpeck experiment has endpoint probability
:math:`1/32` for :math:`7\to\mathtt{0x13}`; its best concrete trail with
those endpoints has probability :math:`1/128`:

.. doctest::

   >>> from claasp.primitives import ToySpeck
   >>> toy = ToySpeck(number_of_rounds=2)
   >>> endpoint = toy.analysis.circle_differential(bibrace=operation).probability(
   ...     7, 0x13, fixed_inputs={"key": 0})
   >>> trail = toy.analysis.find_lowest_weight_circle_differential_trail(
   ...     bibrace=operation, input_difference=7, output_difference=0x13,
   ...     fixed_inputs={"key": 0})
   >>> endpoint.probability, trail.probability, trail.differences
   (Fraction(1, 32), Fraction(1, 128), (7, 228, 19))

Scope of the published reproduction
-----------------------------------

The four-bit experiment above reproduces both complete DDTs in Figures 4 and 5
of the 2024 paper, including the XOR/circle uniformities 4 and 16 and the
probability-one circle differential :math:`7\to6`. It constructs an ordinary
``BitVectorSBox`` graph and uses the generic evaluator and transition semantics.
Regression fixtures record all 512 table entries and their source, and compare
them with the computed tables.

Section 3.2 of that paper reports experiments on a different, specially
constructed 16-bit SPN, averaging over random long keys. The catalogue coverage
tests above do not reproduce that multiround experiment. Reproducing it would
require constructing the paper's diffusion layer and long-key rounds, then
running the prescribed key-averaged campaign. The fixed-input module can supply
the per-key measurements; the averaging and search campaign must be run
explicitly.

Concrete multiround trail search
--------------------------------

The following small SPN publishes its real round outputs. The same key is
reused in every round. CLAASP records pairs through the standard evaluator,
including every S-box and XOR key addition.

.. doctest::

   >>> from claasp import PrimitiveBuilder, UnitArrayType
   >>> from claasp.components import SBox, Xor
   >>> from claasp.unit_types import Word
   >>> state_type = UnitArrayType(Word(4), (1,))
   >>> builder = PrimitiveBuilder("small_spn", {"plaintext": state_type, "key": state_type})
   >>> state, key = builder.input("plaintext"), builder.input("key")
   >>> for _ in range(3):
   ...     _ = builder.add_round()
   ...     state = builder.add_component(SBox(state, table))
   ...     state = builder.add_component(Xor((state, key)))
   ...     _ = builder.set_round_output(state)
   >>> spn = builder.build(state)
   >>> analysis = spn.analysis.circle_differential(bibrace=operation)
   >>> trail = spn.analysis.find_lowest_weight_circle_differential_trail(
   ...     bibrace=operation, input_difference=7, fixed_inputs={"key": 0})
   >>> trail.boundary_labels
   ('input', 'round 1', 'round 2', 'output')
   >>> len(trail.differences), trail.searched, trail.evidence.complete
   (4, True, True)
   >>> checked = analysis.trail_probability(trail.differences, fixed_inputs={"key": 0})
   >>> checked.probability == trail.probability
   True
   >>> trail.to_terminal()
   ... # doctest: +SKIP
   >>> trail.plot(show=False)
   ... # doctest: +SKIP

``find_lowest_weight_circle_differential_trail(input_difference=a,
output_difference=b, ...)`` can also constrain the final output difference. With
``b`` omitted it searches all observed endpoint differences for that input.
It returns ``None`` if a constrained endpoint has no actual pair. Optimality
covers the declared observations, fixed inputs and supplied input difference;
it does not optimise over input differences or operations. Ties use the
lexicographically smallest difference sequence.

For repeated experiments, ``analysis.best_trail(a, b, ...)`` exposes the same
search on the configured circle-differential analysis object.

The input and final output are always retained. Published intermediate round
outputs are used automatically, with their genuine round numbers; a final
round boundary identical to the output is not duplicated. Without published
round outputs, only endpoint histories are searched. To choose observations
explicitly, pass ``boundaries=(selection, ...)``. These replace the intermediate
round observations; ``boundaries=()`` requests endpoints alone. Pass a matching
``boundary_bases`` tuple when those selections need different operations or
cell layouts. For example, a single four-bit selection can use
``boundary_bases=(CircleBasis((operation,)),)``. Observations may be partial
states; the resulting event then specifies only those observations, not every
internal difference.

What the probabilities mean
---------------------------

A **concrete trail** here is the event that actual executions match every
retained boundary difference. Its probability can differ from the product of
standalone local DDT probabilities. A key schedule and repeated round keys
can introduce dependencies; intermediate states conditioned on previous
transitions need not be uniform.

``prefix_counts[i]`` counts initial inputs satisfying all observations through
boundary ``i``. The relative probability is the ratio of successive counts,
conditioned on the entire preceding prefix; their product equals the measured
concrete trail probability by the probability chain rule. These factors must
not be substituted for a reusable local transition DDT. After an empty prefix,
a later conditional probability is undefined and reported as such.

The endpoint differential combines the disjoint concrete trails with matching
endpoints. Their probabilities add to give the endpoint differential
probability.

Budgets and large primitives
----------------------------

``probability()``, ``lookup_semantics()``, ``best_trail()`` and exact
``trail_probability()`` check ``maximum_inputs`` before concrete evaluation.
``best_differential()`` and DDT construction check ``maximum_entries`` before
allocation. The latter conservatively bounds both the dense table size
:math:`2^{n+m}` and the pair-counting work :math:`2^{2n}` for input/output
widths :math:`n,m`. The shared XOR-DDT implementation additionally limits
dense tables to :math:`2^{20}` entries.

Exact methods therefore suit small primitives or reduced experiments; they
are not a solver-based local characteristic search. Use
``estimate_probability()`` or ``trail_probability(..., samples=...)`` on larger
primitive domains. They verify a prespecified event and report sampling evidence,
rather than certifying a global optimum. See :doc:`verification_circle_differential`.

Future work
-----------

Scalable SAT, SMT, MILP and CP circle-differential characteristic search is
left for future work. It requires circle-specific transition constraints within
the shared propagation infrastructure, explicit operation layouts and key
assumptions, and validation against concrete execution. The current bounded
enumeration and verification methods provide small-domain reference results
for checking those future models.
