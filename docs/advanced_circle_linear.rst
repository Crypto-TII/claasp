Circle-linear trails: advanced
==============================

The :doc:`basic_circle_linear` guide covers a basic trail search.
:doc:`verification_circle_linear` covers characteristic reconstruction and
endpoint correlation evaluation. This advanced guide defines the terminology,
explores parameters and checks numerical CRAFT results.

Use ``primitive.analysis.find_lowest_weight_circle_linear_trail(...)`` for
the standard search-and-report workflow, following the XOR trail-query naming.
For model inspection and supplied-mask trails, construct
``primitive.analysis.circle_linear_trail_model(...)`` explicitly. The default
query uses that restricted model. General solver search, described below,
uses a coordinate transformation and the ordinary XOR trail engine.

General characteristic search
-----------------------------

Select ``backend="sat"``, ``"smt"`` or ``"milp"`` to search an exact
circle-coordinate component graph. For fixed auxiliary inputs, it computes
:math:`G=\theta_{out}\circ E\circ\theta_{in}`. Circle-linear masks on the
original primitive are ordinary linear masks on :math:`G`. CLAASP rewrites
the graph using ``GraphPropagation`` and reuses the existing XOR optimizer,
component relations, independent characteristic checker, solver drivers and
trail presentation. The existing primitive graph supplies all component behavior.

This path accepts different S-boxes in different rounds, bit permutations,
general binary affine layers, Feistel wiring and nonlinear key schedules,
subject to the existing XOR backend's component capabilities. Every auxiliary
input, including the complete key and tweak if present, must have an explicit
value. The real schedule is evaluated at those inputs; its round keys are
never assumed independent. Binary extension-field encodings are accepted;
odd-prime fields do not define the binary operations used here.

For example, the four-bit CRAFT lookup can be searched outside the perfect
subgroup, including a check whose best absolute correlation is only 1/2:

.. doctest::

   >>> from claasp.primitives import BitVectorSBox
   >>> from claasp.primitives.block_ciphers.craft import CRAFT_SBOX
   >>> from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace
   >>> operation = BinaryBibrace(4, ((8, 0, 8, 5),), (5,))
   >>> primitive = BitVectorSBox(4, CRAFT_SBOX)
   >>> result = primitive.analysis.find_lowest_weight_circle_linear_trail(
   ...     bibrace=operation, input_name="input", input_mask=1, backend="sat")
   >>> result.weight, result.is_optimal
   (1.0, True)
   >>> abs(result.evaluate_endpoint())
   Fraction(1, 2)

Use ``result.to_terminal()`` and ``result.plot()`` as with XOR trails.
``result.coordinates.primitive`` retains the derived graph, and
``result.search_result`` retains the ordinary checked solver result. Its
internal masks belong to that graph. Endpoint masks remain circle character
labels. ``input_basis`` and ``output_basis`` accept different ``CircleBasis``
layouts when ``bibrace`` is omitted.

Matching S-boxes are conjugated as whole lookup tables, preserving their exact
circle-LATs. Inverse coordinate changes cancel through structural wiring;
orphan changes are pruned before search. Small coordinate maps use lookup
tables; larger maps use quadratic Boolean circuits. General diffusion stays
in its existing graph representation. Consequently this is an optimum for
the **derived component decomposition**, not necessarily the best decomposition
or full-round circle correlation. Splitting a function into components can
introduce multiple trails whose signed contributions must be summed.

The weight is :math:`-\log_2|C_{trail}|`, as in ordinary XOR-linear search.
``result.evaluate_endpoint()`` evaluates the original primitive exactly under
the usual finite input budget; ``samples=...`` instead gives seeded sampling
evidence. Neither a small weight nor successful fixed-key verification proves
an improved key-recovery attack. Key coverage, the endpoint correlation, outer
round extension, dependent key guesses and total data/time/memory costs still
need an analysis of the chosen primitive.

The operation used in the introductory example
----------------------------------------------

.. include:: _includes/craft_circle_operation.txt

Different choices of operation define different analyses of the same
primitive. The operation is a parameter of the analysis; each call to ``search()``
keeps this parameter fixed.

What is a character?
--------------------

In ordinary linear analysis, a **mask** selects some bits and XORs them
together. This gives their **parity**: zero for an even number of selected
one-bits, one for an odd number. For example, the mask ``0101`` selects bits
0 and 2, so its check on ``1101`` is :math:`1\oplus1=0`.

A **character** is a parity-like check compatible with the chosen addition.
CLAASP represents it as a one-bit function :math:`\ell` satisfying

.. math::

   \ell(x\circ y)=\ell(x)\oplus\ell(y).

Mathematically, the character itself is the sign :math:`(-1)^{\ell(x)}`;
``character(label, value)`` returns the bit :math:`\ell(value)`. For XOR,
these checks are the usual parities of selected bits. For the alternative
addition, some also contain products (ANDs) of pairs of bits; such checks
are called **quadratic**. They can reveal relationships ordinary XOR masks miss.
The **label** is the integer identifying which check to use.

The **correlation** between two checks is the fraction of inputs on which
they agree minus the fraction on which they disagree. A correlation of 1
means always equal, -1 means always opposite, and 0 means agreement on
exactly half the inputs. A relation with correlation 1 or -1 is **perfect**.
Its **magnitude** is its absolute value, so both 1 and -1 have magnitude 1.

A **trail** specifies the checks followed through successive layers. All
trails with the same input/output checks form a **linear hull**: their
signed contributions sum to the actual endpoint correlation. A **weak-key
class** is the set of keys on which the selected trail contributes. The
**tweak** is a public input selecting an encryption variant.

Choose a basis and a cell layout
--------------------------------

A **basis of characters** is the complete set of compatible bit checks
available for an addition. Their sign functions form a basis: weighted sums
of them can express any real-valued function on the input domain. A **cell
layout** specifies which chunks of the packed state use each bibrace.
``BinaryBibrace`` represents binary bibraces of **nilpotency class at most
two**. The **correction product** is the extra term added to XOR in the
expression below. It can be nonzero, but applying that product again to its
result and another value always gives zero. Their sum is

.. math::

   x\circ y=x\oplus y\oplus\sum_j\psi_j(x,y)b_j.

Here :math:`\psi_j` is a **bilinear form**: a one-bit function that respects
XOR in each argument separately. **Alternating** means
:math:`\psi_j(x,x)=0`. The **radical** of a form is the set of values
:math:`r` for which :math:`\psi_j(r,y)=0` for every :math:`y`. The vectors
:math:`b_j` must lie in every form's radical and must be linearly
independent (no nonempty XOR of them is zero).

The common radical is also called the **annihilator**: the correction
product vanishes whenever one argument belongs to it. ``annihilator_basis``
returns independent vectors whose XOR combinations generate that set.

The constructor validates these properties and builds an **involution**
:math:`\theta`, a change of coordinates that undoes itself when applied
twice. The checks are :math:`\ell_u(x)=\langle u,\theta(x)\rangle`, where
the brackets mean the parity of the bits selected by :math:`u`. A
**quadratic refinement** is a function :math:`Q` with :math:`Q(x\oplus
y)=Q(x)\oplus Q(y)\oplus\psi(x,y)`. The constructor adjusts these functions
to return zero on all correction outputs when needed. Higher-rank products
can produce outputs spanning more than one independent direction
:math:`b_j`.

.. doctest::

   >>> from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace, CircleBasis
   >>> brace = BinaryBibrace(4, ((8, 0, 8, 5),), (5,))
   >>> brace.annihilator_basis
   (2, 5)
   >>> brace.forms, brace.outputs
   (((8, 0, 8, 5),), (5,))
   >>> higher_rank = BinaryBibrace(
   ...     6, ((2, 1, 0, 0, 0, 0), (0, 0, 8, 4, 0, 0)), (16, 32))
   >>> basis = CircleBasis((brace, higher_rank))
   >>> basis.width
   10

Form row ``i`` is a packed mask with bit 0 the least significant bit (LSB).
In a parallel basis (one bibrace per cell) the **first cell occupies the
most significant bits**. Cell layouts are explicit: do not reinterpret a
nibble-based operation as a byte-based one. An empty list of forms,
``BinaryBibrace(width)``, gives ordinary XOR characters and is useful as an
independent control.

Select a different operation
-----------------------------

Use ``BinaryBibrace(width)`` for ordinary XOR, or supply validated bilinear
forms and correction outputs, as in the introductory example. For example, the
following custom four-bit addition is
:math:`x\circ y=x\oplus y\oplus(x_0y_1\oplus x_1y_0)(0100)_2`:

.. doctest::

   >>> xor_operation = BinaryBibrace(4)
   >>> custom_operation = BinaryBibrace(4, ((2, 1, 0, 0),), (4,))
   >>> xor_operation.circle(1, 2), custom_operation.circle(1, 2)
   (3, 7)
   >>> from claasp.primitives import BitVectorSBox
   >>> from claasp.primitives.block_ciphers.craft import CRAFT_SBOX
   >>> sbox_primitive = BitVectorSBox(4, CRAFT_SBOX)
   >>> custom_analysis = sbox_primitive.analysis.circle_linear(
   ...     input_name="input", bibrace=custom_operation)
   >>> custom_analysis.best_approximation().coefficient
   Fraction(-3, 4)

For trail search, pass the selected operation as
``primitive.analysis.circle_linear_trail_model(bibrace=operation, ...)``.
Every supplied operation is validated. The endpoint tools support the valid
binary bibraces represented by this API; the current optimised trail backend
additionally requires its perfect-subgroup structure. An operation rejected
by that backend can still be evaluated with the endpoint tools.

Compare operations with a stated objective
------------------------------------------

``best_approximation()`` optimises endpoint masks for a fixed operation;
``search()`` optimises a trail within a fixed operation's reported subgroup.
There is currently no built-in unrestricted optimiser over operations.
A finite comparison can be automated by calling these methods for each
candidate and ranking their results.

Specify the candidate family, cell layout, primitive, rounds and key/tweak
setting before interpreting a winner. Two useful objectives are the largest
absolute endpoint correlation and the lowest supported trail weight. They
measure different quantities; a strong local S-box correlation alone does
not determine a strong multi-round trail. Key-class size can also matter.

The following generator enumerates the 105 nontrivial four-bit operations
with one nonzero alternating bilinear form and one nonzero correction vector
in its radical. Adding ordinary XOR gives 106 candidates. This is an explicit
candidate family, not a search over every possible addition or cell layout:

.. doctest::

   >>> from itertools import combinations
   >>> def four_bit_operations():
   ...     yield BinaryBibrace(4)
   ...     pairs = tuple(combinations(range(4), 2))
   ...     for code in range(1, 1 << len(pairs)):
   ...         rows = [0] * 4
   ...         for bit, (i, j) in enumerate(pairs):
   ...             if code >> bit & 1:
   ...                 rows[i] |= 1 << j
   ...                 rows[j] |= 1 << i
   ...         for output in range(1, 16):
   ...             if all((row & output).bit_count() % 2 == 0 for row in rows):
   ...                 yield BinaryBibrace(4, (tuple(rows),), (output,))
   >>> operations = list(four_bit_operations())
   >>> len(operations)
   106

For the strongest exact endpoint relation on the four-bit S-box, ask CLAASP
to optimise the nonzero input/output masks for each operation, then choose
the largest magnitude. All input values are enumerated:

.. doctest::

   >>> endpoint_results = [
   ...     (operation, sbox_primitive.analysis.circle_linear(
   ...         input_name="input", bibrace=operation).best_approximation())
   ...     for operation in operations]
   >>> selected_operation, selected_approximation = max(
   ...     endpoint_results, key=lambda item: abs(item[1].coefficient))
   >>> abs(selected_approximation.coefficient)
   Fraction(1, 1)
   >>> selected_operation.forms, selected_operation.outputs
   (((4, 0, 1, 0),), (2,))
   >>> (selected_approximation.input_mask, selected_approximation.output_mask,
   ...  selected_approximation.coefficient)
   (5, 11, Fraction(-1, 1))

This selected addition is
:math:`x\circ y=x\oplus y\oplus(x_0y_2\oplus x_2y_0)(0010)_2`.
It attains a perfect S-box relation. Ties are possible; the code returns the
first maximiser in the declared enumeration order.

For eight-round CRAFT, compare the operations accepted by the current trail
backend instead. Keep the public tweak at zero, minimise the reported trail
weight, and use the largest satisfying key class to break weight ties.
Retain rejection reasons so that the accepted search space stays explicit:

.. doctest::

   >>> from claasp.primitives import Craft
   >>> craft_for_operations = Craft(number_of_rounds=8)
   >>> compatible_models, rejected_operations = [], []
   >>> for operation in operations:
   ...     try:
   ...         model = craft_for_operations.analysis.circle_linear_trail_model(
   ...             bibrace=operation, fixed_inputs={"tweak": 0})
   ...     except ValueError as error:
   ...         rejected_operations.append((operation, str(error)))
   ...     else:
   ...         compatible_models.append((operation, model))
   >>> len(compatible_models), len(rejected_operations)
   (2, 104)
   >>> trail_results = [(operation, model.search())
   ...                  for operation, model in compatible_models]
   >>> selected_trail_operation, selected_trail_result = min(
   ...     trail_results,
   ...     key=lambda item: (item[1].cost,
   ...                       -item[1].representative.conditions.key_count,
   ...                       item[0].forms, item[0].outputs))
   >>> selected_trail_result.cost
   8
   >>> selected_trail_result.representative.conditions.key_count == 2**120
   True
   >>> selected_trail_operation == BinaryBibrace(4, ((8, 0, 8, 5),), (5,))
   True

Both accepted operations have weight 8 and a satisfying key class of size
:math:`2^{120}`. The final form/output ordering chooses one reproducibly.
The result is optimal among the accepted candidates' reported subgroup
trails under this objective and setting. Rejection means that an operation
is unsupported by this backend, rather than cryptanalytically unhelpful.
A search budget failure or an unresolved key-class case must be resolved
before making the comparison; the code lets search failures propagate.
Different round counts, key criteria, candidate families or layouts require
a new comparison. Endpoint correlation evaluation remains separate from
this trail-weight comparison.

Analyze another binary primitive
--------------------------------

The ``primitive.analysis.circle_linear(...)`` interface evaluates the actual
primitive on input values. Exact endpoint sums, bounded endpoint
optimization and seeded measurements therefore apply to any supported binary
graph, including modular arithmetic and finite unrolled feedback. An
**LFSR** is a linear-feedback shift register; its finite sequence of updates
can be represented as a graph and measured here. There is no primitive-name
filter. Variable-control operations are measurable when the concrete
evaluator supports them; there is no dedicated symbolic carry/control search
backend.

Fix every nonvarying input, including public tweaks. The varying input must
be public; keys are never silently averaged.

.. doctest::

   >>> from claasp.primitives.single_component_primitives import ModularAdd
   >>> primitive = ModularAdd(word_bit_size=4)
   >>> names = tuple(primitive.graph.input_arrays)
   >>> analysis = primitive.analysis.circle_linear(
   ...     input_name=names[0], bibrace=brace)
   >>> analysis.correlation(9, 9, fixed_inputs={names[1]: 0})
   Fraction(1, 1)
   >>> best = analysis.best_approximation(fixed_inputs={names[1]: 1})
   >>> best.complete
   True

For heterogeneous layouts (different bibraces or cell sizes) pass
``input_basis`` and ``output_basis`` instead of ``bibrace``. Both must
exactly match their packed boundary widths. ``correlation`` enumerates the
complete varying-input domain, with a default budget of :math:`2^{16}`
inputs. ``best_approximation`` evaluates a complete endpoint linear
approximation table (**LAT**), which lists correlations for all pairs of
input and output checks, under an explicit entry budget. Both reject
oversized work before evaluating the primitive. They do not claim internal
trail optimality.

Large binary-extension-field primitives may be measured in the same way. For
symbolic work (manipulating equations rather than enumerating inputs), field
addition and constant multiplication are binary **affine** maps: a linear
bit transformation, optionally followed by XOR with a fixed constant;
variable multiplication and nonlinear power maps need small exact tables or
future specialized search methods. Primitives over fields of odd-prime size
are explicitly rejected: their valid domains are not binary vector spaces,
and padding their encodings does not define the required group.

Measure an endpoint correlation with uncertainty
------------------------------------------------

.. doctest::

   >>> estimate = analysis.estimate_correlation(
   ...     9, 9, fixed_inputs={names[1]: 0}, samples=1024, seed=17)
   >>> estimate.value, estimate.samples, estimate.seed, estimate.complete
   (1.0, 1024, 17, False)
   >>> estimate.lower < 1 <= estimate.upper
   True

Sampling is uniform with replacement: each input is drawn independently, so
a value can appear more than once. The **seed** makes the random sequence
reproducible. ``standard_error`` estimates sampling variability from the
observed results. ``lower`` and ``upper`` give a **Hoeffding confidence
interval**, a conservative uncertainty bound that needs no assumption about
the shape of the observations' distribution. Across repeated runs, such
intervals cover the true correlation with at least the requested probability
(default 0.95).

The interval has nonzero width even when all sampled checks agree or all
disagree. To distinguish a correlation of magnitude :math:`c` from zero
generally requires order :math:`c^{-2}` samples. In the usual terminology, **bias** is
agreement probability minus one half, so it equals half the correlation.
Very small long-round correlations are too expensive to validate by this
sampling approach.

Report and plot retained results
--------------------------------

Every endpoint result supports ``to_terminal()`` and ``plot()``. For an
estimate, the plot converts the measured correlation to agreement and
disagreement probabilities and retains the Hoeffding confidence intervals.

.. doctest::

   >>> from io import StringIO
   >>> output = StringIO()
   >>> estimate.to_terminal(file=output)
   >>> "Empirical" in output.getvalue()
   True

.. code-block:: python

   figure = estimate.plot(show=False, save_to="endpoint-estimate.png")

A subgroup search result and its selected ``representative`` both provide
these methods. ``to_terminal(details=True)`` adds the round profile;
``plot()`` shows relative and cumulative trail weights. ``CircleNetwork``'s
``best_trail`` returns a ``CircleTrail`` with the same reporting methods,
using layers rather than rounds on the horizontal axis. Plotting needs the
optional ``presentation`` extra and never repeats an analysis or search.
A zero local coefficient has infinite weight and cannot be shown as a finite
weight profile; a subgroup trail with an empty key class is also rejected
by the weight plot.

Generic affine diffusion and weak-key classes
---------------------------------------------

``CircleAffineLayer`` groups a binary affine operation and its following
key/constant addition:

.. math::

   y=Ax\oplus Bk\oplus c.

Substituting the quadratic checks gives a quadratic expression in the state
and key bits. A **quadratic Gauss sum** is the signed average of
:math:`(-1)` raised to that expression over all state values. It can be
computed exactly using binary linear algebra. The associated form's radical
determines the linear parity equations that the key must satisfy. No dense
state transition table is necessary. Maps may have different input and
output widths (**rectangular**) or lose information (**noninvertible**).
Different boundary cell layouts are allowed. Grouping diffusion with key
addition avoids imposing unnecessary per-cell key conditions.

.. doctest::

   >>> from claasp.semantics.cryptanalysis.circle_linear import (
   ...     CircleAffineLayer, AffineKeyConditions)
   >>> cell = CircleBasis((brace,))
   >>> addition = CircleAffineLayer(cell, cell, (1, 2, 4, 8),
   ...     key_width=4, key_rows=(1, 2, 4, 8))
   >>> transition = addition.transition(1, 1)
   >>> transition.conditions.key_count
   4
   >>> transition.coefficient(0), transition.coefficient(1)
   (Fraction(1, 1), Fraction(0, 1))

Affine row ``i`` produces output bit ``i``, in **LSB order**. ``key_rows``
use one shared packed key coordinate system across layers. ``conditions``
describe exactly which keys make the local coefficient nonzero; the sign is
still key dependent. Intersect conditions across layers to obtain a selected
trail's survival class. Contradictory equations give an empty class.

A **key schedule** derives round keys from the master key. To express
round-key conditions in master-key coordinates, **pull them back**, meaning
substitute the schedule's equations into the conditions:

.. doctest::

   >>> independent = AffineKeyConditions(2, ((3, 0),))
   >>> repeated = independent.pullback((1, 1), master_width=1)
   >>> repeated.key_count
   2
   >>> independent.pullback((1, 1), master_width=1, offset=1).key_count
   0

This does not solve nonlinear key schedules. Their master-key conditions
require another constraint representation and potentially **model
counting**, which counts assignments satisfying those constraints. For a
joint key/tweak system, ``conditions.project(tweak_bit_positions)``
eliminates the master-key variables by keeping each tweak for which at least
one master key satisfies the original conditions. This is called
**existential elimination** and gives the exact admissible-tweak class. It
does not fix the eliminated key bits to zero.

Complete small hulls and general trail search
---------------------------------------------

A **truth table** lists a function's output for every possible input. Use
``CircleLookupLayer`` for a complete small truth table. A grouped primitive
can provide one with ``analysis.lookup_layer(fixed_inputs=...)``. Compose
lookup and affine layers with ``CircleNetwork``. Adjacent bases must agree
exactly. ``best_trail`` maximizes a trail's absolute coefficient over all
intermediate masks; ``correlation`` sums all signed trails.

.. doctest::

   >>> from claasp.semantics.cryptanalysis.circle_linear import CircleLookupLayer, CircleNetwork
   >>> ordinary = CircleBasis((BinaryBibrace(3),))
   >>> involution = CircleLookupLayer(ordinary, ordinary, (0, 1, 2, 3, 4, 5, 7, 6))
   >>> network = CircleNetwork((involution, involution))
   >>> network.best_trail(1, 3).coefficient != 0
   True
   >>> network.correlation(1, 3)
   Fraction(0, 1)

The nonzero trail cancels in the full hull. This is why a reported trail
weight must not be turned directly into a guaranteed distinguisher bias.
Network search and hull sums have a conservative ``maximum_entries`` budget
checked before computation starts. These exact methods are intended for
small networks and validation, not dense whole-state searches on 64-bit
primitives.

Check CRAFT results and transfer the optimized search
-----------------------------------------------------

An **SPN** (substitution-permutation network) combines S-box substitutions
with layers that mix or rearrange cells. The ``CircleLinearTrailModel`` backend is
primitive independent. It accepts a supplied S-box, cell-XOR diffusion, cell
permutation, round count and optional grouped affine key/constant layers. It
checks the four-element perfect subgroup and its **type flip**: an S-box
transition exchanging a linear check (**flat**) with a quadratic one
(**curved**). S-boxes without that structure are rejected by this backend;
they remain usable in general lookup and network analysis. The
**mask-displacement space** contains the linear checks that diffusion or key
addition can add to the selected masks. The backend verifies that only its
zero element belongs to the selected subgroup. Otherwise an additional
propagation path (a **branch**) could remain inside the subgroup, and
following one mask sequence would not search it completely.

For a compatible CLAASP primitive, derive this representation directly from
its graph instead of supplying a second description of its rounds:

.. doctest::

   >>> from claasp.primitives import Craft
   >>> from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace
   >>> primitive = Craft(number_of_rounds=8)
   >>> model = primitive.analysis.circle_linear_trail_model(
   ...     bibrace=BinaryBibrace(4, ((8, 0, 8, 5),), (5,)), fixed_inputs={"tweak": 0})
   >>> model.trail(0x01190000).cost
   8

This adapter uses the shared graph propagation runner. It derives binary
affine state maps, affine master-key expressions, fixed public-input offsets,
S-box tables and published round boundaries from the actual operations.
It accepts bit and word layouts, including parallel S-box components and
structural bit/word conversions. It requires a complete substitution layer
at each round boundary, affine key handling, and the same cell-XOR diffusion
and cell permutation in each round. A nonlinear key schedule, bit-mixing
diffusion or another unsupported structure raises an explicit capability
error. The bibrace and the public inputs to fix must be supplied explicitly;
secret inputs remain symbolic. The convenience method
``Craft(...).circle_linear_trail_model(tweak=...)`` delegates to this adapter.

Each cell's check is written :math:`q\gamma\oplus s\eta`, with
:math:`q,s\in\{0,1\}`. Here :math:`\gamma` is a curved check preserved by
the S-box, and :math:`\eta` is the flat check exchanged with
:math:`\gamma\oplus\eta`. For CRAFT their labels are 9 and 7, respectively.
For a state of :math:`n` cells, :math:`q` and :math:`s` collect these bits
into two vectors of length :math:`n`.

The backward spatial map, which propagates masks through cell mixing and
permutation, acts identically on both mask coordinates. It **commutes** with
the type flip, meaning the two operations give the same result in either
order. Thus the cost separates into functions of :math:`q` and
:math:`q\oplus s`. Two :math:`2^n` enumerations certify the whole
:math:`2^{2n}` subgroup search. Zero-cost nonzero masks are included. The
default factor-state budget is :math:`2^{16}`. Affine key conditions are
checked at every candidate weight; if an entire level is infeasible, search
continues to higher levels. Exhausting the candidate budget raises an error
instead of asserting an optimum.

For larger cell counts, call ``model.search(backend="sat")`` or select
``backend="perfect_subgroup_sat"`` in the analysis query. Shared Boolean gates
and cardinality constraints encode mask propagation and local column ranks,
without the global :math:`2^n` arrays. Each decoded mask is checked using the
same exact affine master-key conditions; an inconsistent candidate is blocked
and search continues. ``maximum_candidates`` bounds this refinement, and
``maximum_factor_states`` bounds each column's rank table. A large connected
diffusion block can still exceed that local table budget.

The SAT path proves one optimum in the same subgroup. It does not enumerate
all tied masks, so ``optimal_mask_count`` is ``None`` and the selected key
class is not claimed largest among ties. The enumeration path retains that
tie-breaking rule. Regressions compare both paths on small SPNs and exercise
a 32-cell SPN that exceeds the enumeration budget.

.. doctest::

   >>> from claasp.primitives import Craft
   >>> result = Craft(number_of_rounds=14).circle_linear_trail_model().search()
   >>> result.cost, result.optimal_mask_count
   (22, 16)
   >>> result.representative.conditions.key_count == 2**108
   True
   >>> result.complete, result.scope
   (True, 'four-element perfect subgroup')

The following executable regression cases record the search results. Counts
and key classes are checked by pytest, independently of a hard-coded CRAFT
cost formula.

.. TODO: Add a public reference for the CRAFT-specific regression cases when available.

.. list-table:: Exact subgroup search regressions
   :header-rows: 1

   * - Rounds
     - Trail weight
     - Optimal masks
     - Largest weak-key class
   * - 8
     - 8
     - 24
     - :math:`2^{120}`
   * - 10
     - 12
     - 16
     - :math:`2^{118}`
   * - 12
     - 18
     - 16
     - :math:`2^{116}`
   * - 14
     - 22
     - 16
     - :math:`2^{108}`
   * - 16
     - 26
     - 32
     - :math:`2^{110}`
   * - 18
     - 32
     - 32
     - :math:`2^{110}`

CRAFT's ``round_offset`` keeps genuine absolute constants and key parity.
``circle_linear_trail_model(tweak=...)`` fixes the public tweak and derives affine
conditions. Its optimized backend excludes the special final round 31, which
omits the S-box and permutation; the concrete primitive and endpoint
measurements support the full CRAFT block cipher. The model's mask codes use
this convention: q in the low sixteen bits, s in the high sixteen, bit i for
cell i. Use ``input_mask`` and ``output_mask`` for packed character labels;
do not pass these coordinate codes to endpoint measurement methods.

Public background and interpretation
------------------------------------

See :doc:`circle_linear` for the published origins of alternative-operation
cryptanalysis. The following references explain the linear framework, the
bibrace structures and the concrete primitive.

* Tim Beyne, `A Geometric Approach to Linear Cryptanalysis
  <https://eprint.iacr.org/2021/1247>`_, ASIACRYPT 2021: the general framework
  for linear analysis, correlation matrices and nonlinear approximations.
* Civino and Fedele, `Binary Bibraces and Applications to Cryptography
  <https://doi.org/10.1007/s00009-024-02793-z>`_, Mediterranean Journal of
  Mathematics 22, article 29 (2025): the algebra of binary bibraces and
  alternative difference operations. This work concerns differential analysis.
* Roberto Civino, `Circle-Linear Cryptanalysis: Bibrace Characters and Weak-Key
  Linear Distinguishers for CRAFT <https://eprint.iacr.org/2026/1767>`_,
  IACR ePrint 2026/1767 (2026): the circle-linear construction and its
  application to CRAFT; publicly available preprint.
* Civino and Fedele, `Classification of small binary bibraces via bilinear maps
  <https://doi.org/10.1007/s00025-026-02612-9>`_: classification of the structures.
* Beierle et al., `CRAFT specification and reference vectors
  <https://doi.org/10.46586/tosc.v2019.i1.5-45>`_: the original primitive definition.

The regression cases test trail contributions and the keys on which those
contributions are nonzero. They do not establish the full input/output
correlation or a distinguisher's sample requirements. That requires a
complete signed hull sum, or separate evidence for the actual correlation.
