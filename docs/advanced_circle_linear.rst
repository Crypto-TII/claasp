Circle-linear cryptanalysis: advanced
=====================================

The introductory guides cover :doc:`basic_circle_linear` and
:doc:`basic_circle_linear_correlations` using the same analyze, print and
plot workflow. This page defines the terminology, explores parameters and
checks numerical CRAFT results.

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
:math:`b_j`; support is not limited to the single direction used for CRAFT.

.. doctest::

   >>> from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace, CircleBasis
   >>> brace = BinaryBibrace.craft()
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

Even unanimous samples do not produce an unjustified zero-width interval. To
distinguish a correlation of magnitude :math:`c` from zero generally
requires order :math:`c^{-2}` samples. In the usual terminology, **bias** is
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
with layers that mix or rearrange cells. The ``FreeSubgroupSPN`` backend is
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
   >>> model = primitive.analysis.circle_linear_model(
   ...     bibrace=BinaryBibrace.craft(), fixed_inputs={"tweak": 0})
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
``Craft(...).circle_linear_model(tweak=...)`` delegates to this adapter.

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
checked on all optimal candidates; if none survives, the method reports that
fact rather than asserting an optimum at an unsearched higher cost.

.. doctest::

   >>> from claasp.primitives import Craft
   >>> result = Craft(number_of_rounds=14).circle_linear_model().search()
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
``circle_linear_model(tweak=...)`` fixes the public tweak and derives affine
conditions. Its optimized backend excludes the special final round 31, which
omits the S-box and permutation; the concrete primitive and endpoint
measurements support the full CRAFT block cipher. The model's mask codes use
this convention: q in the low sixteen bits, s in the high sixteen, bit i for
cell i. Use ``input_mask`` and ``output_mask`` for packed character labels;
do not pass these coordinate codes to endpoint measurement methods.

Public background and interpretation
------------------------------------

The following public works explain the general frameworks; they are not
citations for the numerical CRAFT regression cases above.

* Tim Beyne, `A Geometric Approach to Linear Cryptanalysis
  <https://eprint.iacr.org/2021/1247>`_, ASIACRYPT 2021: the general framework
  for linear analysis, correlation matrices and nonlinear approximations.
* Civino and Fedele, `Binary bi-braces and applications to cryptography
  <https://arxiv.org/abs/2404.09315>`_: the algebra of binary bibraces and
  alternative difference operations. This work concerns differential analysis.
* Civino and Fedele, `Classification of small binary bibraces via bilinear maps
  <https://doi.org/10.1007/s00025-026-02612-9>`_: classification of the structures.
* Beierle et al., `CRAFT specification and reference vectors
  <https://doi.org/10.46586/tosc.v2019.i1.5-45>`_: the original primitive definition.

The regression cases test trail contributions and the keys on which those
contributions are nonzero. They do not establish the full input/output
correlation or a distinguisher's sample requirements. That requires a
complete signed hull sum, or separate evidence for the actual correlation.