Circle-linear cryptanalysis: advanced
=====================================

Choose a basis and a cell layout
--------------------------------

``BinaryBibrace`` represents the class-two binary family

.. math::

   x\circ y=x\oplus y\oplus\sum_j\psi_j(x,y)b_j.

Each bilinear form is alternating, and the independent output vectors lie
in every form's radical. The constructor validates these properties and
builds an involution :math:`\theta` with
:math:`\ell_u(x)=\langle u,\theta(x)\rangle`. It corrects quadratic refinements
when necessary; the naive quadratic expression need not vanish on the
annihilator. Higher-rank products are supported, not only CRAFT's rank one.

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

Form row ``i`` is a packed mask in LSB bit coordinates. In a parallel basis
the **first cell occupies the most significant bits**. Cell layouts are
explicit: do not reinterpret a nibble-based operation as a byte-based one.
An empty list of forms, ``BinaryBibrace(width)``, gives ordinary XOR
characters and is useful as an independent control.

Analyze another binary primitive
--------------------------------

The primitive facade calls the concrete evaluator. Exact endpoint sums,
bounded endpoint optimization and seeded measurements therefore apply to
any supported binary graph, including modular arithmetic and finite unrolled
feedback. There is no primitive-name filter or blanket exclusion of LFSRs.
Variable-control operations are measurable when the concrete evaluator
supports them; there is no dedicated symbolic carry/control search backend.

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

For heterogeneous layouts pass ``input_basis`` and ``output_basis`` instead
of ``bibrace``. Both must exactly match their packed boundary widths.
``correlation`` enumerates the complete varying-input domain, with a default
budget of :math:`2^{16}` inputs. ``best_approximation`` evaluates a complete
endpoint LAT under an explicit entry budget. Both reject oversized work
before evaluating the primitive. They do not claim internal trail optimality.

Large binary-extension-field primitives may be measured in the same way.
For symbolic work, field addition and constant multiplication are binary
affine; variable multiplication and nonlinear power maps need small exact
tables or future specialized search methods. Odd-prime-field primitives are
explicitly rejected: their valid domains are not binary vector spaces, and
padding their encodings does not define the required group.

Measure an endpoint bias with uncertainty
-----------------------------------------

.. doctest::

   >>> estimate = analysis.estimate_correlation(
   ...     9, 9, fixed_inputs={names[1]: 0}, samples=1024, seed=17)
   >>> estimate.value, estimate.samples, estimate.seed, estimate.complete
   (1.0, 1024, 17, False)
   >>> estimate.lower < 1 <= estimate.upper
   True

Sampling is uniform with replacement. ``standard_error`` is a plug-in
estimate; ``lower`` and ``upper`` give a distribution-free Hoeffding interval
at the requested confidence (default 0.95). Even unanimous samples do not
produce an unjustified zero-width interval. A small bias :math:`c` generally
requires order :math:`c^{-2}` samples to resolve. Sampling cannot economically
validate the paper's 14--18-round biases.

Generic affine diffusion and weak-key classes
---------------------------------------------

``CircleAffineLayer`` groups a binary affine operation and its following
key/constant addition:

.. math::

   y=Ax\oplus Bk\oplus c.

Substituting quadratic characters gives a quadratic Boolean exponent. An
exact Gauss-sum calculation returns the signed coefficient; the radical
gives affine key conditions. No dense state transition table is necessary.
Rectangular maps, noninvertible maps and different boundary cell layouts are
allowed. Grouping diffusion with key addition avoids imposing unnecessary
per-cell key conditions.

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
describe the exact nonzero local support; the sign is still key dependent.
Intersect conditions across layers to obtain a selected trail's survival
class. Inconsistency gives an empty class, not an independent-subkey estimate.

Pull back through an affine key schedule explicitly:

.. doctest::

   >>> independent = AffineKeyConditions(2, ((3, 0),))
   >>> repeated = independent.pullback((1, 1), master_width=1)
   >>> repeated.key_count
   2
   >>> independent.pullback((1, 1), master_width=1, offset=1).key_count
   0

This does not solve nonlinear key schedules. Their master-key conditions
require another constraint representation and potentially model counting.
For a joint key/tweak system, ``conditions.project(tweak_bit_positions)``
existentially eliminates the master-key variables and returns the exact
admissible-tweak class. It does not fix the eliminated key bits to zero.

Complete small hulls and general trail search
---------------------------------------------

Use ``CircleLookupLayer`` for a complete small truth table. A grouped
primitive can provide one with ``analysis.lookup_layer(fixed_inputs=...)``.
Compose lookup and affine layers with ``CircleNetwork``. Adjacent bases must
agree exactly. ``best_trail`` maximizes a trail's absolute coefficient over
all intermediate masks; ``correlation`` sums all signed trails.

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
Network search and hull sums have a conservative ``maximum_entries``
preflight budget. These exact methods are intended for small networks and
validation, not dense whole-state searches on 64-bit primitives.

Reproduce the paper and transfer its optimized search
-----------------------------------------------------

The ``FreeSubgroupSPN`` backend is primitive independent. It accepts a supplied
S-box, cell-XOR diffusion, cell permutation, round count and optional grouped
affine key/constant layers. It checks the four-element perfect subgroup and
its type flip. S-boxes without that structure are rejected by this backend;
they remain usable in general lookup and network analysis.

The backward spatial map acts identically on both mask coordinates and
commutes with the type flip. Thus the cost separates into functions of
:math:`q` and :math:`q\oplus s`. Two :math:`2^n` enumerations certify the
whole :math:`2^{2n}` subgroup search. Zero-cost nonzero masks are included.
The default factor-state budget is :math:`2^{16}`. Affine key conditions are
checked on all optimal candidates; if none survives, the method reports
that fact rather than asserting an optimum at an unsearched higher cost.

.. doctest::

   >>> from claasp.primitives import Craft
   >>> result = Craft(number_of_rounds=14).circle_linear_model().search()
   >>> result.cost, result.optimal_mask_count
   (22, 16)
   >>> result.representative.conditions.key_count == 2**108
   True
   >>> result.complete, result.scope
   (True, 'four-element perfect subgroup')

The following results reproduce Table 5 of the supplied **2 November 2026
draft**. Counts and key classes are checked by pytest, independently of a
hard-coded CRAFT cost formula.

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
conditions. Its optimized backend excludes the special final round 31,
which omits the S-box and permutation; the concrete primitive and endpoint
measurements support the full CRAFT block cipher. CRAFT's masks use the paper's code
convention: q in the low sixteen bits, s in the high sixteen, bit i for cell i.
Use ``input_mask`` and ``output_mask`` for packed character labels; do not
pass the paper's coordinate codes to endpoint measurement methods.

References and interpretation
-----------------------------

* Roberto Civino, `Circle-Linear Cryptanalysis: Bibrace Characters and Weak-Key
  Linear Distinguishers for CRAFT <https://eprint.iacr.org/2026/1767>`_. The
  regression fixtures refer to the supplied November draft, which may differ
  from the publicly indexed version.
* Civino and Fedele, `Classification of small binary bibraces via bilinear maps
  <https://doi.org/10.1007/s00025-026-02612-9>`_.
* Beierle et al., `CRAFT specification and reference vectors
  <https://doi.org/10.46586/tosc.v2019.i1.5-45>`_.

The paper's trail contributions and survival classes are regression targets.
They are not a proof of its full-hull distinguisher claims. Neither the
optimality of subgroup trails nor short-round sampling resolves that gap.
