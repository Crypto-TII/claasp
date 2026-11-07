Circle-linear trails
====================

Ordinary linear cryptanalysis looks for biased relationships between parities
of input and output bits. A **mask** selects the bits to XOR together, defining
a one-bit **parity check**. Circle-linear cryptanalysis uses the same approach
with parity-like checks compatible with a chosen alternative addition,
written :math:`\circ`. These checks can be nonlinear in the usual input bits.

In CLAASP, the chosen operation provides a change of coordinates
:math:`\theta` satisfying
:math:`\theta(x\circ y)=\theta(x)\oplus\theta(y)`. A circle mask selects
bits of :math:`\theta(x)` rather than bits of :math:`x`. In the table below,
:math:`a\cdot z` means the XOR of the bits of :math:`z` selected by mask
:math:`a`.

.. list-table:: Ordinary linear and circle-linear cryptanalysis
   :header-rows: 1
   :widths: 20 40 40

   * - Concept
     - Ordinary linear (XOR-linear)
     - Circle-linear
   * - Mask representation
     - A bit vector :math:`a`, often displayed as an integer.
     - The same representation, interpreted in the chosen coordinates.
   * - Check selected by the mask
     - :math:`\ell_a(x)=a\cdot x`.
     - :math:`\ell_a(x)=a\cdot\theta(x)`; this can include products of input bits.
   * - Compatibility rule
     - :math:`\ell_a(x\oplus y)=\ell_a(x)\oplus\ell_a(y)`.
     - :math:`\ell_a(x\circ y)=\ell_a(x)\oplus\ell_a(y)`.
   * - Trail description
     - A sequence of masks; each determines its parity check.
     - A sequence of masks; each determines its check once the operation and
       coordinate convention are fixed.
   * - Correlation
     - The fraction of inputs on which the two checks agree minus the fraction
       on which they disagree.
     - The same definition, applied to the circle-linear checks.

Once the operation and coordinate convention are fixed, each mask determines
its check function. Choosing XOR with the usual coordinates recovers ordinary
linear cryptanalysis. The primitive itself is unchanged. The :doc:`basic guide <basic_circle_linear>` defines the concrete
operation used in its example, and the :doc:`advanced guide
<advanced_circle_linear>` explains the coordinate construction.

In both analyses, a **trail** follows selected checks through successive
rounds. The product of the round correlations gives that trail's contribution;
the signed sum over all trails with the same input and output checks gives
the full endpoint correlation. Circle-linear analysis can expose biases that
ordinary parity checks miss, sometimes only for a particular class of keys.

Use ``primitive.analysis.find_lowest_weight_circle_linear_trail(...)`` for
the standard search workflow. The default optimized SPN backend retains its
supported subgroup and exact affine key class. A generic solver backend also
supports other binary graph structures and non-perfect transitions, with all
auxiliary inputs explicitly fixed; see :doc:`advanced_circle_linear`.

.. toctree::
   :maxdepth: 2

   Basic <basic_circle_linear>
   Advanced <advanced_circle_linear>
   Verification <verification_circle_linear>

Origins and references
----------------------

For the alternative-addition and binary-bibrace background, see the
:ref:`differential origins and references <circle-differential-origins>`.
The linear-analysis framework and its circle-linear application are described
in the following works:

* Tim Beyne, `A Geometric Approach to Linear Cryptanalysis
  <https://eprint.iacr.org/2021/1247>`_, ASIACRYPT 2021: the general framework
  over finite abelian groups, including nonlinear approximations.
* Roberto Civino, `Circle-Linear Cryptanalysis: Bibrace Characters and Weak-Key
  Linear Distinguishers for CRAFT <https://eprint.iacr.org/2026/1767>`_,
  IACR ePrint 2026/1767 (2026), publicly available preprint: instantiates the
  framework using binary bibraces and applies it to CRAFT.
