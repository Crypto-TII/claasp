Circle-linear cryptanalysis: introduction
=========================================

A bibrace supplies an alternative addition on the same binary values as XOR.
Circle-linear analysis measures correlations using the characters of that
addition. Some characters are quadratic Boolean functions, so a primitive can
have strong relations that ordinary scalar-product masks do not reveal.

The implementation uses exact signed rational coefficients and needs no
external solver. The examples below require only the core installation.

Find a perfect S-box relation
-----------------------------

CRAFT and Midori share a four-bit S-box. For the bibrace used in Roberto
Civino's *Circle-Linear Cryptanalysis: Bibrace Characters and Weak-Key Linear
Distinguishers for CRAFT*, its circle-LAT contains perfect relations.

.. doctest::

   >>> from claasp.primitives import BitVectorSBox
   >>> from claasp.primitives.block_ciphers.craft import CRAFT_SBOX
   >>> from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace
   >>> primitive = BitVectorSBox(4, CRAFT_SBOX)
   >>> analysis = primitive.analysis.circle_linear(
   ...     input_name="input", bibrace=BinaryBibrace.craft())
   >>> analysis.correlation(9, 9)
   Fraction(1, 1)
   >>> analysis.correlation(7, 14)
   Fraction(-1, 1)

These are actual endpoint correlations over all sixteen input values. The
minus sign is meaningful: the second relation holds with a constant offset
of one. Mask labels are hexadecimal cell values; bit 0 inside a cell is its
least significant bit.

Reproduce an optimal CRAFT trail
--------------------------------

The paper finds a four-element subgroup of perfect S-box masks. Within that
subgroup the masks propagate deterministically, and only the diffusion/key
layers cost correlation. CLAASP verifies these properties and searches the
whole subgroup using two independent sixteen-bit factors.

.. doctest::

   >>> from claasp.primitives import Craft
   >>> primitive = Craft(number_of_rounds=8)
   >>> result = primitive.circle_linear_model().search()
   >>> result.cost, result.optimal_mask_count
   (8, 24)
   >>> trail = result.representative
   >>> hex(trail.input_code), hex(trail.output_code)
   ('0x725a0000', '0x1190000')
   >>> trail.conditions.key_count == 2**120
   True
   >>> abs(trail.contribution(0))
   Fraction(1, 256)

Cost is :math:`-\log_2 |c_{\rm trail}|`; here the magnitude is
:math:`2^{-8}`. The result certifies an optimum **inside the declared perfect
subgroup**, not among all circle-linear trails. The key class is the exact
set on which this selected trail has a nonzero contribution, with public
tweak zero and the genuine CRAFT round constants.

A trail contribution is one signed term in the full endpoint correlation.
Other trails may reinforce or cancel it. Therefore the trail's magnitude
does not by itself establish a distinguisher or its data complexity. The
advanced guide shows complete small hull sums and seeded endpoint estimates.

Continue with :doc:`advanced_circle_linear` for layouts, generic affine
layers, arbitrary binary primitives, key schedules and paper regressions.
