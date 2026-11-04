Circle-linear cryptanalysis: introduction
=========================================

Circle-linear analysis looks for relationships between bit checks on a
primitive's input and output. It uses an alternative addition, written
:math:`\circ`, alongside ordinary XOR. A **bibrace** is the mathematical
structure that makes these two additions compatible.

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

The implementation uses exact signed fractions and needs no external solver.
The examples below require only the core installation.

Find a perfect S-box relation
-----------------------------

CRAFT and Midori share a four-bit **S-box**, a small lookup table replacing
each four-bit input with a four-bit output. The bibrace configured below
makes some input and output checks perfectly related. These relations can be
verified directly by trying all sixteen possible inputs.

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

These are exact correlations between the checks at the input and output (the
**endpoints**) of the S-box. In the first relation the two check bits are
always equal; in the second they are always opposite. Here each **cell** is
a four-bit chunk, and bit 0 is its least significant bit. Labels are
integers; label 14 is hexadecimal ``e``.

Find an optimal CRAFT trail
---------------------------

A **trail** specifies the checks followed through successive layers of a
primitive. The CRAFT S-box has four checks, including the always-zero check,
that pass through it without losing correlation magnitude. They form a
**subgroup**: XORing any two of these check functions gives another one in
the same set.

Within this restricted set, each mask has one possible next mask. The
**diffusion** layer, which mixes cells, and its following key addition
determine the trail's correlation cost and which keys allow it. CLAASP
checks the required structure and searches this restricted space exactly.

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

Trail **cost** counts halvings of its correlation magnitude. Formally it is
:math:`-\log_2 |c_{\rm trail}|`; here cost 8 means magnitude
:math:`2^{-8}`. The result certifies an optimum **inside the declared
perfect subgroup**, not among all circle-linear trails.

The **weak-key class** is the set of keys on which this selected trail has a
nonzero contribution. Here its size is :math:`2^{120}` out of CRAFT's
:math:`2^{128}` possible keys. The **tweak**, a public input selecting an
encryption variant, is fixed to zero; the round constants retain their
specified values.

A trail contribution is one signed term in the full input/output
correlation. All trails sharing those endpoints form a **linear hull**;
their signed contributions add together and may cancel. Thus one trail's
magnitude alone does not establish a **distinguisher**, a statistical test
that separates the primitive from a random mapping, or the number of samples
that test needs. The advanced guide shows complete small hull sums and
reproducible estimates of actual input/output correlations.

Continue with :doc:`advanced_circle_linear` for layouts, generic affine
layers, arbitrary binary primitives, key schedules and CRAFT regression
checks.