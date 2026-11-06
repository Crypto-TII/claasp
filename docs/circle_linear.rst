Circle-linear trails
====================

Ordinary linear cryptanalysis looks for biased relationships between parities
of input and output bits. A **mask** selects the bits to XOR together; this
one-bit function is a **parity check**. Its correlation measures how often
the input and output checks agree, minus how often they disagree.

Circle-linear cryptanalysis follows the same idea using checks compatible
with a chosen alternative addition, written :math:`\circ`, instead of XOR.
A circle-linear check :math:`\ell` satisfies
:math:`\ell(x\circ y)=\ell(x)\oplus\ell(y)`, just as an ordinary parity
check satisfies this identity for XOR. A mask labels which check to use,
but the check can be nonlinear in the usual input bits. Choosing XOR as the
addition recovers ordinary linear cryptanalysis. The cipher itself is unchanged;
the alternative addition changes the checks used to analyse it. The
:doc:`introduction <basic_circle_linear>` defines the concrete operation used
in its example.

As in ordinary linear cryptanalysis, a **trail** follows selected checks
through successive rounds. The product of the round correlations gives that
trail's contribution; the signed sum over all trails with the same input and
output checks gives the full endpoint correlation. Circle-linear analysis
can expose biases that ordinary parity checks miss, sometimes only for a
particular class of keys.

.. toctree::
   :maxdepth: 2

   Introduction <basic_circle_linear>
   Advanced <advanced_circle_linear>
   Verification <verification_circle_linear>
