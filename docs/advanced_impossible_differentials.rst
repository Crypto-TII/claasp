Impossible differentials: advanced
==================================

Checking a component transition
-------------------------------

For exact S-box differences, impossibility can be queried directly through
the graph facade:

.. doctest::

   >>> from claasp.primitives import Present
   >>> primitive = Present(number_of_rounds=1)
   >>> primitive.analysis.is_xor_differential_transition_possible("sbox_1_0", 1, 1)
   False

This checks one component transition. A complete multi-round impossible-
differential walkthrough remains **TODO**.
