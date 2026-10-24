Truncated differences: advanced
===============================

Deterministic truncated differences use the explicit symbols ``0``, ``1``,
and ``?``. Modular addition propagates them with a sound paired-carry
reachability computation:

.. doctest::

   >>> from claasp.analysis import TruncatedXorDifference, truncated_modular_add
   >>> left = TruncatedXorDifference.parse("1000")
   >>> zero = TruncatedXorDifference.parse("0000")
   >>> str(truncated_modular_add(left, zero))
   '1000'

Sound deterministic propagation is available for supported graphs. For example::

   from claasp.primitives import Speck

   boundaries = Speck(number_of_rounds=3).analysis \
       .propagate_truncated_xor_difference(
           "00000000011000000000000000000000"
       )
   assert len(boundaries.boundaries) == 4

Unsupported graphs raise a capability error identifying the missing semantic rule.

Probabilistic truncated differences
-----------------------------------

**TODO:** Add a worked probabilistic-truncated search example, including its
model assumptions, parameters and interpretation. The deterministic propagation
examples above are already documented.
