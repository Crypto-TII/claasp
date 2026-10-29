Statistical tests: introduction
===============================

A statistical test can be applied to supplied data without constructing a
primitive. For example, the frequency (monobit) test checks whether zeros and
ones occur in roughly equal numbers:

.. doctest::

   >>> from claasp.analysis import frequency_test
   >>> result = frequency_test([0, 1] * 4000)
   >>> result.p_value, result.passed
   (1.0, True)

A high p-value means this test did not detect an imbalance; it does not prove
that the data is random or cryptographically secure. An alternating sequence
passes this test despite being predictable. Use several tests addressing
different properties, as shown in :doc:`statistical_testing`.

Inputs may also be flat NumPy bit arrays. Below 100 bits, ``applicable`` is
false and ``passed`` is ``None`` because the recommended sample size is not met.
