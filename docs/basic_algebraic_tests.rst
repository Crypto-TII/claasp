Boolean polynomial systems and algebraic tests: introduction
============================================================

Represent a primitive as Boolean equations and inspect how the system grows:

.. doctest::
   :options: +NORMALIZE_WHITESPACE

   >>> from claasp.primitives import Speck
   >>> result = Speck(number_of_rounds=2).analysis.polynomial_system()
   >>> result.to_terminal()
   Round | Variables | Equations | Terms | Max degree
   ------+-----------+-----------+-------+-----------
   1     | 272       | 208       | 586   | 2
   2     | 368       | 304       | 871   | 2

Each polynomial is equal to zero over GF(2). Counts are cumulative and include
variables occurring in those equations. Intermediate values and carry bits
remain variables, so modular addition has quadratic equations even when its
fully expanded output ANF would have high degree. These counts describe the
encoding; they do not measure resistance to algebraic attacks on their own.
