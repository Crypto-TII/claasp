Polynomial models
=================

CLAASP lowers a typed cipher graph to a solver-independent sparse polynomial
system before exporting it to a computer algebra backend. The initial model
supports homogeneous prime-field graphs.

.. doctest::

   >>> from claasp_next.ciphers import MiMCPermutation
   >>> from claasp_next.polynomial import PrimeFieldPolynomialModel
   >>> cipher = MiMCPermutation(17, 3, (1, 2))
   >>> system = PrimeFieldPolynomialModel(cipher).polynomial_system()
   >>> len(system.variables)
   7
   >>> len(system.equations)
   6
   >>> system.maximum_degree
   3
   >>> system.provenance[:3]
   ('constant_0_0', 'add_0_1', 'power_0_2')

Each equation is interpreted as a left-hand side equal to zero. Component
output variables are retained, keeping round equations sparse instead of
expanding the entire permutation into input variables.

The built-in representation is intentionally not a general computer algebra
system. Future exporters will translate it to tools such as Singular and
msolve for Gröbner-basis experiments.
