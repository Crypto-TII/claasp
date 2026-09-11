What is new in CLAASP 5
=======================

CLAASP 5 generalizes the graph's logical unit. A wire may carry bits,
fixed-width words, binary-extension-field elements, or prime-field elements.
This supports traditional and arithmetization-oriented ciphers without forcing
both into an implicit bit representation.

The implementation is independent of SageMath. Scalar and batch evaluation,
graph construction, Boolean and polynomial intermediate representations, and
exporters run on ordinary CPython. External algebra systems and solvers are
optional integrations.

Native field example
--------------------

.. doctest::

   >>> from claasp_next.ciphers import MiMCPermutation
   >>> MiMCPermutation(17, 3, (1, 2, 4)).evaluate(5)
   5

Poseidon retains a vector of field elements rather than packing it into an
artificial integer:

.. doctest::

   >>> from claasp_next.ciphers import PoseidonPermutation
   >>> poseidon = PoseidonPermutation(
   ...     17, 3, 2, 1,
   ...     ((1, 2), (3, 4), (5, 6)),
   ...     ((1, 1), (1, 2)),
   ... )
   >>> poseidon.evaluate((0, 1))
   (4, 15)

Architecture and migration status
---------------------------------

The temporary distribution and import names are ``claasp-next`` and
``claasp_next``. They become ``claasp`` only when v5 replaces the legacy
package. Cipher descriptions, evaluation, mathematical models, exporters, and
solver processes remain separate layers.

See :doc:`concepts` for typed-unit details and :doc:`parameters` for verified
AO parameter catalogues. Boolean and polynomial representations are described
in the advanced modeling guides.
