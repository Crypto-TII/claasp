Monomial prediction and division property: introduction
=======================================================

An algebraic normal form (ANF) expresses an output bit using XORs of products
of input bits. Inspect a short Simon example:

.. doctest::

   >>> from claasp.primitives import Simon
   >>> result = Simon(number_of_rounds=1).analysis.anf(output_bit=0)
   >>> result.degrees
   (2,)
   >>> result.coefficient(("p1", "p8"))
   (1,)

The degree is exact and the coefficient is computed after cancellation over
GF(2). Input variables use MSB-first positions: ``p`` for plaintext, ``k`` for
key, ``i`` for IV and ``s`` for state. ``result.to_terminal(details=True)``
prints the polynomial as well as its degree and number of terms.

ANFs can grow quickly. CLAASP stops at explicit resource limits instead of
returning truncated polynomials. The advanced guide shows solver-based bounds,
exact parity checks and cube-superpoly recovery.
