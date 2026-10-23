Complete inversion
==================

A complete inverse takes the forward output plus every retained auxiliary
input. For a block primitive, the first input is recovered by default and the
key is retained:

.. doctest::

   >>> from claasp.primitives import Speck
   >>> source = Speck(number_of_rounds=2)
   >>> plaintext, key = 0x6574694c, 0x1918111009080100
   >>> ciphertext = source.evaluate(plaintext, key)
   >>> inverse = source.edit.inverse().primitive
   >>> tuple(inverse.graph.input_arrays)
   ('output', 'key')
   >>> inverse.evaluate(ciphertext, key) == plaintext
   True

Only components with explicit inverse semantics are reversed. A non-bijective
operation fails with a typed ``information_loss`` diagnostic instead of
claiming an inverse.


When inversion is defined
-------------------------

Catalogue metadata identifies the data or state input that is expected to be
recoverable when all auxiliary inputs are retained. XOR, modular addition,
rotation, permutation, and identity operations can therefore be invertible
with respect to one designated input even though a multi-input operation is
not jointly invertible in all of its inputs.

This does not make every custom constructor choice reversible. A lossy lookup
table, singular matrix, hash, stream-output function, or non-reversible
feedback description reports a typed diagnostic such as
``information_loss`` or ``multiple_predecessors``.
