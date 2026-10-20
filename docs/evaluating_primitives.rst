Evaluating primitives
=====================

One binary input
----------------

At ordinary binary primitive boundaries, pass one packed Python integer for
each named input. The returned integer uses the primitive's documented bit
width:

.. doctest::

   >>> from claasp.primitives import AES
   >>> aes = AES()
   >>> output = aes.evaluate(
   ...     plaintext=0x00112233445566778899AABBCCDDEEFF,
   ...     key=0x000102030405060708090A0B0C0D0E0F,
   ... )
   >>> f"{output:032x}"
   '69c4e0d86a7b0430d8cdb78070b4c55a'

Several binary inputs
---------------------

``evaluate_many()`` evaluates independent inputs. A list varies an input;
one scalar value is reused for the whole batch. Here two plaintexts share one
key:

.. doctest::

   >>> plaintexts = [0x0, 0x1]
   >>> outputs = aes.evaluate_many(plaintext=plaintexts, key=0x0)
   >>> [f"{value:032x}" for value in outputs]
   ['66e94bd4ef8a2c3b884cfa59ca342b2e', '58e2fccefa7e3061367f1d57a4e7455a']

Supply lists of the same length to pair each plaintext with a different key:

.. doctest::

   >>> keys = [0x0, 0x1]
   >>> outputs = aes.evaluate_many(plaintext=plaintexts, key=keys)
   >>> [f"{value:032x}" for value in outputs]
   ['66e94bd4ef8a2c3b884cfa59ca342b2e', 'a17e9f69e4f25a8b8620b4af78eefd6f']

Non-binary inputs
-----------------

For a vector over a prime field, pass a tuple containing one integer per field
element. The output preserves that logical-unit structure:

.. doctest::

   >>> from claasp.primitives import Poseidon
   >>> poseidon = Poseidon(
   ...     modulus=17,
   ...     exponent=3,
   ...     full_rounds=2,
   ...     partial_rounds=1,
   ...     round_constants=((1, 2), (3, 4), (5, 6)),
   ...     linear_layer=((1, 1), (1, 2)),
   ... )
   >>> poseidon.evaluate(state=(0, 1))
   (4, 15)

These are teaching parameters for the existing ``Poseidon`` permutation,
not a secure parameter set. Each input and output coordinate is an element
of the field modulo 17. See :doc:`concepts` for ``UnitArrayType`` and the
available unit types. For direct access to
batch execution strategies, see :doc:`batch_evaluation`.
