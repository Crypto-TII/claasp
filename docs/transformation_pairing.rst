Paired XOR graphs
=================

.. doctest::

   >>> from claasp.primitives import Speck
   >>> source = Speck(number_of_rounds=2)
   >>> plaintext, key = 0x6574694c, 0x1918111009080100


Pairing retains two named composite scopes and publishes input, round, key, and
output differences. Shared inputs express a single-key experiment:

.. doctest::

   >>> paired = source.edit.pair_xor(shared_inputs=("key",))
   >>> left, right = 0x6574694c, 0x6574694d
   >>> paired.primitive.evaluate(left, right, key) == (
   ...     source.evaluate(left, key) ^ source.evaluate(right, key)
   ... )
   True
   >>> (paired.left_scope.path, paired.right_scope.path)
   ('left', 'right')
