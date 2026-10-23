Slicing and reducing rounds
===========================

.. doctest::

   >>> from claasp.primitives import Speck
   >>> source = Speck(number_of_rounds=2)
   >>> plaintext, key = 0x6574694c, 0x1918111009080100


``edit.slice()`` keeps the dependency closure needed by an explicit output. Published
round states provide stable specification-level boundaries:

.. doctest::

   >>> source = Speck(number_of_rounds=3)
   >>> first_round = source.edit.slice(source.graph.round_outputs[0]).primitive
   >>> first_round.evaluate(plaintext, key) == Speck(number_of_rounds=1).evaluate(plaintext, key)
   True
   >>> two_rounds = source.edit.reduce_rounds(2).primitive
   >>> two_rounds.evaluate(plaintext, key) == Speck(number_of_rounds=2).evaluate(plaintext, key)
   True

For a middle slice, pass ``inputs={...}`` to name the new boundary selections.
The transformation validates complete logical units and reports a disconnected
dependency if a required unit is omitted.
