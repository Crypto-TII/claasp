Implementing a two-round ToySPN
===============================

This guide turns short substitution-permutation-network pseudocode into a
CLAASP primitive. The construction has a 16-bit state and key, four parallel
4-bit S-boxes, a bit permutation, and two rounds.

Start with the fixed mathematical parameters. The S-box is the PRESENT S-box;
the permutation transposes the four-by-four bit state:

.. doctest::

   >>> SBOX = (0xC, 5, 6, 0xB, 9, 0, 0xA, 0xD, 3, 0xE, 0xF, 8, 4, 7, 1, 2)
   >>> P_LAYER = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)

The implementation follows the round pseudocode directly: add the key, apply
the S-boxes in parallel, and permute the bits.

.. doctest::

   >>> from claasp import BitWord, PrimitiveBuilder
   >>> from claasp.components import BitVectorSBox, Permutation, Xor
   >>> def ToySPN():
   ...     graph = PrimitiveBuilder(
   ...         "toy_spn",
   ...         plaintext=BitWord(16),
   ...         key=BitWord(16),
   ...         instance_name="ToySPN-16",
   ...     )
   ...     state = graph.input("plaintext")
   ...     key = graph.input("key")
   ...
   ...     for _ in range(2):
   ...         graph.add_round()
   ...         state = graph.add(Xor(state, key))
   ...         nibbles = [
   ...             graph.add(BitVectorSBox(state[start:start + 4], SBOX))
   ...             for start in range(0, 16, 4)
   ...         ]
   ...         state = graph.add(Permutation(graph.join(*nibbles), P_LAYER))
   ...
   ...     return graph.build()

``BitWord(16)`` declares a packed 16-bit boundary. Inside the graph, indexing
selects individual bits, so ``state[start:start + 4]`` connects one nibble to
one S-box. ``graph.join()`` places the four S-box outputs back into one state;
it is structural wiring rather than an extra cryptographic operation.

Build the primitive, inspect it, and evaluate one input:

.. doctest::

   >>> toy_spn = ToySPN()
   >>> toy_spn.details()
   Primitive details
     Type: block cipher
     Instance: ToySPN-16
     Inputs:
       plaintext: 16 bits (public)
       key: 16 bits (secret)
     Output: 16 bits
     Rounds: 2
     Realization: default
   >>> f"{toy_spn.evaluate(plaintext=0x1234, key=0x5678):04x}"
   'f616'

The completed object is immutable. Continue with :doc:`primitive_authoring`
for published round states and round keys, reusable composite blocks, field and
word domains, explicit provenance, validation, and full primitive classes.
