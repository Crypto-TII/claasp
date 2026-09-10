Traditional word-oriented ciphers
==================================

Words as logical units
----------------------

``Word(width)`` represents an unsigned fixed-width integer as one graph unit.
It is intentionally distinct from both an array of ``Bit`` values and an
element of ``BinaryExtensionField``. This lets ARX constructions express
rotation, XOR, and addition modulo :math:`2^w` without prematurely lowering
every operation to gates.

.. doctest::

   >>> from claasp_next import Word
   >>> Word(32).encoded_bit_size
   32
   >>> Word(32).contains(0xffffffff)
   True

Speck64/128
-----------

The first traditional-cipher validation target is Speck64/128. Its plaintext
and key inputs follow the word order in the designers' implementation guide.

.. doctest::

   >>> from claasp_next.ciphers import SpeckBlockCipher
   >>> from claasp_next.evaluators import ScalarEvaluator
   >>> result = ScalarEvaluator().evaluate(SpeckBlockCipher(), {
   ...     "plaintext": (0x3b726574, 0x7475432d),
   ...     "key": (0x1b1a1918, 0x13121110, 0x0b0a0908, 0x03020100),
   ... })
   >>> tuple(f"{word:08x}" for word in result.output)
   ('8c6fa548', '454e028b')

The construction includes the key schedule in the graph. Reduced-round
instances are available through ``number_of_rounds`` for analysis and retain
the prefix of the standard schedule. This implementation currently targets
only the 64-bit-block, 128-bit-key member; other Speck variants will be added
only when they provide additional architectural validation.

AES-128
-------

AES validates a different interpretation of an eight-bit unit. Its bytes are
elements of :math:`GF(2^8)` in the polynomial basis defined by
:math:`x^8+x^4+x^3+x+1`, rather than unsigned ``Word(8)`` values.

.. doctest::

   >>> from claasp_next.ciphers import AES128BlockCipher
   >>> plaintext = tuple(bytes.fromhex("00112233445566778899aabbccddeeff"))
   >>> key = tuple(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
   >>> result = ScalarEvaluator().evaluate(
   ...     AES128BlockCipher(), {"plaintext": plaintext, "key": key}
   ... )
   >>> bytes(result.output).hex()
   '69c4e0d86a7b0430d8cdb78070b4c55a'

The graph includes the AES-128 key expansion. SubBytes uses a reusable typed
``SBox`` lookup, ShiftRows is a domain-neutral ``Permutation``, MixColumns is
a ``LinearMap`` over the byte field, and AddRoundKey is field addition.
``number_of_rounds`` constructs a prefix of the standard cipher; MixColumns
is omitted only in standard round 10.
