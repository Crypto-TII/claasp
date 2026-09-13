Traditional ciphers
===================

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

Speck is represented directly with fixed-width word units. Packed integer
boundaries hide the internal word ordering from ordinary evaluation calls.

.. doctest::

   >>> from claasp_next.ciphers import SpeckBlockCipher
   >>> speck = SpeckBlockCipher(64, 128)
   >>> plaintext = 0x3B7265747475432D
   >>> key = 0x1B1A1918131211100B0A090803020100
   >>> f"{speck.evaluate(plaintext, key):016x}"
   '8c6fa548454e028b'

The construction includes the key schedule in the graph. All standard
block/key configurations are accepted. Reduced-round instances retain a
prefix of the standard schedule.

Simon32/64
----------

Simon uses the same typed word boundaries, adding a reusable component-wise
``BitwiseAnd`` operation for its nonlinear round function. The key schedule is
part of the graph, and packed integers remain the ordinary user interface.

.. doctest::

   >>> from claasp_next.ciphers import SimonBlockCipher
   >>> simon = SimonBlockCipher()
   >>> f"{simon.evaluate(0x65656877, 0x1918111009080100):08x}"
   'c69be9bb'

All ten standard block/key configurations are supported. The migrated tests
retain the fixed Simon32/64, Simon48/72, Simon48/96, and Simon128/256 vectors
from the legacy CLAASP suite.

AES
---

AES validates a different semantics of an eight-bit unit. Its bytes are
elements of :math:`GF(2^8)` in the polynomial basis defined by
:math:`x^8+x^4+x^3+x+1`, rather than unsigned ``Word(8)`` values.

.. doctest::

   >>> from claasp_next.ciphers import AESBlockCipher
   >>> plaintext = 0x00112233445566778899AABBCCDDEEFF
   >>> key = 0x000102030405060708090A0B0C0D0E0F
   >>> f"{AESBlockCipher().evaluate(plaintext, key):032x}"
   '69c4e0d86a7b0430d8cdb78070b4c55a'

The graph supports AES-128, AES-192, and AES-256 key expansion. SubBytes uses a reusable typed
``SBox`` lookup, ShiftRows is a domain-neutral ``Permutation``, MixColumns is
a ``LinearMap`` over the byte field, and AddRoundKey is field addition.
``number_of_rounds`` constructs a prefix of the standard cipher; MixColumns
is omitted only in standard round 10.

PRESENT
-------

PRESENT validates the individual-bit representation needed by Boolean
analysis backends. Its 4-bit S-box is a ``BitVectorSBox`` connecting four
separate ``Bit`` units, unlike AES's lookup over one byte-field unit.

.. doctest::

   >>> from claasp_next.ciphers import Present80BlockCipher
   >>> f"{Present80BlockCipher().evaluate(plaintext=0, key=0):016x}"
   '5579c1387b228445'

Both 80- and 128-bit key schedules are supported. The friendly boundary API converts packed integers to the graph's canonical
MSB-first units and rejects values that would be truncated. The graph contains
all 31 substitution-permutation rounds, the 80-bit key schedule, and final
whitening.
