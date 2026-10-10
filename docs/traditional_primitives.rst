Traditional primitives
========================

Words as logical units
----------------------

``Word(width)`` represents an unsigned fixed-width integer as one graph unit.
It is intentionally distinct from both an array of ``Bit`` values and an
element of ``BinaryExtensionField``. This lets ARX constructions express
rotation, XOR, and addition modulo :math:`2^w` without prematurely lowering
every operation to gates.

.. doctest::

   >>> from claasp import Word
   >>> Word(32).encoded_bit_size
   32
   >>> Word(32).contains(0xffffffff)
   True

Speck64/128
-----------

Speck is represented directly with fixed-width word units. Packed integer
boundaries hide the internal word ordering from ordinary evaluation calls.

.. doctest::

   >>> from claasp.primitives import Speck
   >>> speck = Speck(64, 128)
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

   >>> from claasp.primitives import Simon
   >>> simon = Simon()
   >>> f"{simon.evaluate(0x65656877, 0x1918111009080100):08x}"
   'c69be9bb'

All ten standard block/key configurations are supported and checked against
fixed Simon32/64, Simon48/72, Simon48/96, and Simon128/256 test vectors.

AES
---

AES validates a different semantics of an eight-bit unit. Its bytes are
elements of :math:`GF(2^8)` in the polynomial basis defined by
:math:`x^8+x^4+x^3+x+1`, rather than unsigned ``Word(8)`` values.

.. doctest::

   >>> from claasp.primitives import AES
   >>> plaintext = 0x00112233445566778899AABBCCDDEEFF
   >>> key = 0x000102030405060708090A0B0C0D0E0F
   >>> f"{AES().evaluate(plaintext, key):032x}"
   '69c4e0d86a7b0430d8cdb78070b4c55a'

Choosing an AES configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``instances`` lists the configurations approved by the AES specification,
while ``parameters`` lists every constructor option, including options useful
for reduced-round studies:

.. doctest::

   >>> aes = AES()
   >>> aes.instances
   Official instances for AES (3)
     [0] AES(key_bit_size=128, number_of_rounds=10)
     [1] AES(key_bit_size=192, number_of_rounds=12)
     [2] AES(key_bit_size=256, number_of_rounds=14)
   >>> aes.parameters
   Customizable parameters for AES (3)
     key_bit_size: int = 128
     number_of_rounds: int | None = None
     realization: str = 'lookup'

Pass parameters by name. This example chooses a 256-bit key, keeps only five
rounds, and represents SubBytes algebraically:

.. doctest::

   >>> aes256 = AES(
   ...     key_bit_size=256,
   ...     number_of_rounds=5,
   ...     realization="algebraic",
   ... )
   >>> aes256.details()
   Primitive details
     Type: block cipher
     Instance: AES-256
     Inputs:
       plaintext: 128 bits (public)
       key: 256 bits (secret)
     Output: 128 bits
     Rounds: 5
     Realization: algebraic

The ``lookup`` realization stores the published 256-entry AES substitution
table. The ``algebraic`` realization expresses the same substitution as field
inversion followed by the AES affine transformation. They produce the same
cipher values but expose different graph components to analysis backends.

Use :doc:`customizing_aes` to replace the S-box, omit MixColumns, change other
AES building blocks, or use Toy AES with a smaller state or word size.

The graph supports AES-128, AES-192, and AES-256 key expansion. SubBytes uses a reusable typed
``SBox`` lookup, ShiftRows is a domain-neutral ``Permutation``, MixColumns is
a ``LinearMap`` over the byte field, and AddRoundKey is field addition.
``number_of_rounds`` constructs a prefix of the standard primitive; MixColumns
is omitted only in standard round 10.

AES provides ``lookup`` and ``algebraic`` graph realizations of SubBytes.
They share the same public inputs and output; :doc:`concepts` explains when
and how to select a realization.

PRESENT
-------

PRESENT validates the individual-bit representation needed by Boolean
analysis backends. Its 4-bit S-box is a ``BitVectorSBox`` connecting four
separate ``Bit`` units, unlike AES's lookup over one byte-field unit.

.. doctest::

   >>> from claasp.primitives import Present80
   >>> f"{Present80().evaluate(plaintext=0, key=0):016x}"
   '5579c1387b228445'

Both 80- and 128-bit key schedules are supported. The friendly boundary API converts packed integers to the graph's canonical
MSB-first units and rejects values that would be truncated. The graph contains
all 31 substitution-permutation rounds, the 80-bit key schedule, and final
whitening.

ChaCha
------

``ChaCha`` represents the fixed-length unkeyed permutation, not the
variable-length stream-cipher mode. Its round parameter follows the standard
terminology: one round applies four quarter rounds, alternating columns and
diagonals.

.. doctest::

   >>> from claasp.primitives import ChaCha
   >>> toy = ChaCha(number_of_rounds=1, word_size=8, rotations=(4, 3, 2, 1))
   >>> f"{toy.evaluate(1 << 120):032x}"
   '81000000ad0000005600000046000000'

The implementation is a typed word graph built only from modular addition,
XOR, rotation, and concatenation. The round count uses the standard convention
and fixed tests cover the ChaCha20 permutation plus reduced toy instances.

Salsa
-----

``Salsa`` is likewise the fixed-length unkeyed word permutation. Column and
row rounds alternate, and the public count uses standard full rounds.

.. doctest::

   >>> from claasp.primitives import Salsa
   >>> output = Salsa(number_of_rounds=2).evaluate(1 << (15 * 32))
   >>> f"{output:0128x}"[:32]
   '8186a22d0040a2848247921006929051'

Sparse and dense test vectors and batch evaluation use the same typed modular
addition, rotation, XOR, and concatenation components as other ARX primitives.

Trivium
-------

Trivium is published as a stream cipher, and a stream cipher is a stateful
variable-length construction rather than a CLAASP primitive. ``Trivium`` is
therefore the fixed-length function that its initialization and keystream
generation define: an 80-bit key and an 80-bit IV produce the first
``keystream_bit_size`` keystream bits after a chosen number of initialization
clocks. The key is the secret input, the IV is the public fixed-length data
input, and the output width is unrelated to the input width, so the primitive
is a keyed function rather than a keyed permutation.

Both parameters are free, so the same class covers the standard 1152-clock
instance and the small reduced instances used for algebraic evidence.
Boundary bit order follows the published eSTREAM vectors, where the bits of
each byte are numbered from its least significant bit.

.. doctest::

   >>> from claasp.primitives import Trivium
   >>> from claasp.primitives.block_functions.trivium import (
   ...     estream_bytes_to_bit_sequence)
   >>> key = estream_bytes_to_bit_sequence(0x80000000000000000000, 10)
   >>> keystream = Trivium(keystream_bit_size=32).evaluate(key=key, iv=0)
   >>> f"{estream_bytes_to_bit_sequence(keystream, 4):08x}"
   '38eb86ff'

Setting ``keystream_bit_size=0`` returns the complete 288-bit state instead,
which is the natural boundary for state-recovery and division-property work.
The graph is built only from the reusable ``Constant``, ``Xor``, and
``BitwiseAnd`` components; joins and the three shift registers are graph wiring
rather than private operations. Tests cover five published eSTREAM 80/80
vectors, an all-zero 256-bit keystream, scalar/batch parity, and reduced
instances checked against an independent transcription of the specification
pseudocode.
