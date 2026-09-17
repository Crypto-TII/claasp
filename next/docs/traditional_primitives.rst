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

   >>> from claasp_next.primitives import Speck
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

   >>> from claasp_next.primitives import Simon
   >>> simon = Simon()
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

   >>> from claasp_next.primitives import AES
   >>> plaintext = 0x00112233445566778899AABBCCDDEEFF
   >>> key = 0x000102030405060708090A0B0C0D0E0F
   >>> f"{AES().evaluate(plaintext, key):032x}"
   '69c4e0d86a7b0430d8cdb78070b4c55a'

The graph supports AES-128, AES-192, and AES-256 key expansion. SubBytes uses a reusable typed
``SBox`` lookup, ShiftRows is a domain-neutral ``Permutation``, MixColumns is
a ``LinearMap`` over the byte field, and AddRoundKey is field addition.
``number_of_rounds`` constructs a prefix of the standard primitive; MixColumns
is omitted only in standard round 10.

AES is also the first primitive with interchangeable graph realizations. The
default ``lookup`` realization exposes each SubBytes operation as an ``SBox``;
the ``algebraic`` realization exposes field inversion and the binary affine
map as separate reusable components. They have the same parameters and
external input/output contract:

.. doctest::

   >>> lookup = AES(realization="lookup")
   >>> algebraic = AES(realization="algebraic")
   >>> lookup.evaluate(plaintext, key) == algebraic.evaluate(plaintext, key)
   True
   >>> [item.name for item in AES.available_realizations()]
   ['lookup', 'algebraic']

Users may request a realization explicitly. An analysis compiler can instead
select deterministically from declared capabilities:

.. doctest::

   >>> AES.for_capabilities({"sbox_semantics"}).realization.name
   'lookup'
   >>> AES.for_capabilities({"algebraic_semantics"}).realization.name
   'algebraic'

Automatic selection is part of reproducibility: results must retain the
chosen realization, and an unsupported requirement raises an error rather
than silently changing the analysis.

Selecting realizations in other families
-----------------------------------------

The same small API applies to every audited family. A realization name
chooses a graph explicitly, while a task states capabilities rather than
guessing from component identifiers:

.. doctest::

   >>> from claasp_next.primitives import Gift, Katan
   >>> gift = Gift.realize("sbox", number_of_rounds=2)
   >>> gift.realization_identity
   'gift:sbox'
   >>> Katan.for_capabilities(
   ...     {"feedback_register_semantics"}, number_of_rounds=2
   ... ).realization.name
   'feedback_register'

The canonical class keeps one external contract across its realizations.
For example, the word-oriented Simon boundary is unchanged when the explicit
legacy-regression S-box graph is requested:

.. doctest::

   >>> from claasp_next.primitives import Simon
   >>> word_graph = Simon.realize("word", number_of_rounds=2)
   >>> sbox_graph = Simon.realize("legacy_sbox", number_of_rounds=2)
   >>> word_graph.input("plaintext").value_type == sbox_graph.input("plaintext").value_type
   True
   >>> word_graph.evaluate(0x65656877, 0x1918111009080100) == sbox_graph.evaluate(0x65656877, 0x1918111009080100)
   True

Preferred capability selection is deterministic. A caller that requires a
single match can instead request the ``unique`` policy; ambiguity and an
unsupported capability are errors rather than implicit fallbacks.

Result provenance keeps graph and engine identities separate:

.. doctest::

   >>> result = gift.evaluate_with_trace(plaintext=0, key=0)
   >>> (result.realization.name, result.execution_engine.name)
   ('sbox', 'python_scalar')
   >>> result.trace.annotation.realization_identity
   'gift:sbox'

PRESENT
-------

PRESENT validates the individual-bit representation needed by Boolean
analysis backends. Its 4-bit S-box is a ``BitVectorSBox`` connecting four
separate ``Bit`` units, unlike AES's lookup over one byte-field unit.

.. doctest::

   >>> from claasp_next.primitives import Present80
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

   >>> from claasp_next.primitives import ChaCha
   >>> toy = ChaCha(number_of_rounds=1, word_size=8, rotations=(4, 3, 2, 1))
   >>> f"{toy.evaluate(1 << 120):032x}"
   '81000000ad0000005600000046000000'

The implementation is a typed word graph built only from modular addition,
XOR, rotation, and concatenation. The migrated tests retain the full
ChaCha20 permutation vector, two reduced toy vectors, and scalar/batch parity.
The legacy API counted alternating half-rounds; v5 intentionally uses the
standard round convention.

Salsa
-----

``Salsa`` is likewise the fixed-length unkeyed word permutation. Column and
row rounds alternate, and the public count uses standard full rounds instead
of the legacy implementation's internal half-round counter.

.. doctest::

   >>> from claasp_next.primitives import Salsa
   >>> output = Salsa(number_of_rounds=2).evaluate(1 << (15 * 32))
   >>> f"{output:0128x}"[:32]
   '8186a22d0040a2848247921006929051'

The retained sparse and dense legacy vectors and batch evaluation all use the
same typed modular-addition, rotation, XOR, and concatenation components as
other ARX primitives.

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

   >>> from claasp_next.primitives import Trivium
   >>> from claasp_next.primitives.block_functions.trivium import (
   ...     estream_bytes_to_bit_sequence)
   >>> key = estream_bytes_to_bit_sequence(0x80000000000000000000, 10)
   >>> keystream = Trivium(keystream_bit_size=32).evaluate(key=key, iv=0)
   >>> f"{estream_bytes_to_bit_sequence(keystream, 4):08x}"
   '38eb86ff'

Setting ``keystream_bit_size=0`` returns the complete 288-bit state instead,
which is the natural boundary for state-recovery and division-property work.
The graph is built only from the reusable ``Constant``, ``Xor``,
``BitwiseAnd``, and ``Concatenate`` components; the three shift registers are
graph wiring rather than a private feedback implementation. Tests retain five
published eSTREAM 80/80 vectors, the legacy CLAASP all-zero 256-bit keystream,
scalar/batch parity, and reduced instances checked against an independently
written transcription of the specification pseudocode.
