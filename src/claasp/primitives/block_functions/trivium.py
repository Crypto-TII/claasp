"""The fixed-length Trivium keystream function.

Trivium is published as a stream cipher, and a stream cipher is a stateful
variable-length construction rather than a CLAASP primitive category.  The
fixed-length primitive extracted here is the map

``(key, iv) -> the first keystream bits produced after N initialization clocks``

It is keyed by the 80-bit key, takes the public 80-bit initialization vector as
its fixed-length data input, and its output width is unrelated to its input
width, so it is a ``block_function`` and not a ``block_cipher``.  The M10.7
catalogue inventory records the same ``block_functions`` classification and the
class name ``Trivium`` for
``claasp/ciphers/stream_ciphers/trivium_stream_cipher.py``; M10.9b confirms it
against the final catalogue invariants.

The 288-bit state is written ``s1 .. s288`` as in the specification, with
registers ``A = s1..s93``, ``B = s94..s177`` and ``C = s178..s288``.  Each clock
computes

``t1 = s66 + s93``, ``t2 = s162 + s177``, ``t3 = s243 + s288``,
``z = t1 + t2 + t3``,

then shifts ``t3 + s286*s287 + s69`` into ``A``, ``t1 + s91*s92 + s171`` into
``B`` and ``t2 + s175*s176 + s264`` into ``C``.

Boundary bit order follows the published eSTREAM test-vector convention:
logical unit ``m`` of ``key`` is bit ``m % 8`` of key byte ``m // 8`` counted
from the least significant bit, and likewise for ``iv`` and for the keystream.
:func:`estream_bytes_to_bit_sequence` converts a published byte string to the
packed most-significant-bit-first integer this graph expects, and back.  In the
state, key unit ``m`` is loaded at ``s(80 - m)`` and IV unit ``m`` at
``s(173 - m)``; output unit ``m`` is the keystream bit ``z(m + 1)``.
"""

from claasp.components import BitwiseAnd, Constant, Xor
from claasp.domains import Word
from claasp.graph import Port, Primitive, Selection, ValueType

KEY_BIT_SIZE = 80
IV_BIT_SIZE = 80
STATE_BIT_SIZE = 288
STANDARD_INITIALIZATION_CLOCKS = 4 * 288

_BIT = ValueType(Word(1), (1,))
#: ``(tap_a, tap_b, and_left, and_right, feedback_tap)`` for ``t1``, ``t2`` and
#: ``t3``, using the specification's one-based state indices.
_REGISTERS = (
    (66, 93, 91, 92, 171),
    (162, 177, 175, 176, 264),
    (243, 288, 286, 287, 69),
)
#: ``(feedback_index, first_state_index, last_state_index)``: ``t3`` shifts into
#: register ``A``, ``t1`` into ``B`` and ``t2`` into ``C``.
_TARGETS = ((2, 1, 93), (0, 94, 177), (1, 178, 288))


def estream_bytes_to_bit_sequence(value: int, byte_length: int) -> int:
    """Convert an eSTREAM byte string to a packed Trivium bit sequence.

    ``value`` is a published hexadecimal byte string read as a big-endian
    integer of ``byte_length`` bytes.  The eSTREAM vectors number the bits of
    every byte from its least significant bit, so the conversion reverses the
    bits inside each byte.  It is its own inverse and is used for keys, IVs and
    keystreams alike.

    EXAMPLES::
        >>> from claasp.primitives.block_functions.trivium import (
        ...     estream_bytes_to_bit_sequence)
        >>> hex(estream_bytes_to_bit_sequence(0x8000, 2))
        '0x100'
        >>> estream_bytes_to_bit_sequence(0x100, 2) == 0x8000
        True
    """

    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError("value must be an integer")
    if not isinstance(byte_length, int) or isinstance(byte_length, bool) or byte_length <= 0:
        raise ValueError("byte_length must be a positive integer")
    if not 0 <= value < 1 << (8 * byte_length):
        raise ValueError("value does not fit the requested number of bytes")
    result = 0
    for index in range(byte_length):
        byte = (value >> (8 * (byte_length - 1 - index))) & 0xFF
        for bit in range(8):
            result = (result << 1) | ((byte >> bit) & 1)
    return result


class Trivium(Primitive):
    """Build the fixed-length Trivium keystream function as a typed bit graph.

    ``number_of_initialization_clocks`` is the number of state updates applied
    before the first keystream bit is read; the specification uses ``1152``.
    ``keystream_bit_size`` selects how many keystream bits are returned, and
    ``0`` returns the complete 288-bit state instead, which is the natural
    boundary for state-recovery and division-property work.  Both parameters
    are free so that reduced instances stay small enough for exact algebraic
    evidence.

    EXAMPLES::
        >>> from claasp.primitives import Trivium
        >>> from claasp.primitives.block_functions.trivium import (
        ...     estream_bytes_to_bit_sequence)
        >>> trivium = Trivium(keystream_bit_size=32)
        >>> key = estream_bytes_to_bit_sequence(0x80000000000000000000, 10)
        >>> keystream = trivium.evaluate(key=key, iv=0)
        >>> hex(estream_bytes_to_bit_sequence(keystream, 4))
        '0x38eb86ff'

    A reduced instance exposes the same graph with fewer clocks:

        >>> reduced = Trivium(number_of_initialization_clocks=13, keystream_bit_size=1)
        >>> len(reduced.rounds), reduced.evaluate(key=1 << 79, iv=0)
        (15, 1)


    EXAMPLES::

        >>> primitive = Trivium()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0xdf07fd641a9aa0d8', 64)
    """

    def __init__(
        self,
        number_of_initialization_clocks: int = STANDARD_INITIALIZATION_CLOCKS,
        keystream_bit_size: int = 64,
    ) -> None:
        clocks = number_of_initialization_clocks
        if not isinstance(clocks, int) or isinstance(clocks, bool):
            raise TypeError("number_of_initialization_clocks must be an integer")
        if clocks < 0:
            raise ValueError("number_of_initialization_clocks must not be negative")
        if not isinstance(keystream_bit_size, int) or isinstance(keystream_bit_size, bool):
            raise TypeError("keystream_bit_size must be an integer")
        if keystream_bit_size < 0:
            raise ValueError("keystream_bit_size must not be negative")

        super().__init__(
            "trivium",
            {
                "key": ValueType(Word(1), (KEY_BIT_SIZE,)),
                "iv": ValueType(Word(1), (IV_BIT_SIZE,)),
            },
        )
        self.number_of_initialization_clocks = clocks
        self.keystream_bit_size = keystream_bit_size

        self.add_round()
        zero = self.add_component(Constant(_BIT, (0,), component_id="zero"))[0]
        one = self.add_component(Constant(_BIT, (1,), component_id="one"))[0]
        key, iv = self.input("key"), self.input("iv")
        state: list[Port | Selection] = (
            # register A: s1..s80 hold the key, s81..s93 are zero
            [key[KEY_BIT_SIZE - 1 - index] for index in range(KEY_BIT_SIZE)]
            + [zero] * 13
            # register B: s94..s173 hold the IV, s174..s177 are zero
            + [iv[IV_BIT_SIZE - 1 - index] for index in range(IV_BIT_SIZE)]
            + [zero] * 4
            # register C: s178..s285 are zero and s286..s288 are one
            + [zero] * 108
            + [one] * 3
        )
        if len(state) != STATE_BIT_SIZE:
            raise AssertionError("Trivium state layout must cover exactly 288 bits")

        keystream = []
        for clock in range(clocks + keystream_bit_size):
            self.add_round()
            emitting = clock >= clocks
            state, keystream_bit = self._clock(state, emitting)
            if emitting:
                keystream.append(keystream_bit)
        self.set_output(keystream if keystream_bit_size else state)

    def _clock(self, state, emitting):
        """Apply one Trivium state update and optionally emit a keystream bit."""

        keystream_bit = None
        if emitting:
            keystream_bit = self.add_component(
                Xor([state[index - 1] for register in _REGISTERS for index in register[:2]])
            )
        feedback = []
        for tap_a, tap_b, and_left, and_right, feedback_tap in _REGISTERS:
            product = self.add_component(BitwiseAnd((state[and_left - 1], state[and_right - 1])))
            feedback.append(
                self.add_component(
                    Xor(
                        (
                            state[tap_a - 1],
                            state[tap_b - 1],
                            product,
                            state[feedback_tap - 1],
                        )
                    )
                )
            )
        updated = list(state)
        for source, start, stop in _TARGETS:
            updated[start - 1 : stop] = [feedback[source]] + state[start - 1 : stop - 1]
        return updated, keystream_bit
