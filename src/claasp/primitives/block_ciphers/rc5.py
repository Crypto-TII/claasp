"""RC5 variable-word block primitive."""

from decimal import Decimal, localcontext
from math import ceil, log10

from claasp.domains import Bit, Word
from claasp.graph import Primitive, ValueType

from ._word_graph import (
    add,
    byte_swap,
    concatenate,
    constant,
    low_bits,
    rotate,
    select,
    variable_rotate,
    xor,
)


def _magic_constants(width):
    with localcontext() as context:
        context.prec = ceil(width * log10(2)) + 25
        scale = Decimal(2) ** width
        p = int((Decimal(1).exp() - 2) * scale) | 1
        phi = (Decimal(1) + Decimal(5).sqrt()) / 2
        q = int((phi - 1) * scale) | 1
    return p, q


class RC5(Primitive):
    """RC5-w/r/b for byte-aligned words and keys, including an empty key.

    EXAMPLES::

        >>> primitive = RC5()
        >>> inputs = {name: 0 for name in primitive.graph.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0xd9dd7e74', 32)
    """

    def __init__(self, number_of_rounds=16, word_size=16, key_size=64):
        if word_size < 8 or word_size % 8:
            raise ValueError("RC5 word_size must be byte-aligned and at least 8")
        if not 0 <= number_of_rounds <= 255 or not 0 <= key_size <= 2040:
            raise ValueError("RC5 rounds or key size lies outside the specification")
        if key_size not in (0, 1) and key_size % 8:
            raise ValueError("this typed RC5 graph requires a byte-aligned nonempty key")
        key_type = (
            ValueType(Bit(), (1,)) if key_size in (0, 1) else ValueType(Word(8), (key_size // 8,))
        )
        byte_count = word_size // 8
        super().__init__(
            "rc5", {"key": key_type, "plaintext": ValueType(Word(8), (2 * byte_count,))}
        )
        self._builder.add_round()

        def pack_little_endian(byte_selection):
            byte_selection = tuple(reversed(tuple(byte_selection)))
            joined = self._builder.join(*byte_selection)
            return self._builder.pack_bits(self._builder.unpack_bits(joined), word_size)

        if key_size in (0, 1):
            key_words = [constant(self, word_size, 0)]
        else:
            key_bytes = self.graph.input("key")
            key_words = []
            count = max(1, ceil((key_size // 8) / byte_count))
            for index in range(count):
                chunk = [
                    select(key_bytes, byte)
                    for byte in range(
                        index * byte_count, min((index + 1) * byte_count, key_size // 8)
                    )
                ]
                while len(chunk) < byte_count:
                    # RC5 pads the last little-endian key word with zero bytes.
                    zero = constant(self, 8, 0)
                    chunk.append(zero)
                key_words.append(pack_little_endian(chunk))
        p, q = _magic_constants(word_size)
        amount_width = word_size.bit_length() - 1
        schedule = [
            constant(self, word_size, p + index * q) for index in range(2 * (number_of_rounds + 1))
        ]
        a = b = constant(self, word_size, 0)
        i = j = 0
        for _ in range(3 * max(len(schedule), len(key_words))):
            a = rotate(self, add(self, schedule[i], a, b), -3)
            schedule[i] = a
            amount = low_bits(self, add(self, a, b), amount_width)
            b = variable_rotate(self, add(self, key_words[j], a, b), amount, left=True)
            key_words[j] = b
            i = (i + 1) % len(schedule)
            j = (j + 1) % len(key_words)

        plain_bytes = self.graph.input("plaintext")
        a = add(
            self,
            pack_little_endian([select(plain_bytes, i) for i in range(byte_count)]),
            schedule[0],
        )
        b = add(
            self,
            pack_little_endian([select(plain_bytes, i) for i in range(byte_count, 2 * byte_count)]),
            schedule[1],
        )
        for round_number in range(number_of_rounds):
            self._builder.add_round()
            a = add(
                self,
                variable_rotate(self, xor(self, a, b), low_bits(self, b, amount_width), left=True),
                schedule[2 * round_number + 2],
            )
            b = add(
                self,
                variable_rotate(self, xor(self, b, a), low_bits(self, a, amount_width), left=True),
                schedule[2 * round_number + 3],
            )
        self._builder.set_output(
            concatenate(self, byte_swap(self, a, word_size), byte_swap(self, b, word_size))
        )
