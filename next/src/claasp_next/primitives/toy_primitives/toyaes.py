"""Generalized small AES teaching family."""

from claasp_next.components import Add, Constant, LinearMap, Permutation, SBox
from claasp_next.composites.aes import AES_SBOX
from claasp_next.domains import BinaryExtensionField
from claasp_next.graph import Primitive, ValueType

SBOXES = {
    2: (0x0, 0x1, 0x1, 0x2),
    3: (0x0, 0x1, 0x5, 0x6, 0x7, 0x2, 0x3, 0x4),
    4: (0x0, 0x1, 0x9, 0xE, 0xD, 0xB, 0x7, 0x6, 0xF, 0x2, 0xC, 0x5, 0xA, 0x4, 0x3, 0x8),
    8: AES_SBOX,
}

IRREDUCIBLE_POLYNOMIALS = {2: 0x7, 3: 0xB, 4: 0x13, 8: 0x11B}

MIX_COLUMN_MATRICES = {
    (2, 2): ((2, 3), (3, 2)),
    (3, 2): ((2, 3), (3, 2)),
    (4, 2): ((2, 3), (3, 2)),
    (8, 2): ((2, 3), (3, 2)),
    (2, 3): ((1, 2, 2), (2, 1, 2), (2, 2, 1)),
    (3, 3): ((1, 2, 5), (5, 6, 5), (5, 5, 1)),
    (4, 3): ((8, 3, 4), (10, 6, 9), (3, 4, 12)),
    (8, 3): ((1, 2, 5), (5, 6, 5), (5, 5, 1)),
    (2, 4): ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2)),
    (3, 4): ((1, 7, 5, 5), (7, 2, 1, 3), (6, 3, 1, 2), (7, 5, 5, 7)),
    (4, 4): ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2)),
    (8, 4): ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2)),
}

ROUND_CONSTANT_WORDS = {
    2: (1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1),
    3: (1, 2, 4, 3, 6, 7, 5, 1, 2, 4, 3, 6, 7, 5, 1, 2),
    4: (1, 2, 4, 8, 3, 6, 12, 11, 5, 10, 7, 14, 15, 13, 9, 1),
    8: (1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A),
}


def _concat(primitive, items, component_id=None):
    del component_id
    return primitive.join(*items)


class ToyAES(Primitive):
    """AES-shaped family over 2-, 3-, 4-, or 8-bit binary fields.

    EXAMPLES::

        >>> primitive = ToyAES()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x66e94bd4ef8a2c3b', 127)
    """

    def __init__(self, number_of_rounds: int = 10, word_size: int = 8, state_size: int = 4) -> None:
        if word_size not in SBOXES:
            raise ValueError("word_size must be 2, 3, 4, or 8")
        if state_size not in (2, 3, 4):
            raise ValueError("state_size must be 2, 3, or 4")
        if not isinstance(number_of_rounds, int) or not 1 <= number_of_rounds <= 16:
            raise ValueError("number_of_rounds must be between 1 and 16")
        self.word_size = word_size
        self.state_size = state_size
        self.number_of_rounds = number_of_rounds
        self.mix_column_matrix = MIX_COLUMN_MATRICES[(word_size, state_size)]
        self.irreducible_polynomial = IRREDUCIBLE_POLYNOMIALS[word_size]
        field = BinaryExtensionField(word_size, self.irreducible_polynomial)
        state_type = ValueType(field, (state_size * state_size,))
        super().__init__(
            "toy_aes",
            {"key": state_type, "plaintext": state_type},
            provenance=(("derived_from", "AES"), ("purpose", "small-field teaching family")),
        )

        self.add_round()
        state = self.add_component(Add((self.input("key"), self.input("plaintext"))))
        round_key = self.input("key").select_all()
        shift_mapping = tuple(
            ((column + row) % state_size) * state_size + row
            for column in range(state_size)
            for row in range(state_size)
        )
        for round_number in range(number_of_rounds):
            if round_number:
                self.add_round()
            state = self.add_component(SBox(state, SBOXES[word_size]))
            state = self.add_component(Permutation(state, shift_mapping))
            if round_number != number_of_rounds - 1:
                columns = tuple(
                    self.add_component(
                        LinearMap(
                            state[tuple(range(column * state_size, (column + 1) * state_size))],
                            self.mix_column_matrix,
                        )
                    )
                    for column in range(state_size)
                )
                state = _concat(self, columns)

            old_columns = tuple(
                round_key[tuple(range(column * state_size, (column + 1) * state_size))]
                for column in range(state_size)
            )
            last = old_columns[-1]
            rotated = last[tuple(range(1, state_size)) + (0,)]
            substituted = self.add_component(SBox(rotated, SBOXES[word_size]))
            constant = self.add_component(
                Constant(
                    ValueType(field, (state_size,)),
                    (ROUND_CONSTANT_WORDS[word_size][round_number],) + (0,) * (state_size - 1),
                )
            )
            columns = [self.add_component(Add((substituted, constant, old_columns[0])))]
            for column in range(1, state_size):
                columns.append(self.add_component(Add((columns[-1], old_columns[column]))))
            round_key = _concat(self, columns)
            state = self.add_component(Add((state, round_key)))
        self.set_output(state)
