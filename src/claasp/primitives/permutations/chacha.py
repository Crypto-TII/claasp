"""Reference ChaCha implementation following the designers' pseudocode."""

from claasp.components import ModularAdd, Rotate, Xor
from claasp.domains import Word
from claasp.graph import Primitive, PrimitiveKind, ValueType

_COLUMNS = ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15))
_DIAGONALS = ((0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14))


class ChaCha(Primitive):
    """Build ChaCha using the variables and assignments in its pseudocode.

    ``number_of_rounds`` uses the standard ChaCha convention: one round
    applies four complete quarter rounds, alternating columns and diagonals.
    The standard permutation has 20 rounds.

    The input and output are sixteen words packed from word 0 (most
    significant) through word 15 (least significant), matching CLAASP's
    retained vectors.

    Component identifiers are intentionally omitted: CLAASP assigns stable
    identifiers when each operation is added to the current round.

    EXAMPLES::

        >>> state = int("617078653320646e79622d326b206574"
        ...             "03020100070605040b0a09080f0e0d0c"
        ...             "13121110171615141b1a19181f1e1d1c"
        ...             "00000001090000004a00000000000000", 16)
        >>> hex(ChaCha().evaluate(state))
        '0x837778abe238d763a67ae21e5950bb2fc4f2d0c7fc62bb2f8fa018fc3f5ec7b7335271c2f29489f3eabda8fc82e46ebdd19c12b4b04e16de9e83d0cb4e3c50a2'
    """

    def __init__(
        self,
        number_of_rounds: int = 20,
        *,
        word_size: int = 32,
        rotations: tuple[int, int, int, int] = (16, 12, 8, 7),
    ) -> None:
        number_of_rounds = Primitive.validate_positive_integer(
            number_of_rounds,
            name="number_of_rounds",
        )
        word_size = Primitive.validate_positive_integer(word_size, name="word_size")
        if len(rotations) != 4 or any(
            not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < word_size
            for value in rotations
        ):
            raise ValueError("rotations must contain four integers in range(word_size)")

        super().__init__(
            "chacha",
            {"state": ValueType(Word(word_size), (16,))},
            kind=PrimitiveKind.PERMUTATION,
        )
        state = [self.input("state")[index] for index in range(16)]

        def quarter_round(a, b, c, d):
            a = self.add_component(ModularAdd((a, b)))
            d = self.add_component(Xor((d, a)))
            d = self.add_component(Rotate(d, rotations[0], "left"))
            c = self.add_component(ModularAdd((c, d)))
            b = self.add_component(Xor((b, c)))
            b = self.add_component(Rotate(b, rotations[1], "left"))
            a = self.add_component(ModularAdd((a, b)))
            d = self.add_component(Xor((d, a)))
            d = self.add_component(Rotate(d, rotations[2], "left"))
            c = self.add_component(ModularAdd((c, d)))
            b = self.add_component(Xor((b, c)))
            b = self.add_component(Rotate(b, rotations[3], "left"))
            return a, b, c, d

        for round_number in range(number_of_rounds):
            self.add_round()
            groups = _COLUMNS if round_number % 2 == 0 else _DIAGONALS
            for a, b, c, d in groups:
                state[a], state[b], state[c], state[d] = quarter_round(
                    state[a],
                    state[b],
                    state[c],
                    state[d],
                )
            self.add_round_state(*state)

        self.set_output(state)
