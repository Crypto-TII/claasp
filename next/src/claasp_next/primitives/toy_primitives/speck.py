"""Nonstandard Speck8/16 fixture, distinct from the official catalogue."""

from claasp_next.components import Constant, ModularAdd, Rotate, Xor
from claasp_next.domains import Word
from claasp_next.graph import Primitive, PrimitiveKind, ValueType


class ToySpeck(Primitive):
    """Four-bit-word regression fixture using the legacy toy rotations."""

    def __init__(self, number_of_rounds: int = 4) -> None:
        if not isinstance(number_of_rounds, int) or isinstance(number_of_rounds, bool):
            raise ValueError("ToySpeck requires an integer round count")
        rounds = Primitive.validate_number_of_rounds(
            number_of_rounds, default=4, maximum=4, name="ToySpeck",
        )
        word_type = ValueType(Word(4), (1,))
        super().__init__(
            "toy_speck",
            {"plaintext": ValueType(Word(4), (2,)), "key": ValueType(Word(4), (4,))},
            kind=PrimitiveKind.BLOCK_CIPHER,
        )
        x, y = self.input("plaintext")[0], self.input("plaintext")[1]
        key = self.input("key")
        schedule = [key[position] for position in (2, 1, 0)]
        round_key = key[3]

        def round_function(x, y, key):
            x = self.add_component(Rotate(x, 0, "right"))
            x = self.add_component(ModularAdd((x, y)))
            x = self.add_component(Xor((x, key)))
            y = self.add_component(Rotate(y, 3, "left"))
            y = self.add_component(Xor((y, x)))
            return x, y

        for round_number in range(rounds):
            self.add_round()
            x, y = round_function(x, y, round_key)
            if round_number + 1 < rounds:
                index = round_number % len(schedule)
                constant = self.add_component(Constant(word_type, (round_number,)))
                schedule[index], round_key = round_function(schedule[index], round_key, constant)
        self.set_output((x, y))
