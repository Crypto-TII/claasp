"""Word-oriented Speck block cipher."""

from claasp_next.components import Concatenate, Constant, ModularAdd, Rotate, Xor
from claasp_next.core import Cipher, Port, Selection, ValueType
from claasp_next.domains import Word


class SpeckBlockCipher(Cipher):
    """Construct Speck64/128 as a graph over 32-bit logical units.

    Inputs use the word ordering from the designers' implementation guide:
    ``plaintext=(Pt[1], Pt[0])`` and ``key=(K[3], K[2], K[1], K[0])``.

    EXAMPLES::

        >>> from claasp_next.evaluators import ScalarEvaluator
        >>> cipher = SpeckBlockCipher()
        >>> result = ScalarEvaluator().evaluate(cipher, {
        ...     "plaintext": (0x3b726574, 0x7475432d),
        ...     "key": (0x1b1a1918, 0x13121110, 0x0b0a0908, 0x03020100),
        ... })
        >>> tuple(hex(word) for word in result.output)
        ('0x8c6fa548', '0x454e028b')
    """

    def __init__(self, number_of_rounds: int = 27) -> None:
        if not isinstance(number_of_rounds, int) or isinstance(number_of_rounds, bool):
            raise TypeError("number_of_rounds must be an integer")
        if number_of_rounds <= 0 or number_of_rounds > 27:
            raise ValueError("Speck64/128 requires between 1 and 27 rounds")

        word_type = ValueType(Word(32), (1,))
        super().__init__(
            "speck_64_128",
            {
                "plaintext": ValueType(Word(32), (2,)),
                "key": ValueType(Word(32), (4,)),
            },
        )
        plaintext = self.input("plaintext")
        key = self.input("key")
        x: Port | Selection = plaintext.select(0)
        y: Port | Selection = plaintext.select(1)
        schedule = [key.select(2), key.select(1), key.select(0)]
        round_key: Port | Selection = key.select(3)

        for round_number in range(number_of_rounds):
            self.add_round()
            x, y = self._round_function(x, y, round_key, f"round_{round_number}")
            if round_number + 1 < number_of_rounds:
                schedule_index = round_number % 3
                counter = self.add_component(Constant(
                    f"key_constant_{round_number}", word_type, (round_number,)
                ))
                schedule[schedule_index], round_key = self._round_function(
                    schedule[schedule_index],
                    round_key,
                    counter,
                    f"key_{round_number}",
                )

        output = self.add_component(Concatenate(
            "cipher_output", (self._selection(x), self._selection(y))
        ))
        self.set_output(output.select_all())

    @staticmethod
    def _selection(value: Port | Selection) -> Selection:
        return value if isinstance(value, Selection) else value.select_all()

    def _round_function(
        self,
        x: Port | Selection,
        y: Port | Selection,
        key: Port | Selection,
        prefix: str,
    ) -> tuple[Port, Port]:
        rotated_x = self.add_component(Rotate(
            f"{prefix}_rotate_right", self._selection(x), 8, "right"
        ))
        added_x = self.add_component(ModularAdd(
            f"{prefix}_modular_add", (rotated_x.select_all(), self._selection(y))
        ))
        new_x = self.add_component(Xor(
            f"{prefix}_xor_key", (added_x.select_all(), self._selection(key))
        ))
        rotated_y = self.add_component(Rotate(
            f"{prefix}_rotate_left", self._selection(y), 3, "left"
        ))
        new_y = self.add_component(Xor(
            f"{prefix}_xor_xy", (rotated_y.select_all(), new_x.select_all())
        ))
        return new_x, new_y
