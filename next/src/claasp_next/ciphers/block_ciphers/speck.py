"""Word-oriented Speck block cipher."""

from claasp_next.components import Concatenate, Constant, ModularAdd, Rotate, Xor
from claasp_next.core import Cipher, Port, Selection, ValueType
from claasp_next.domains import Word

PARAMETERS_CONFIGURATION_LIST = (
    {"block_bit_size": 32, "key_bit_size": 64, "number_of_rounds": 22},
    {"block_bit_size": 48, "key_bit_size": 72, "number_of_rounds": 22},
    {"block_bit_size": 48, "key_bit_size": 96, "number_of_rounds": 23},
    {"block_bit_size": 64, "key_bit_size": 96, "number_of_rounds": 26},
    {"block_bit_size": 64, "key_bit_size": 128, "number_of_rounds": 27},
    {"block_bit_size": 96, "key_bit_size": 96, "number_of_rounds": 28},
    {"block_bit_size": 96, "key_bit_size": 144, "number_of_rounds": 29},
    {"block_bit_size": 128, "key_bit_size": 128, "number_of_rounds": 32},
    {"block_bit_size": 128, "key_bit_size": 192, "number_of_rounds": 33},
    {"block_bit_size": 128, "key_bit_size": 256, "number_of_rounds": 34},
)


class SpeckBlockCipher(Cipher):
    """Construct a standard Speck variant as a graph over word units.

    Inputs use the word ordering from the designers' implementation guide:
    ``plaintext=(Pt[1], Pt[0])`` and ``key=(K[3], K[2], K[1], K[0])``.

    EXAMPLES::

        >>> from claasp_next.ciphers import SpeckBlockCipher
        >>> cipher = SpeckBlockCipher(block_bit_size=64, key_bit_size=128)
        >>> plaintext = 0x3B7265747475432D
        >>> key = 0x1B1A1918131211100B0A090803020100
        >>> hex(cipher.evaluate(plaintext, key))
        '0x8c6fa548454e028b'
    """

    def __init__(
        self,
        block_bit_size: int = 32,
        key_bit_size: int = 64,
        number_of_rounds: int | None = None,
        rotation_alpha: int | None = None,
        rotation_beta: int | None = None,
    ) -> None:
        configuration = next(
            (
                item
                for item in PARAMETERS_CONFIGURATION_LIST
                if item["block_bit_size"] == block_bit_size
                and item["key_bit_size"] == key_bit_size
            ),
            None,
        )
        if configuration is None:
            raise ValueError("unsupported Speck block/key size combination")
        standard_rounds = configuration["number_of_rounds"]
        rounds = standard_rounds if number_of_rounds is None else number_of_rounds
        if not isinstance(rounds, int) or isinstance(rounds, bool):
            raise TypeError("number_of_rounds must be an integer")
        if rounds <= 0 or rounds > standard_rounds:
            raise ValueError(
                f"Speck{block_bit_size}/{key_bit_size} requires between 1 and "
                f"{standard_rounds} rounds"
            )

        word_size = block_bit_size // 2
        alpha = (7 if word_size == 16 else 8) if rotation_alpha is None else rotation_alpha
        beta = (2 if word_size == 16 else 3) if rotation_beta is None else rotation_beta
        for name, amount in (("rotation_alpha", alpha), ("rotation_beta", beta)):
            if not isinstance(amount, int) or isinstance(amount, bool) or not 0 <= amount < word_size:
                raise ValueError(f"{name} must be an integer in range({word_size})")
        key_word_count = key_bit_size // word_size

        word_type = ValueType(Word(word_size), (1,))
        super().__init__(
            "speck",
            {
                "plaintext": ValueType(Word(word_size), (2,)),
                "key": ValueType(Word(word_size), (key_word_count,)),
            },
        )
        plaintext = self.input("plaintext")
        key = self.input("key")
        x: Port | Selection = plaintext[0]
        y: Port | Selection = plaintext[1]
        schedule = [key[position] for position in range(key_word_count - 2, -1, -1)]
        round_key: Port | Selection = key[key_word_count - 1]

        for round_number in range(rounds):
            self.add_round()
            x, y = self._round_function(x, y, round_key, f"round_{round_number}", alpha, beta)
            if round_number + 1 < rounds:
                schedule_index = round_number % len(schedule)
                counter = self.add_component(Constant(
                    word_type, (round_number,), component_id=f"key_constant_{round_number}"
                ))
                schedule[schedule_index], round_key = self._round_function(
                    schedule[schedule_index],
                    round_key,
                    counter,
                    f"key_{round_number}",
                    alpha,
                    beta,
                )

        output = self.add_component(Concatenate(
            (x, y), component_id="cipher_output"
        ))
        self.set_output(output)

    @staticmethod
    def _selection(value: Port | Selection) -> Selection:
        return value if isinstance(value, Selection) else value.select_all()

    def _round_function(
        self,
        x: Port | Selection,
        y: Port | Selection,
        key: Port | Selection,
        prefix: str,
        alpha: int,
        beta: int,
    ) -> tuple[Port, Port]:
        rotated_x = self.add_component(Rotate(
            x, alpha, "right", component_id=f"{prefix}_rotate_right"
        ))
        added_x = self.add_component(ModularAdd(
            (rotated_x, y), component_id=f"{prefix}_modular_add"
        ))
        new_x = self.add_component(Xor(
            (added_x, key), component_id=f"{prefix}_xor_key"
        ))
        rotated_y = self.add_component(Rotate(
            y, beta, "left", component_id=f"{prefix}_rotate_left"
        ))
        new_y = self.add_component(Xor(
            (rotated_y, new_x), component_id=f"{prefix}_xor_xy"
        ))
        return new_x, new_y
