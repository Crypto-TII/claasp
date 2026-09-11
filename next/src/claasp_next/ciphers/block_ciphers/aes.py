"""AES-128 over byte-sized binary-extension-field units."""

from claasp_next.components import Add, Concatenate, Constant, LinearMap, Permutation, SBox
from claasp_next.core import Cipher, Port, Selection, ValueType
from claasp_next.domains import BinaryExtensionField


def _gf_multiply(left: int, right: int) -> int:
    result = 0
    for _ in range(8):
        if right & 1:
            result ^= left
        carry = left & 0x80
        left = (left << 1) & 0xFF
        if carry:
            left ^= 0x1B
        right >>= 1
    return result


def _gf_power(value: int, exponent: int) -> int:
    result = 1
    while exponent:
        if exponent & 1:
            result = _gf_multiply(result, value)
        value = _gf_multiply(value, value)
        exponent >>= 1
    return result


def _rotate_byte(value: int, amount: int) -> int:
    return ((value << amount) | (value >> (8 - amount))) & 0xFF


AES_SBOX = tuple(
    inverse
    ^ _rotate_byte(inverse, 1)
    ^ _rotate_byte(inverse, 2)
    ^ _rotate_byte(inverse, 3)
    ^ _rotate_byte(inverse, 4)
    ^ 0x63
    for inverse in (_gf_power(value, 254) if value else 0 for value in range(256))
)


def _mix_columns_matrix() -> tuple[tuple[int, ...], ...]:
    column = (
        (2, 3, 1, 1),
        (1, 2, 3, 1),
        (1, 1, 2, 3),
        (3, 1, 1, 2),
    )
    rows = []
    for output_index in range(16):
        output_column, output_row = divmod(output_index, 4)
        row = [0] * 16
        for input_row, coefficient in enumerate(column[output_row]):
            row[4 * output_column + input_row] = coefficient
        rows.append(tuple(row))
    return tuple(rows)


MIX_COLUMNS_MATRIX = _mix_columns_matrix()
SHIFT_ROWS_MAPPING = tuple(4 * ((column + row) % 4) + row for column in range(4) for row in range(4))
ROUND_CONSTANTS = (1, 2, 4, 8, 16, 32, 64, 128, 27, 54)
PARAMETERS_CONFIGURATION_LIST = (
    {"key_bit_size": 128, "number_of_rounds": 10},
    {"key_bit_size": 192, "number_of_rounds": 12},
    {"key_bit_size": 256, "number_of_rounds": 14},
)


class AESBlockCipher(Cipher):
    """Construct AES-128, AES-192, or AES-256 over ``GF(2^8)`` bytes.

    Plaintext, key, and output are 16-byte tuples in the order used by FIPS
    197 hexadecimal vectors.

    EXAMPLES::

        >>> from claasp_next.evaluators import ScalarEvaluator
        >>> cipher = AESBlockCipher()
        >>> plaintext = tuple(bytes.fromhex("00112233445566778899aabbccddeeff"))
        >>> key = tuple(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
        >>> result = ScalarEvaluator().evaluate(cipher, {"plaintext": plaintext, "key": key})
        >>> bytes(result.output).hex()
        '69c4e0d86a7b0430d8cdb78070b4c55a'
    """

    def __init__(self, key_bit_size: int = 128, number_of_rounds: int | None = None) -> None:
        if key_bit_size not in (128, 192, 256):
            raise ValueError("AES key_bit_size must be 128, 192, or 256")
        self.Nk = key_bit_size // 32
        standard_rounds = {128: 10, 192: 12, 256: 14}[key_bit_size]
        rounds = standard_rounds if number_of_rounds is None else number_of_rounds
        if not isinstance(rounds, int) or isinstance(rounds, bool):
            raise TypeError("number_of_rounds must be an integer")
        if rounds <= 0 or rounds > standard_rounds:
            raise ValueError(
                f"AES-{key_bit_size} requires between 1 and {standard_rounds} rounds"
            )
        self.Nr = rounds
        byte = BinaryExtensionField(8, 0x11B)
        state_type = ValueType(byte, (16,))
        word_type = ValueType(byte, (4,))
        key_type = ValueType(byte, (key_bit_size // 8,))
        super().__init__("aes", {"plaintext": state_type, "key": key_type})

        self.add_round()
        state = self.add_component(Add(
            "initial_add_round_key",
            (self.input("plaintext").select_all(), self.input("key").select(*range(16))),
        ))
        expanded_words: list[Port | Selection] = [
            self.input("key").select(*range(4 * word, 4 * word + 4))
            for word in range(self.Nk)
        ]

        for round_number in range(1, rounds + 1):
            self.add_round()
            self._expand_words(expanded_words, 4 * (round_number + 1), word_type)
            round_key = self.add_component(Concatenate(
                f"round_key_{round_number}",
                tuple(self._selection(word) for word in expanded_words[4 * round_number:4 * round_number + 4]),
            ))
            state = self.add_component(SBox(
                f"sub_bytes_{round_number}", state.select_all(), AES_SBOX
            ))
            state = self.add_component(Permutation(
                f"shift_rows_{round_number}", state.select_all(), SHIFT_ROWS_MAPPING
            ))
            if round_number != standard_rounds:
                state = self.add_component(LinearMap(
                    f"mix_columns_{round_number}", state.select_all(), MIX_COLUMNS_MATRIX
                ))
            state = self.add_component(Add(
                f"add_round_key_{round_number}",
                (state.select_all(), round_key.select_all()),
            ))

        self.set_output(state.select_all())

    @staticmethod
    def _selection(value: Port | Selection) -> Selection:
        return value.select_all() if isinstance(value, Port) else value

    def _expand_words(
        self,
        words: list[Port | Selection],
        required_count: int,
        word_type: ValueType,
    ) -> None:
        while len(words) < required_count:
            word_index = len(words)
            temporary = self._selection(words[-1])
            if word_index % self.Nk == 0:
                expansion_index = word_index // self.Nk
                rotated = temporary.source.select(
                    temporary.positions[1],
                    temporary.positions[2],
                    temporary.positions[3],
                    temporary.positions[0],
                )
                substituted = self.add_component(SBox(
                    f"key_sub_word_{expansion_index}", rotated, AES_SBOX
                ))
                constant = self.add_component(Constant(
                    f"key_round_constant_{expansion_index}",
                    word_type,
                    (ROUND_CONSTANTS[expansion_index - 1], 0, 0, 0),
                ))
                temporary = self.add_component(Add(
                    f"key_add_constant_{expansion_index}",
                    (substituted.select_all(), constant.select_all()),
                )).select_all()
            elif self.Nk == 8 and word_index % self.Nk == 4:
                substituted = self.add_component(SBox(
                    f"key_sub_word_{word_index}", temporary, AES_SBOX
                ))
                temporary = substituted.select_all()
            word = self.add_component(Add(
                f"key_word_{word_index}",
                (self._selection(words[word_index - self.Nk]), temporary),
            ))
            words.append(word)


class AES128BlockCipher(AESBlockCipher):
    """Convenience constructor for AES-128."""

    def __init__(self, number_of_rounds: int = 10) -> None:
        super().__init__(key_bit_size=128, number_of_rounds=number_of_rounds)
