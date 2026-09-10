"""AES-128 over byte-sized binary-extension-field units."""

from claasp_next.components import Add, Concatenate, Constant, LinearMap, Permutation, SBox
from claasp_next.core import Cipher, Port, ValueType
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


class AES128BlockCipher(Cipher):
    """Construct AES-128 with bytes represented as ``GF(2^8)`` units.

    Plaintext, key, and output are 16-byte tuples in the order used by FIPS
    197 hexadecimal vectors.

    EXAMPLES::

        >>> from claasp_next.evaluators import ScalarEvaluator
        >>> cipher = AES128BlockCipher()
        >>> plaintext = tuple(bytes.fromhex("00112233445566778899aabbccddeeff"))
        >>> key = tuple(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
        >>> result = ScalarEvaluator().evaluate(cipher, {"plaintext": plaintext, "key": key})
        >>> bytes(result.output).hex()
        '69c4e0d86a7b0430d8cdb78070b4c55a'
    """

    def __init__(self, number_of_rounds: int = 10) -> None:
        if not isinstance(number_of_rounds, int) or isinstance(number_of_rounds, bool):
            raise TypeError("number_of_rounds must be an integer")
        if number_of_rounds <= 0 or number_of_rounds > 10:
            raise ValueError("AES-128 requires between 1 and 10 rounds")
        byte = BinaryExtensionField(8, 0x11B)
        state_type = ValueType(byte, (16,))
        word_type = ValueType(byte, (4,))
        super().__init__("aes_128", {"plaintext": state_type, "key": state_type})

        self.add_round()
        state = self.add_component(Add(
            "initial_add_round_key",
            (self.input("plaintext").select_all(), self.input("key").select_all()),
        ))
        round_key = self.input("key")

        for round_number in range(1, number_of_rounds + 1):
            self.add_round()
            round_key = self._expand_round_key(round_key, round_number, word_type)
            state = self.add_component(SBox(
                f"sub_bytes_{round_number}", state.select_all(), AES_SBOX
            ))
            state = self.add_component(Permutation(
                f"shift_rows_{round_number}", state.select_all(), SHIFT_ROWS_MAPPING
            ))
            if round_number != 10:
                state = self.add_component(LinearMap(
                    f"mix_columns_{round_number}", state.select_all(), MIX_COLUMNS_MATRIX
                ))
            state = self.add_component(Add(
                f"add_round_key_{round_number}",
                (state.select_all(), round_key.select_all()),
            ))

        self.set_output(state.select_all())

    def _expand_round_key(self, key: Port, round_number: int, word_type: ValueType) -> Port:
        rotated = key.select(13, 14, 15, 12)
        substituted = self.add_component(SBox(
            f"key_sub_word_{round_number}", rotated, AES_SBOX
        ))
        constant = self.add_component(Constant(
            f"key_round_constant_{round_number}",
            word_type,
            (ROUND_CONSTANTS[round_number - 1], 0, 0, 0),
        ))
        temporary = self.add_component(Add(
            f"key_add_constant_{round_number}",
            (substituted.select_all(), constant.select_all()),
        ))
        words = []
        previous: Port | None = None
        for word_index in range(4):
            left = key.select(*range(4 * word_index, 4 * word_index + 4))
            right = temporary.select_all() if previous is None else previous.select_all()
            previous = self.add_component(Add(
                f"key_word_{round_number}_{word_index}", (left, right)
            ))
            words.append(previous.select_all())
        return self.add_component(Concatenate(f"round_key_{round_number}", words))
