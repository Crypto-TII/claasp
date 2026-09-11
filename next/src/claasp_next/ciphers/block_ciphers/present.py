"""Bit-oriented PRESENT block cipher."""

from claasp_next.components import Add, BitVectorSBox, Concatenate, Constant, Permutation
from claasp_next.core import Cipher, Port, ValueType
from claasp_next.domains import Bit

PRESENT_SBOX = (0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2)


def _p_layer_mapping() -> tuple[int, ...]:
    mapping = [0] * 64
    for input_lsb_position in range(64):
        output_lsb_position = (
            63 if input_lsb_position == 63 else 16 * input_lsb_position % 63
        )
        mapping[63 - output_lsb_position] = 63 - input_lsb_position
    return tuple(mapping)


P_LAYER_MAPPING = _p_layer_mapping()
class PresentBlockCipher(Cipher):
    """Construct PRESENT with a 64-bit block and an 80- or 128-bit key.

    Inputs and output are MSB-first bit tuples. Use
    :func:`claasp_next.encoding.bits_from_int` and
    :func:`claasp_next.encoding.int_from_bits` at integer-facing boundaries.

    EXAMPLES::

        >>> from claasp_next import bits_from_int, int_from_bits
        >>> from claasp_next.evaluators import ScalarEvaluator
        >>> cipher = PresentBlockCipher()
        >>> result = ScalarEvaluator().evaluate(cipher, {
        ...     "plaintext": bits_from_int(0, 64),
        ...     "key": bits_from_int(0, 80),
        ... })
        >>> hex(int_from_bits(result.output))
        '0x5579c1387b228445'
    """

    def __init__(self, key_bit_size: int = 80, number_of_rounds: int = 31) -> None:
        if key_bit_size not in (80, 128):
            raise ValueError("PRESENT key_bit_size must be 80 or 128")
        if not isinstance(number_of_rounds, int) or isinstance(number_of_rounds, bool):
            raise TypeError("number_of_rounds must be an integer")
        if number_of_rounds <= 0 or number_of_rounds > 31:
            raise ValueError("PRESENT requires between 1 and 31 rounds")
        bit = Bit()
        state_type = ValueType(bit, (64,))
        key_type = ValueType(bit, (key_bit_size,))
        counter_type = ValueType(bit, (5,))
        super().__init__("present", {"plaintext": state_type, "key": key_type})
        state = self.input("plaintext")
        key = self.input("key")

        for round_number in range(1, number_of_rounds + 1):
            self.add_round()
            state = self.add_component(Add(
                f"add_round_key_{round_number}",
                (state.select_all(), key.select(*range(64))),
            ))
            substituted_nibbles = []
            for nibble in range(16):
                start = 4 * nibble
                substituted = self.add_component(BitVectorSBox(
                    f"sbox_{round_number}_{nibble}",
                    state.select(*range(start, start + 4)),
                    PRESENT_SBOX,
                ))
                substituted_nibbles.append(substituted.select_all())
            substituted_state = self.add_component(Concatenate(
                f"sbox_layer_{round_number}", substituted_nibbles
            ))
            state = self.add_component(Permutation(
                f"p_layer_{round_number}", substituted_state.select_all(), P_LAYER_MAPPING
            ))
            key = self._update_key(key, round_number, key_type, counter_type, key_bit_size)

        state = self.add_component(Add(
            "final_add_round_key", (state.select_all(), key.select(*range(64)))
        ))
        self.set_output(state.select_all())

    def _update_key(
        self,
        key: Port,
        round_number: int,
        key_type: ValueType,
        counter_type: ValueType,
        key_bit_size: int,
    ) -> Port:
        rotation_mapping = tuple(
            (position + 61) % key_bit_size for position in range(key_bit_size)
        )
        rotated = self.add_component(Permutation(
            f"key_rotate_{round_number}", key.select_all(), rotation_mapping
        ))
        high_nibble = self.add_component(BitVectorSBox(
            f"key_sbox_{round_number}", rotated.select(0, 1, 2, 3), PRESENT_SBOX
        ))
        prefix = [high_nibble.select_all()]
        remaining_start = 4
        if key_bit_size == 128:
            second_nibble = self.add_component(BitVectorSBox(
                f"key_sbox_second_{round_number}",
                rotated.select(4, 5, 6, 7),
                PRESENT_SBOX,
            ))
            prefix.append(second_nibble.select_all())
            remaining_start = 8
        substituted = self.add_component(Concatenate(
            f"key_substituted_{round_number}",
            (*prefix, rotated.select(*range(remaining_start, key_bit_size))),
        ))
        counter_bits = tuple(
            (round_number >> position) & 1 for position in range(4, -1, -1)
        )
        counter = self.add_component(Constant(
            f"key_counter_{round_number}", counter_type, counter_bits
        ))
        counter_start = 60 if key_bit_size == 80 else 61
        counter_xor = self.add_component(Add(
            f"key_counter_xor_{round_number}",
            (substituted.select(*range(counter_start, counter_start + 5)), counter.select_all()),
        ))
        return self.add_component(Concatenate(
            f"round_key_state_{round_number + 1}",
            (
                substituted.select(*range(counter_start)),
                counter_xor.select_all(),
                substituted.select(*range(counter_start + 5, key_bit_size)),
            ),
        ))


class Present80BlockCipher(PresentBlockCipher):
    """Convenience constructor for the PRESENT-80 variant."""

    def __init__(self, number_of_rounds: int = 31) -> None:
        super().__init__(key_bit_size=80, number_of_rounds=number_of_rounds)
