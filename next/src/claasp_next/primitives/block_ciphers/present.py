"""Bit-oriented PRESENT block primitive."""

from claasp_next.components import Add, BitVectorSBox, Constant, Permutation
from claasp_next.graph import Primitive, Port, ValueType
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
class Present(Primitive):
    """Construct PRESENT with a 64-bit block and an 80- or 128-bit key.

    Inputs and output are MSB-first bit tuples. Use
    :func:`claasp_next.encoding.bits_from_int` and
    :func:`claasp_next.encoding.int_from_bits` at integer-facing boundaries.

    EXAMPLES::

        >>> from claasp_next.primitives import Present
        >>> primitive = Present()
        >>> hex(primitive.evaluate(plaintext=0, key=0))
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
                (state, key[:64]), component_id=f"add_round_key_{round_number}"
            ))
            substituted_nibbles = []
            for nibble in range(16):
                start = 4 * nibble
                substituted = self.add_component(BitVectorSBox(
                    state[start:start + 4],
                    PRESENT_SBOX,
                    component_id=f"sbox_{round_number}_{nibble}",
                ))
                substituted_nibbles.append(substituted)
            substituted_state = self.join(*substituted_nibbles)
            state = self.add_component(Permutation(
                substituted_state, P_LAYER_MAPPING, component_id=f"p_layer_{round_number}"
            ))
            key = self._update_key(key, round_number, key_type, counter_type, key_bit_size)

        state = self.add_component(Add(
            (state, key[:64]), component_id="final_add_round_key"
        ))
        self.set_output(state)

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
            key, rotation_mapping, component_id=f"key_rotate_{round_number}"
        ))
        high_nibble = self.add_component(BitVectorSBox(
            rotated[0:4], PRESENT_SBOX, component_id=f"key_sbox_{round_number}"
        ))
        prefix = [high_nibble]
        remaining_start = 4
        if key_bit_size == 128:
            second_nibble = self.add_component(BitVectorSBox(
                rotated[4:8],
                PRESENT_SBOX,
                component_id=f"key_sbox_second_{round_number}",
            ))
            prefix.append(second_nibble)
            remaining_start = 8
        substituted = self.join(*prefix, rotated[remaining_start:key_bit_size])
        counter_bits = tuple(
            (round_number >> position) & 1 for position in range(4, -1, -1)
        )
        counter = self.add_component(Constant(
            counter_type, counter_bits, component_id=f"key_counter_{round_number}"
        ))
        counter_start = 60 if key_bit_size == 80 else 61
        counter_xor = self.add_component(Add(
            (substituted[counter_start:counter_start + 5], counter),
            component_id=f"key_counter_xor_{round_number}",
        ))
        return self.join(
            substituted[:counter_start],
            counter_xor,
            substituted[counter_start + 5:key_bit_size],
        )


class Present80(Present):
    """Convenience constructor for the PRESENT-80 variant."""

    def __init__(self, number_of_rounds: int = 31) -> None:
        super().__init__(key_bit_size=80, number_of_rounds=number_of_rounds)
