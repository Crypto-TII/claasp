"""Fancy mixed-operation testing primitive."""

from claasp_next.components import LinearMap
from claasp_next.graph import Primitive

from ._bit_graph import (
    and_bits, bit_type, concatenate, constant_bits, modular_add_bits, rotate_bits,
    sbox_layer, shift_bits, xor_bits,
)


SBOX = (0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15)
LINEAR_LAYER = (
    (0,0,0,1,0,0,1,0,1,1,0,0,1,0,1,1,1,0,1,1,0,0,0,1),
    (0,1,1,0,1,0,0,0,0,0,0,0,0,0,1,1,1,0,1,1,0,1,0,1),
    (1,1,0,0,1,1,0,0,0,0,0,1,0,1,1,1,1,1,0,1,0,0,1,1),
    (1,1,0,1,0,0,0,1,1,1,0,0,0,0,0,0,1,0,1,0,1,0,0,1),
    (1,1,1,1,1,1,0,1,1,0,0,1,0,1,0,0,1,0,1,1,0,0,0,0),
    (1,0,1,1,1,1,1,0,1,1,0,1,0,1,0,1,0,0,0,0,0,0,0,0),
    (0,1,1,1,0,1,0,1,1,0,0,1,1,1,1,1,1,1,0,0,0,1,0,0),
    (1,1,0,0,1,0,1,1,1,1,1,1,1,0,1,0,1,1,1,1,1,1,0,1),
    (1,0,0,0,1,0,0,0,0,0,0,1,0,0,1,1,0,1,1,1,1,1,0,0),
    (1,1,1,1,0,0,1,0,1,0,1,1,0,0,1,0,0,0,0,1,0,1,0,1),
    (0,1,1,1,1,1,0,0,0,1,0,0,1,1,1,1,0,1,0,1,1,0,1,0),
    (0,0,1,1,0,1,0,1,0,1,0,1,1,0,1,0,0,0,0,1,1,1,0,0),
    (0,0,0,1,0,1,0,0,1,0,1,1,0,1,1,1,1,0,0,1,0,0,0,0),
    (1,1,0,1,0,0,0,0,1,0,1,0,1,0,1,0,1,0,0,0,1,1,0,1),
    (0,0,1,1,0,0,0,0,0,0,0,0,0,1,1,1,0,0,1,0,1,1,1,1),
    (0,1,1,1,0,0,0,1,0,0,0,0,1,1,1,0,1,1,0,1,0,0,0,1),
    (0,1,1,1,1,1,1,1,0,1,1,0,0,1,0,1,1,1,1,1,0,0,0,0),
    (0,1,1,1,0,1,0,1,0,1,0,1,0,0,1,0,1,0,0,0,1,1,0,1),
    (1,1,0,1,1,0,1,1,0,1,0,0,1,1,1,1,1,0,1,1,1,1,0,1),
    (0,1,0,1,0,1,0,0,0,0,0,1,1,0,1,0,0,0,1,1,0,0,1,1),
    (0,1,0,1,1,1,0,1,1,0,0,1,0,1,0,0,0,1,1,0,0,0,1,0),
    (1,1,1,1,1,0,1,0,1,1,1,0,1,1,1,0,1,1,0,0,1,1,1,1),
    (0,0,0,1,1,0,0,0,1,1,0,1,0,0,0,0,1,1,1,1,1,0,0,1),
    (1,1,1,1,1,0,0,1,1,0,0,1,0,1,1,1,0,0,1,1,1,1,1,1),
)


class Fancy(Primitive):
    """A deliberately heterogeneous 24-bit primitive used for framework tests.

    EXAMPLES::

        >>> primitive = Fancy()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0xca3417', 24)
    """

    def __init__(self, block_bit_size: int = 24, key_bit_size: int = 24, number_of_rounds: int = 20) -> None:
        if (block_bit_size, key_bit_size) != (24, 24):
            raise ValueError("Fancy has fixed 24-bit block and key widths")
        if number_of_rounds <= 0:
            raise ValueError("number_of_rounds must be positive")
        super().__init__("fancy", {"plaintext": bit_type(24), "key": bit_type(24)})
        state = self.input("plaintext").select_all()
        key = self.input("key").select_all()
        key_xor = key_and = None
        for round_number in range(number_of_rounds):
            self.add_round()
            substituted = sbox_layer(self, state, SBOX, component_id_prefix=f"round_{round_number}_sbox")
            if round_number % 2 == 0:
                # The legacy description stores one output column per row.
                state = self.add_component(LinearMap(substituted, tuple(zip(*LINEAR_LAYER))))
                if round_number == 0:
                    key_xor = xor_bits(self, key[:12], key[12:])
                    key_and = and_bits(self, key_xor, key[12:])
                else:
                    key_xor = xor_bits(self, key_xor, key_and)
                    key_and = and_bits(self, key_xor, key_and)
                state = xor_bits(self, constant_bits(self, 24, 0xFEDCBA), state,
                                 concatenate(self, (key_xor, key_and)))
            else:
                key_xor = xor_bits(self, key_xor, key_and)
                key_and = and_bits(self, key_xor, key_and)
                chunks = tuple(substituted[tuple(range(i * 4, (i + 1) * 4))] for i in range(6))
                left_a = concatenate(self, (chunks[0], chunks[1][:2]))
                left_b = concatenate(self, (chunks[1][2:], chunks[3]))
                right_a = concatenate(self, (chunks[3], chunks[4][:2]))
                right_b = concatenate(self, (chunks[4][2:], chunks[5]))
                add_left = modular_add_bits(self, key_xor[:6], left_a, left_b)
                add_right = modular_add_bits(self, key_xor[6:], right_a, right_b)
                rotated = rotate_bits(self, concatenate(self, (chunks[1][2:], chunks[2])), -3)
                shifted = shift_bits(self, concatenate(self, (chunks[4][2:], chunks[5])), 3)
                xor_left = xor_bits(self, add_left, rotated, key_and[:6])
                xor_right = xor_bits(self, add_right, shifted, key_and[6:])
                state = concatenate(self, (add_left, xor_left, add_right, xor_right))
        self.set_output(state)
