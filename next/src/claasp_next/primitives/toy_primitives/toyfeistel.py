"""Small configurable Feistel teaching primitive."""

from claasp_next.components import BitVectorSBox
from claasp_next.graph import Primitive

from ._bit_graph import bit_type, concatenate, constant_bits, rotate_bits, xor_bits

DEFAULT_SBOX = (14, 9, 15, 0, 13, 4, 10, 11, 1, 2, 8, 3, 7, 6, 12, 5)


class ToyFeistel(Primitive):
    """A small Feistel network with the historical CLAASP key update.

    EXAMPLES::

        >>> primitive = ToyFeistel()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0xa6', 8)
    """

    def __init__(
        self,
        block_bit_size: int = 8,
        key_bit_size: int = 8,
        sbox=DEFAULT_SBOX,
        number_of_rounds: int = 5,
    ) -> None:
        if block_bit_size != key_bit_size or block_bit_size % 2:
            raise ValueError("ToyFeistel requires equal, even block and key widths")
        half = block_bit_size // 2
        if len(sbox) != 1 << half:
            raise ValueError("ToyFeistel S-box width must equal half the block width")
        super().__init__(
            "toyfeistel", {"plaintext": bit_type(block_bit_size), "key": bit_type(key_bit_size)}
        )
        state = self.input("plaintext").select_all()
        key = self.input("key").select_all()
        left_positions = tuple(range(half))
        right_positions = tuple(range(half, block_bit_size))
        for round_number in range(1, number_of_rounds + 1):
            self.add_round()
            after_key = xor_bits(self, state[right_positions], key[left_positions])
            substituted = self.add_component(BitVectorSBox(after_key, tuple(sbox)))
            new_right = xor_bits(self, substituted, state[left_positions])
            state = concatenate(self, (state[right_positions], new_right))

            rotated = rotate_bits(self, key, -5)
            mixed = xor_bits(self, key, rotated)
            round_constant = constant_bits(self, half, round_number)
            low = xor_bits(self, mixed[right_positions], round_constant)
            key = concatenate(self, (mixed[left_positions], low))
        self.set_output(concatenate(self, (state[right_positions], state[left_positions])))
