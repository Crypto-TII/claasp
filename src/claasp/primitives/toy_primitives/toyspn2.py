"""Small SPN with a rotating round key."""

from claasp.graph import Primitive

from ._bit_graph import bit_type, rotate_bits, sbox_layer, xor_bits


class ToySPN2(Primitive):
    """A configurable SPN whose complete key rotates before every round.

    EXAMPLES::

        >>> primitive = ToySPN2()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x0', 0)
    """

    def __init__(
        self,
        block_bit_size: int = 6,
        key_bit_size: int = 6,
        rotation_layer: int = 1,
        round_key_rotation: int = 1,
        sbox=(0, 5, 3, 2, 6, 1, 4, 7),
        number_of_rounds: int = 2,
    ) -> None:
        if block_bit_size != key_bit_size:
            raise ValueError("ToySPN2 requires equal block and key widths")
        if number_of_rounds <= 0:
            raise ValueError("number_of_rounds must be positive")
        super().__init__(
            "toyspn2", {"plaintext": bit_type(block_bit_size), "key": bit_type(key_bit_size)}
        )
        state = self.input("plaintext")
        round_key = self.input("key")
        for round_number in range(number_of_rounds):
            self.add_round()
            round_key = rotate_bits(
                self,
                round_key,
                round_key_rotation,
                component_id=f"round_{round_number}_key_rotation",
            )
            state = xor_bits(self, state, round_key, component_id=f"round_{round_number}_key_add")
            state = sbox_layer(
                self, state, tuple(sbox), component_id_prefix=f"round_{round_number}_sbox"
            )
            state = rotate_bits(
                self, state, rotation_layer, component_id=f"round_{round_number}_rotation"
            )
        self.set_output(state)
