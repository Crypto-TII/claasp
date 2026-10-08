"""Configurable small substitution-permutation teaching primitive."""

from claasp.graph import Primitive

from ._bit_graph import bit_type, rotate_bits, sbox_layer, xor_bits


class ToySPN1(Primitive):
    """A repeated-key SPN with configurable S-box and bit rotation.

    EXAMPLES::

        >>> primitive = ToySPN1()
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
        sbox=(0, 5, 3, 2, 6, 1, 4, 7),
        number_of_rounds: int = 2,
    ) -> None:
        if block_bit_size != key_bit_size:
            raise ValueError("ToySPN1 requires equal block and key widths")
        if number_of_rounds <= 0:
            raise ValueError("number_of_rounds must be positive")
        super().__init__(
            "toyspn1", {"plaintext": bit_type(block_bit_size), "key": bit_type(key_bit_size)}
        )
        state = self.input("plaintext")
        for round_number in range(number_of_rounds):
            self._builder.add_round()
            state = xor_bits(
                self, state, self.input("key"), component_id=f"round_{round_number}_key_add"
            )
            state = sbox_layer(
                self, state, tuple(sbox), component_id_prefix=f"round_{round_number}_sbox"
            )
            state = rotate_bits(
                self, state, rotation_layer, component_id=f"round_{round_number}_rotation"
            )
        self._builder.set_output(state)
