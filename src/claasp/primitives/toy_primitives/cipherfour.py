"""CipherFour teaching primitive."""

from claasp.graph import Primitive

from ._bit_graph import bit_type, permute_bits, sbox_layer, xor_bits

DEFAULT_SBOX = (12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2)
DEFAULT_PERMUTATION = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)


class CipherFour(Primitive):
    """The configurable CipherFour SPN used in the legacy teaching fixtures.

    EXAMPLES::

        >>> primitive = CipherFour()
        >>> inputs = {name: 0 for name in primitive.graph.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x9844', 16)
    """

    def __init__(
        self,
        block_bit_size: int = 16,
        key_bit_size: int = 16,
        rotation_layer: int = 1,
        sbox=None,
        permutations=None,
        number_of_rounds: int = 5,
    ) -> None:
        del rotation_layer
        if number_of_rounds <= 0:
            raise ValueError("number_of_rounds must be positive")
        table = DEFAULT_SBOX if sbox is None else tuple(sbox)
        permutation = DEFAULT_PERMUTATION if permutations is None else tuple(permutations)
        if block_bit_size % ((len(table)).bit_length() - 1):
            raise ValueError("block width must be divisible by the S-box width")
        key_stream_size = key_bit_size * (number_of_rounds + 1)
        super().__init__(
            "cipherfour",
            {"plaintext": bit_type(block_bit_size), "key": bit_type(key_stream_size)},
            provenance=(("reference", "Knudsen and Robshaw, The Block Cipher Companion"),),
        )
        state = self.graph.input("plaintext")
        key = self.graph.input("key")
        for round_number in range(number_of_rounds - 1):
            self._builder.add_round()
            round_key = key[
                tuple(range(round_number * block_bit_size, (round_number + 1) * block_bit_size))
            ]
            state = xor_bits(self, state, round_key, component_id=f"round_{round_number}_key_add")
            state = sbox_layer(self, state, table, component_id_prefix=f"round_{round_number}_sbox")
            state = permute_bits(
                self, state, permutation, component_id=f"round_{round_number}_permutation"
            )
        self._builder.add_round()
        # These two fixed offsets are part of the historical CipherFour fixture,
        # including its reduced/extended-round parameter behavior.
        state = xor_bits(self, state, key[tuple(range(4 * block_bit_size, 5 * block_bit_size))])
        state = sbox_layer(self, state, table, component_id_prefix="final_sbox")
        state = xor_bits(self, state, key[tuple(range(5 * block_bit_size, 6 * block_bit_size))])
        self._builder.set_output(state)
