"""Heys tutorial SPN."""

from claasp_next.graph import Primitive

from ._bit_graph import bit_type, permute_bits, sbox_layer, xor_bits


HEYS_SBOX = (0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8, 0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7)
HEYS_PERMUTATION = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)


class Heys(Primitive):
    """The SPN from Heys' linear and differential cryptanalysis tutorial.

    EXAMPLES::

        >>> primitive = Heys()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0xe0bb', 16)
    """

    def __init__(self, block_bit_size: int = 16, key_bit_size: int = 80, number_of_rounds: int = 4) -> None:
        if block_bit_size != 16:
            raise ValueError("the Heys tutorial construction has a 16-bit block")
        if key_bit_size < block_bit_size * (number_of_rounds + 1):
            raise ValueError("key is too short for the requested Heys rounds")
        super().__init__(
            "heys", {"plaintext": bit_type(block_bit_size), "key": bit_type(key_bit_size)},
            provenance=(("reference", "Heys, A Tutorial on Linear and Differential Cryptanalysis"),),
        )
        state = self.input("plaintext")
        key = self.input("key")
        for round_number in range(number_of_rounds):
            self.add_round()
            round_key = key[tuple(range(round_number * block_bit_size, (round_number + 1) * block_bit_size))]
            state = xor_bits(self, state, round_key)
            state = sbox_layer(self, state, HEYS_SBOX, component_id_prefix=f"round_{round_number}_sbox")
            if round_number != number_of_rounds - 1:
                state = permute_bits(self, state, HEYS_PERMUTATION)
        state = xor_bits(
            self, state,
            key[tuple(range(number_of_rounds * block_bit_size, (number_of_rounds + 1) * block_bit_size))],
        )
        self.set_output(state)
