"""Tiny Encryption Algorithm (TEA)."""

from claasp_next.graph import Primitive

from ._word_graph import add, concatenate, constant, select, shift, word_type, xor


class TEA(Primitive):
    """TEA with configurable word size, shifts, and reduced rounds.

    EXAMPLES::

        >>> primitive = TEA()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x41ea3a0a94baa940', 63)
    """

    def __init__(self, block_bit_size=64, key_bit_size=128, number_of_rounds=None,
                 right_shift_amount=5, left_shift_amount=4):
        width = block_bit_size // 2
        if key_bit_size != 4 * width or block_bit_size % 2:
            raise ValueError("TEA requires a four-word key and a two-word block")
        rounds = 32 if number_of_rounds is None and block_bit_size == 64 else number_of_rounds
        if not isinstance(rounds, int) or isinstance(rounds, bool) or rounds <= 0:
            raise ValueError("number_of_rounds must be a positive integer")
        super().__init__("tea", {"plaintext": word_type(width, 2), "key": word_type(width, 4)})
        left, right = select(self.input("plaintext"), 0), select(self.input("plaintext"), 1)
        keys = tuple(select(self.input("key"), index) for index in range(4))
        delta = 0x9E3779B9 & ((1 << width) - 1)
        for round_number in range(rounds):
            self.add_round()
            round_sum = constant(self, width, delta * (round_number + 1))
            mix = xor(
                self,
                add(self, shift(self, right, -left_shift_amount), keys[0]),
                add(self, right, round_sum),
                add(self, shift(self, right, right_shift_amount), keys[1]),
            )
            left = add(self, left, mix)
            mix = xor(
                self,
                add(self, shift(self, left, -left_shift_amount), keys[2]),
                add(self, left, round_sum),
                add(self, shift(self, left, right_shift_amount), keys[3]),
            )
            right = add(self, right, mix)
        self.set_output(concatenate(self, left, right))
