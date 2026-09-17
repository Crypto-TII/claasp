"""Extended Tiny Encryption Algorithm (XTEA)."""

from claasp_next.graph import Primitive

from ._word_graph import add, concatenate, constant, select, shift, word_type, xor


class XTEA(Primitive):
    """XTEA with configurable word size, shifts, and reduced rounds."""

    def __init__(self, block_bit_size=64, key_bit_size=128, number_of_rounds=None,
                 right_shift_amount=5, left_shift_amount=4):
        width = block_bit_size // 2
        if key_bit_size != 4 * width or block_bit_size % 2:
            raise ValueError("XTEA requires a four-word key and a two-word block")
        rounds = 32 if number_of_rounds is None and block_bit_size == 64 else number_of_rounds
        if not isinstance(rounds, int) or isinstance(rounds, bool) or rounds <= 0:
            raise ValueError("number_of_rounds must be a positive integer")
        super().__init__("xtea", {"plaintext": word_type(width, 2), "key": word_type(width, 4)})
        left, right = select(self.input("plaintext"), 0), select(self.input("plaintext"), 1)
        keys = tuple(select(self.input("key"), index) for index in range(4))
        delta = 0x9E3779B9 & ((1 << width) - 1)
        round_sum_value = 0
        for _ in range(rounds):
            self.add_round()
            round_sum = constant(self, width, round_sum_value)
            nonlinear = add(self, xor(self, shift(self, right, -left_shift_amount),
                                      shift(self, right, right_shift_amount)), right)
            keyed = add(self, round_sum, keys[round_sum_value & 3])
            left = add(self, left, xor(self, nonlinear, keyed))
            round_sum_value = (round_sum_value + delta) & ((1 << width) - 1)
            round_sum = constant(self, width, round_sum_value)
            nonlinear = add(self, xor(self, shift(self, left, -left_shift_amount),
                                      shift(self, left, right_shift_amount)), left)
            keyed = add(self, round_sum, keys[(round_sum_value >> 11) & 3])
            right = add(self, right, xor(self, nonlinear, keyed))
        self.set_output(concatenate(self, left, right))
