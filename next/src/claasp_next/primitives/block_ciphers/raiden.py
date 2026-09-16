"""Raiden word-oriented block primitive."""

from claasp_next.graph import Primitive

from ._word_graph import add, concatenate, select, shift, subtract, variable_shift, word_type, xor


class Raiden(Primitive):
    """Raiden with its data-dependent key update and configurable rounds."""

    def __init__(self, block_bit_size=64, key_bit_size=128, number_of_rounds=0,
                 right_shift_amount=14, left_shift_amount=9):
        width = block_bit_size // 2
        if key_bit_size != 4 * width or block_bit_size % 2:
            raise ValueError("Raiden requires a four-word key and two-word block")
        rounds = 16 if number_of_rounds == 0 and block_bit_size == 64 else number_of_rounds
        if rounds <= 0:
            raise ValueError("number_of_rounds must be positive")
        super().__init__("raiden", {"plaintext": word_type(width, 2), "key": word_type(width, 4)})
        block = [select(self.input("plaintext"), index) for index in range(2)]
        key = [select(self.input("key"), index) for index in range(4)]
        for round_number in range(rounds):
            self.add_round()
            key_sum = add(self, key[2], key[3])
            shifted = variable_shift(self, key[0], key[2], left=True)
            subkey = add(self, key[0], key[1], xor(self, key_sum, shifted))
            key[round_number % 4] = subkey
            for index in range(2):
                other = block[1 - index]
                summed = add(self, subkey, other)
                mixed = xor(self, subtract(self, subkey, other), shift(self, summed, right_shift_amount))
                block[index] = add(self, block[index], xor(self, shift(self, summed, -left_shift_amount), mixed))
        self.set_output(concatenate(self, *block))
