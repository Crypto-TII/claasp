"""Simeck lightweight Feistel family."""

from claasp_next.graph import Primitive

from ._word_graph import bit_and, concatenate, constant, rotate, select, word_type, xor


PARAMETERS = {(32, 64): 32, (48, 96): 36, (64, 128): 44}
Z = (5557826286501673759, 3114073359753873471)
Z_INDEX = {16: 0, 24: 0, 32: 1}


class Simeck(Primitive):
    """Simeck-32/64, Simeck-48/96, or Simeck-64/128."""

    def __init__(self, block_bit_size=32, key_bit_size=64, number_of_rounds=None,
                 rotation_amounts=(-5, -1)):
        if (block_bit_size, key_bit_size) not in PARAMETERS:
            raise ValueError("unsupported Simeck parameter set")
        rounds = PARAMETERS[(block_bit_size, key_bit_size)] if number_of_rounds is None else number_of_rounds
        width = block_bit_size // 2
        super().__init__("simeck", {"plaintext": word_type(width, 2), "key": word_type(width, 4)})
        left, right = select(self.input("plaintext"), 0), select(self.input("plaintext"), 1)
        keys = [select(self.input("key"), index) for index in range(4)]
        z_value = Z[Z_INDEX[width]]
        c_value = (1 << width) - 4

        def feistel(x, y, round_key):
            nonlinear = xor(self, bit_and(self, x, rotate(self, x, rotation_amounts[0])),
                            rotate(self, x, rotation_amounts[1]))
            return xor(self, y, nonlinear, round_key), x

        for round_number in range(rounds):
            self.add_round()
            left, right = feistel(left, right, keys[3])
            if round_number != rounds - 1:
                new_key, keys[3] = feistel(
                    keys[2], keys[3], constant(self, width, c_value ^ ((z_value >> round_number) & 1))
                )
                keys = [new_key, keys[0], keys[1], keys[3]]
        self.set_output(concatenate(self, left, right))
