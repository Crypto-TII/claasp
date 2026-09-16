"""Threefish tweakable block primitive."""

from claasp_next.graph import Primitive

from ._word_graph import add, concatenate, constant, rotate, select, word_type, xor


ROTATIONS = (
    ((0x0E, 0x10), (0x2E, 0x24, 0x13, 0x25), (0x18, 0x0D, 0x08, 0x2F, 0x08, 0x11, 0x16, 0x25)),
    ((0x34, 0x39), (0x21, 0x1B, 0x0E, 0x2A), (0x26, 0x13, 0x0A, 0x37, 0x31, 0x12, 0x17, 0x34)),
    ((0x17, 0x28), (0x11, 0x31, 0x24, 0x27), (0x21, 0x04, 0x33, 0x0D, 0x22, 0x29, 0x3B, 0x11)),
    ((0x05, 0x25), (0x2C, 0x09, 0x36, 0x38), (0x05, 0x14, 0x30, 0x29, 0x2F, 0x1C, 0x10, 0x19)),
    ((0x19, 0x21), (0x27, 0x1E, 0x22, 0x18), (0x29, 0x09, 0x25, 0x1F, 0x0C, 0x2F, 0x2C, 0x1E)),
    ((0x2E, 0x0C), (0x0D, 0x32, 0x0A, 0x11), (0x10, 0x22, 0x38, 0x33, 0x04, 0x35, 0x2A, 0x29)),
    ((0x3A, 0x16), (0x19, 0x1D, 0x27, 0x2B), (0x1F, 0x2C, 0x2F, 0x2E, 0x13, 0x2A, 0x2C, 0x19)),
    ((0x20, 0x20), (0x08, 0x23, 0x38, 0x16), (0x09, 0x30, 0x23, 0x34, 0x17, 0x1F, 0x25, 0x14)),
)
PERMUTATIONS = ((0, 3, 2, 1), (6, 1, 0, 7, 2, 5, 4, 3),
                (0, 15, 2, 11, 6, 13, 4, 9, 14, 1, 8, 5, 10, 3, 12, 7))
DEFAULT_ROUNDS = {256: 72, 512: 72, 1024: 80}


class Threefish(Primitive):
    """Threefish-256, Threefish-512, or Threefish-1024."""

    def __init__(self, block_bit_size=256, key_bit_size=None, tweak_bit_size=128,
                 number_of_rounds=0):
        key_bit_size = block_bit_size if key_bit_size is None else key_bit_size
        if block_bit_size not in DEFAULT_ROUNDS or key_bit_size != block_bit_size or tweak_bit_size != 128:
            raise ValueError("Threefish requires equal 256/512/1024-bit block and key plus a 128-bit tweak")
        rounds = DEFAULT_ROUNDS[block_bit_size] if number_of_rounds == 0 else number_of_rounds
        count = block_bit_size // 64
        parameter_index = {4: 0, 8: 1, 16: 2}[count]
        super().__init__("threefish", {
            "plaintext": word_type(64, count), "key": word_type(64, count), "tweak": word_type(64, 2),
        })
        self.add_round()
        state = [select(self.input("plaintext"), index) for index in range(count)]
        key = [select(self.input("key"), index) for index in range(count)]
        parity = constant(self, 64, 0x1BD11BDAA9FC1A22)
        for value in key:
            parity = xor(self, parity, value)
        key.append(parity)
        tweak = [select(self.input("tweak"), 0), select(self.input("tweak"), 1)]
        tweak.append(xor(self, *tweak))

        def inject(subkey_index):
            subkey = [key[(subkey_index + index) % (count + 1)] for index in range(count)]
            subkey[-3] = add(self, subkey[-3], tweak[subkey_index % 3])
            subkey[-2] = add(self, subkey[-2], tweak[(subkey_index + 1) % 3])
            subkey[-1] = add(self, subkey[-1], constant(self, 64, subkey_index))
            return [add(self, value, subkey[index]) for index, value in enumerate(state)]

        for round_number in range(rounds):
            if round_number:
                self.add_round()
            if round_number % 4 == 0:
                state = inject(round_number // 4)
            mixed = []
            for pair in range(count // 2):
                first, second = state[2 * pair:2 * pair + 2]
                total = add(self, first, second)
                mixed.extend((total, xor(self, rotate(
                    self, second, -ROTATIONS[round_number % 8][parameter_index][pair]
                ), total)))
            permuted = [None] * count
            for source, destination in enumerate(PERMUTATIONS[parameter_index]):
                permuted[destination] = mixed[source]
            state = permuted
        self.add_round()
        state = inject(rounds // 4)
        self.set_output(concatenate(self, *state))
