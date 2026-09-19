"""CHAM lightweight ARX family."""

from claasp_next.graph import Primitive

from ._word_graph import add, concatenate, constant, rotate, select, word_type, xor


DEFAULT_ROUNDS = {(64, 128): 88, (128, 128): 112, (128, 256): 120}


class CHAM(Primitive):
    """CHAM-64/128, CHAM-128/128, or CHAM-128/256.

    EXAMPLES::

        >>> primitive = CHAM()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0xce2084f0a4c1b6bf', 64)
    """

    def __init__(self, block_bit_size=64, key_bit_size=128, number_of_rounds=None):
        if (block_bit_size, key_bit_size) not in DEFAULT_ROUNDS:
            raise ValueError("unsupported CHAM parameter set")
        rounds = DEFAULT_ROUNDS[(block_bit_size, key_bit_size)] if number_of_rounds is None else number_of_rounds
        if not isinstance(rounds, int) or isinstance(rounds, bool) or rounds <= 0:
            raise ValueError("number_of_rounds must be a positive integer")
        width = block_bit_size // 4
        key_words = key_bit_size // width
        super().__init__("cham", {"key": word_type(width, key_words), "plaintext": word_type(width, 4)})
        state = [select(self.input("plaintext"), index) for index in range(4)]
        master = [select(self.input("key"), index) for index in range(key_words)]
        round_keys = [None] * (2 * key_words)
        self.add_round()
        for index, key_word in enumerate(master):
            common = xor(self, key_word, rotate(self, key_word, -1))
            round_keys[index] = xor(self, common, rotate(self, key_word, -8))
            round_keys[(index + key_words) ^ 1] = xor(self, common, rotate(self, key_word, -11))
        for round_number in range(rounds):
            if round_number:
                self.add_round()
            target = round_number % 4
            following = (target + 1) % 4
            inner_amount, outer_amount = ((-1, -8) if round_number % 2 == 0 else (-8, -1))
            first = xor(self, state[target], constant(self, width, round_number))
            second = xor(self, rotate(self, state[following], inner_amount),
                         round_keys[round_number % len(round_keys)])
            state[target] = rotate(self, add(self, first, second), outer_amount)
        self.set_output(concatenate(self, *state))
