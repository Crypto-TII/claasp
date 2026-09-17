"""LEA block primitive."""

from claasp_next.graph import Primitive

from ._word_graph import add, byte_swap, concatenate, constant, rotate, select, word_type, xor


DEFAULT_ROUNDS = {128: 24, 192: 28, 256: 32}
DELTA = (0xC3EFE9DB, 0x44626B02, 0x79E27C8A, 0x78DF30EC,
         0x715EA49E, 0xC785DA0A, 0xE04EF22A, 0xE5C40957)
KEY_ROTATIONS = (-1, -3, -6, -11, -13, -17)


class LEA(Primitive):
    """LEA-128 with 128-, 192-, or 256-bit keys."""

    def __init__(self, block_bit_size=128, key_bit_size=192, number_of_rounds=None,
                 reorder_input_and_output=True):
        if block_bit_size != 128 or key_bit_size not in DEFAULT_ROUNDS:
            raise ValueError("LEA requires a 128-bit block and 128-, 192-, or 256-bit key")
        rounds = DEFAULT_ROUNDS[key_bit_size] if number_of_rounds is None else number_of_rounds
        if not isinstance(rounds, int) or isinstance(rounds, bool) or rounds <= 0:
            raise ValueError("number_of_rounds must be a positive integer")
        key_word_count = key_bit_size // 32
        super().__init__("lea", {"plaintext": word_type(32, 4), "key": word_type(32, key_word_count)})
        state = [select(self.input("plaintext"), index) for index in range(4)]
        key = [select(self.input("key"), index) for index in range(key_word_count)]
        self.add_round()
        if reorder_input_and_output:
            state = [byte_swap(self, value, 32) for value in state]
            key = [byte_swap(self, value, 32) for value in key]
        for round_number in range(rounds):
            if round_number:
                self.add_round()
            delta = DELTA[round_number % key_word_count]
            if key_bit_size in (128, 192):
                operations = 4 if key_bit_size == 128 else 6
                for operation in range(operations):
                    key[operation] = rotate(
                        self,
                        add(self, key[operation], rotate(self, constant(self, 32, delta),
                                                         -(round_number + operation))),
                        KEY_ROTATIONS[operation],
                    )
                round_key = ([key[0], key[1], key[2], key[1], key[3], key[1]]
                             if key_bit_size == 128 else list(key))
            else:
                round_key = []
                for operation in range(6):
                    index = (6 * round_number + operation) % 8
                    key[index] = rotate(
                        self,
                        add(self, key[index], rotate(self, constant(self, 32, delta),
                                                     -(round_number + operation))),
                        KEY_ROTATIONS[operation],
                    )
                    round_key.append(key[index])
            state = [
                rotate(self, add(self, xor(self, state[0], round_key[0]),
                                 xor(self, state[1], round_key[1])), -9),
                rotate(self, add(self, xor(self, state[1], round_key[2]),
                                 xor(self, state[2], round_key[3])), 5),
                rotate(self, add(self, xor(self, state[2], round_key[4]),
                                 xor(self, state[3], round_key[5])), 3),
                state[0],
            ]
        if reorder_input_and_output:
            state = [byte_swap(self, value, 32) for value in state]
        self.set_output(concatenate(self, *state))
