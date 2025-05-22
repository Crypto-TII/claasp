from claasp.cipher import Cipher
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY, BLOCK_CIPHER


PARAMETERS_CONFIGURATION_LIST = [{"block_bit_size": 128, "key_bit_size": 128, "number_of_rounds": 35}]
# fmt: off
SBOX = [0x3, 0x0, 0x6, 0xD, 0xB, 0x5, 0x8, 0xE, 0xC, 0xF, 0x9, 0x2, 0x4, 0xA, 0x7, 0x1]
TAP_POSITIONS = (21, 60, 92, 108, 114, 119)
ROUND_CONSTANTS = (
    0x02, 0x21, 0x10, 0x09, 0x24, 0x13, 0x28, 0x35, 0x1A, 0x0D, 0x26, 0x33, 0x38, 0x3D, 0x3E,
    0x1F, 0x0E, 0x07, 0x22, 0x31, 0x18, 0x2D, 0x36, 0x3B, 0x1C, 0x2F, 0x16, 0x2B, 0x14, 0x0B,
    0x04, 0x03, 0x20, 0x11, 0x08,
)
PERMUTATION = (
    96, 1, 34, 67, 64, 97, 2, 35, 32, 65, 98, 3, 0, 33, 66, 99, 100, 5, 38, 71, 68, 101, 6, 39,
    36, 69, 102, 7, 4, 37, 70, 103, 104, 9, 42, 75, 72, 105, 10, 43, 40, 73, 106, 11, 8, 41, 74,
    107, 108, 13, 46, 79, 76, 109, 14, 47, 44, 77, 110, 15, 12, 45, 78, 111, 112, 17, 50, 83,
    80, 113, 18, 51, 48, 81, 114, 19, 16, 49, 82, 115, 116, 21, 54, 87, 84, 117, 22, 55, 52, 85,
    118, 23, 20, 53, 86, 119, 120, 25, 58, 91, 88, 121, 26, 59, 56, 89, 122, 27, 24, 57, 90,
    123, 124, 29, 62, 95, 92, 125, 30, 63, 60, 93, 126, 31, 28, 61, 94, 127
)
# fmt: on


class BaksheeshBlockCipher(Cipher):
    def __init__(self, block_bit_size=128, key_bit_size=128, number_of_rounds=35):
        super().__init__(
            family_name="baksheesh",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[block_bit_size, key_bit_size],
            cipher_output_bit_size=block_bit_size,
        )

        self.block_bit_size = block_bit_size
        self.key_bit_size = key_bit_size
        self.number_of_nibbles = block_bit_size // 4

        state = ([INPUT_PLAINTEXT], [list(range(block_bit_size))])
        key = ([INPUT_KEY], [list(range(key_bit_size))])

        # 1) Whitening
        self.add_round()
        xor = self.add_XOR_component(state[0] + key[0], state[1] + key[1], block_bit_size)
        state = ([xor.id], [list(range(block_bit_size))])

        # 2) Rounds
        for r in range(number_of_rounds - 1):
            state = self.apply_sbox_layer(state)
            state = self.apply_bit_permutation(state)
            state = self.apply_round_constants(state, r)
            key = self.update_key(key)
            xor = self.add_XOR_component(state[0] + key[0], state[1] + key[1], block_bit_size)
            state = ([xor.id], [list(range(block_bit_size))])
            self.add_round_output_component(state[0], state[1], block_bit_size)
            self.add_round()

        # Last round
        state = self.apply_sbox_layer(state)
        state = self.apply_bit_permutation(state)
        state = self.apply_round_constants(state, number_of_rounds - 1)
        key = self.update_key(key)
        xor = self.add_XOR_component(state[0] + key[0], state[1] + key[1], block_bit_size)

        self.add_cipher_output_component([xor.id], [list(range(block_bit_size))], block_bit_size)

    def apply_sbox_layer(self, state):
        ids, bits = [], []
        for i in range(self.number_of_nibbles):
            sbox = self.add_SBOX_component(state[0], [state[1][0][i * 4 : (i + 1) * 4]], 4, SBOX)
            ids.append(sbox.id)
            bits.append(list(range(4)))
        state = (ids, bits)
        return state

    def apply_bit_permutation(self, state):
        permutation = self.add_permutation_component(state[0], state[1], self.block_bit_size, PERMUTATION)
        state = ([permutation.id], [list(range(self.block_bit_size))])
        return state

    def apply_round_constants(self, state, round_number):
        round_constant = ROUND_CONSTANTS[round_number]
        bits = map(int, f"{round_constant:06b}")
        value = 0
        for bit, tap_position in zip(bits, TAP_POSITIONS):
            little_position = self.block_bit_size - 1 - tap_position
            value ^= bit << little_position

        constant = self.add_constant_component(self.block_bit_size, value)

        comp = self.add_XOR_component(
            state[0] + [constant.id], state[1] + [list(range(self.block_bit_size))], self.block_bit_size
        )
        state = ([comp.id], [list(range(self.block_bit_size))])

        return state

    def update_key(self, key):
        rotate = self.add_rotate_component(key[0], key[1], self.key_bit_size, 1)
        key = ([rotate.id], [list(range(self.key_bit_size))])
        return key
