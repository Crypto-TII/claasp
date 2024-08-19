from claasp.cipher import Cipher
import numpy as np

from claasp.name_mappings import INPUT_KEY, INPUT_PLAINTEXT

round_constants = [
    0x0000000000000000, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89,
    0x452821e638d01377, 0xbe5466cf34e90c6c, 0x7ef84f78fd955cb1, 0x85840851f1ac43aa,
    0xc882d32f25323c54, 0x64a51195e0e3610d, 0xd3b5a399ca0c2399, 0xc0ac29b7c97c50dd
]


m0 = np.array([
    [0, 0, 0, 0],
    [0, 1, 0, 0],
    [0, 0, 1, 0],
    [0, 0, 0, 1]
])

m1 = np.array([
    [1, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 1, 0],
    [0, 0, 0, 1]
])

m2 = np.array([
    [1, 0, 0, 0],
    [0, 1, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 1]
])

m3 = np.array([
    [1, 0, 0, 0],
    [0, 1, 0, 0],
    [0, 0, 1, 0],
    [0, 0, 0, 0]
])


def get_shift_rows_matrix():
    temp_matrix = [[0 for _ in range(64)] for _ in range(64)]
    idx = 0
    for nibble_idx in range(16):
        for i in range(4):
            original_position = nibble_idx * 4 + i
            new_position = idx * 4 + i
            temp_matrix[new_position][original_position] = 1
        idx = (idx + 5) % 16

    return temp_matrix


def get_shift_rows_matrix_inverse():
    temp_matrix = [[0 for _ in range(64)] for _ in range(64)]

    idx = 0
    for nibble_idx in range(16):
        for i in range(4):
            original_position = nibble_idx * 4 + i
            new_position = idx * 4 + i
            temp_matrix[new_position][original_position] = 1
        idx = (idx + 13) % 16

    return temp_matrix


def get_m_prime():
    m_hat_0 = np.block([
        [m0, m1, m2, m3],
        [m1, m2, m3, m0],
        [m2, m3, m0, m1],
        [m3, m0, m1, m2]
    ])

    m_hat_1 = np.block([
        [m1, m2, m3, m0],
        [m2, m3, m0, m1],
        [m3, m0, m1, m2],
        [m0, m1, m2, m3]
    ])

    m_prime = np.block([
        [m_hat_0, np.zeros_like(m_hat_0), np.zeros_like(m_hat_0), np.zeros_like(m_hat_0)],
        [np.zeros_like(m_hat_0), m_hat_1, np.zeros_like(m_hat_0), np.zeros_like(m_hat_0)],
        [np.zeros_like(m_hat_0), np.zeros_like(m_hat_0), m_hat_1, np.zeros_like(m_hat_0)],
        [np.zeros_like(m_hat_0), np.zeros_like(m_hat_0), np.zeros_like(m_hat_0), m_hat_0],
    ])

    return m_prime.tolist()


sbox = [0xB, 0xF, 0x3, 0x2, 0xA, 0xC, 0x9, 0x1, 0x6, 0x7, 0x8, 0x0, 0xE, 0x5, 0xD, 0x4]
inverse_sbox = [0xB, 0x7, 0x3, 0x2, 0xF, 0xD, 0x8, 0x9, 0xa, 0x6, 0x4, 0x0, 0x5, 0xe, 0xc, 0x1]


class PrinceBlockCipher(Cipher):
    """
    Return a cipher object of Prince Block Cipher.

    INPUT:

    - ``number_of_rounds`` -- **integer** (default: `12`); number of rounds of the cipher. Must be greater or equal than 1.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.prince_block_cipher import PrinceBlockCipher
        sage: prince = PrinceBlockCipher()
        sage: key = 0xffffffffffffffff0000000000000000
        sage: plaintext = 0x0000000000000000
        sage: ciphertext = 0x9fb51935fc3df524
        sage: prince.evaluate([key, plaintext, tweak]) == ciphertext
        True
    """

    def generate_first_rounds(self, current_state, number_of_rounds):
        for round_idx in range(1, number_of_rounds // 2):
            sbox_layer = []

            for i in range(16):
                sbox_layer.append(
                    self.add_SBOX_component(
                        [current_state],
                        [[i * 4, i * 4 + 1, i * 4 + 2, i * 4 + 3]],
                        4, sbox
                    )
                )

            input_ids = [c.id for c in sbox_layer]
            input_bit_positions = [list(range(4)) for i in range(16)]
            after_m_matrix = self.add_linear_layer_component(
                input_ids, input_bit_positions, 64, get_m_prime()
            )
            after_shift_row = self.add_linear_layer_component(
                [after_m_matrix.id],
                [list(range(64))],
                64,
                get_shift_rows_matrix()
            )
            current_state = after_shift_row.id
            round_constant = self.add_constant_component(64, round_constants[round_idx])
            current_state = self.add_XOR_component(
                [current_state, round_constant.id],
                [list(range(64)), list(range(64))],
                64
            ).id

            round_key_xor = self.add_XOR_component(
                [current_state, INPUT_KEY],
                [list(range(64)), list(range(64, 128))],
                64
            )
            current_state = round_key_xor.id
            self.add_round_output_component(
                [current_state], [[i for i in range(64)]], 64
            )
            self.add_round()
        return current_state

    def prince_core(self, xor_initial, number_of_rounds):
        round_constant_0 = self.add_constant_component(64, round_constants[0])
        round_constant_xor_key_1 = self.add_XOR_component(
            [round_constant_0.id, INPUT_KEY],
            [list(range(64)), list(range(64, 128))],
            64
        ).id

        current_state = self.add_XOR_component(
            [xor_initial, round_constant_xor_key_1],
            [list(range(64)), list(range(64))],
            64
        )

        current_state = current_state.id
        current_state = self.generate_first_rounds(current_state, number_of_rounds)

        sboxes = []
        for i in range(16):
            sboxes.append(
                self.add_SBOX_component(
                    [current_state],
                    [[i * 4, i * 4 + 1, i * 4 + 2, i * 4 + 3]],
                    4, sbox
                )
            )
        input_ids = [sbox_layer.id for sbox_layer in sboxes]
        input_bit_positions = [list(range(4)) for i in range(16)]
        current_state = self.add_linear_layer_component(
            input_ids, input_bit_positions, 64, get_m_prime()
        )

        sboxes = []
        for i in range(16):
            sboxes.append(
                self.add_SBOX_component(
                    [current_state.id],
                    [[i * 4, i * 4 + 1, i * 4 + 2, i * 4 + 3]],
                    4,
                    inverse_sbox)
            )

        input_ids = [sbox_layer.id for sbox_layer in sboxes]
        input_bit_positions = [list(range(4)) for i in range(16)]

        input_ids, input_bit_positions = self.get_last_rounds(number_of_rounds, input_ids, input_bit_positions)

        round_constant_11 = self.add_constant_component(64, round_constants[11])

        constant_xor_key1 = self.add_XOR_component(
            [round_constant_11.id, INPUT_KEY],
            [list(range(64)), list(range(64, 128))],
            64
        )

        final_xor = self.add_XOR_component(
            input_ids + [constant_xor_key1.id],
            input_bit_positions + [list(range(64))],
            64
        )

        return final_xor

    def pre_whitening(self):
        self.add_round()
        return self.add_XOR_component(
            [INPUT_PLAINTEXT, INPUT_KEY],
            [list(range(64)), list(range(64))],
            64
        ).id

    def get_k0_prime(self, key_component_id):
        k0_rot = self.add_rotate_component(
            [key_component_id], [list(range(64))], 64, 1
        ).id
        k0_shift = self.add_SHIFT_component(
            [key_component_id], [list(range(64))], 64, 63
        ).id

        k0_prime = self.add_XOR_component(
            [k0_rot, k0_shift], [list(range(64)), list(range(64))], 64
        ).id

        return k0_prime

    def pos_whitening(self, final_xor):
        k0_prime = self.get_k0_prime(INPUT_KEY)
        return self.add_XOR_component(
            [final_xor.id, k0_prime],
            [list(range(64)), list(range(64))],
            64
        )
    def get_last_rounds(self, number_of_rounds, input_ids, input_bit_positions):
        for round_idx in range(number_of_rounds // 2, (number_of_rounds // 2 - 1) + number_of_rounds // 2):
            self.add_round()
            round_constant_0 = self.add_constant_component(64, round_constants[round_idx])
            constant_xor_key1 = self.add_XOR_component(
                [round_constant_0.id, INPUT_KEY],
                [list(range(64)), list(range(64, 128))],
                64
            )
            current_state = self.add_XOR_component(
                input_ids + [constant_xor_key1.id],
                input_bit_positions + [list(range(64))],
                64
            )

            after_shift_row = self.add_linear_layer_component(
                [current_state.id],
                [list(range(64))],
                64,
                get_shift_rows_matrix_inverse()
            )

            current_state = self.add_linear_layer_component(
                [after_shift_row.id], [list(range(64))], 64, get_m_prime()
            )

            sbox_layer = []
            for i in range(16):
                sbox_layer.append(
                    self.add_SBOX_component(
                        [current_state.id],
                        [[i * 4, i * 4 + 1, i * 4 + 2, i * 4 + 3]],
                        4, inverse_sbox)
                )

            input_ids = [c.id for c in sbox_layer]
            input_bit_positions = [list(range(4)) for i in range(16)]
            self.add_round_output_component(
                input_ids, [[i for i in range(4)] for _ in range(16)], 64,
            )
        return input_ids, input_bit_positions

    def __init__(self, number_of_rounds=12):
        super().__init__(family_name="prince",
                         cipher_type="block_cipher",
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                         cipher_inputs_bit_size=[64, 128],
                         cipher_output_bit_size=64)
        pre_whitening = self.pre_whitening()
        final_xor = self.prince_core(pre_whitening, number_of_rounds)
        pos_whitening = self.pos_whitening(final_xor)
        self.add_cipher_output_component(
            [pos_whitening.id], [[i for i in range(64)]], 64
        )
