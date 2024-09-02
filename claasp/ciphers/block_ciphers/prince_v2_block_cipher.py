from claasp.cipher import Cipher
import numpy as np

from claasp.name_mappings import INPUT_KEY, INPUT_PLAINTEXT

round_constants = [
    0x0000000000000000, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89,
    0x452821e638d01377, 0xbe5466cf34e90c6c, 0x7ef84f78fd955cb1, 0x7aacf4538d971a60,
    0xc882d32f25323c54, 0x9b8ded979cd838c7, 0xd3b5a399ca0c2399, 0x3f84d5b5b5470917
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


class PrinceBlockCipherV2(Cipher):
    """
    Return a cipher object of PrinceV2 Block Cipher.

    INPUT:

    - ``number_of_rounds`` -- **integer** (default: `12`); number of rounds of the cipher. Must be greater or equal than 1.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.prince_v2_block_cipher import PrinceBlockCipherV2
        sage: prince_v2 = PrinceBlockCipherV2()
        sage: key = 0x00000000000000000000000000000000
        sage: plaintext = 0x0000000000000000
        sage: ciphertext = 0x0125fc7359441690
        sage: prince_v2.evaluate([plaintext, key]) == ciphertext
        True
        sage: plaintext_list = [0x0000000000000000, 0xffffffffffffffff, 0x0000000000000000, 0x0000000000000000, 0x0123456789abcdef]
        sage: key_list = [0x00000000000000000000000000000000, 0x00000000000000000000000000000000, 0xffffffffffffffff0000000000000000, 0x0000000000000000ffffffffffffffff, 0x0123456789abcdeffedcba9876543210]
        sage: ciphertext_list = [0x0125fc7359441690, 0x832bd46f108e7857, 0xee873b2ec447944d, 0x0ac6f9cd6e6f275d, 0x603cd95fa72a8704]
        sage: for j in range(0, len(key_list)):
                plaintext = plaintext_list[j]
                key = key_list[j]
                ciphertext = ciphertext_list[j]
                prince_v2.evaluate([plaintext, key]) == ciphertext
        True
        True
        True
        True
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

            if round_idx % 2 == 1:
                round_key_xor = self.add_XOR_component(
                    [current_state, INPUT_KEY],
                    [list(range(64)), list(range(64, 128))],
                    64
                )
            else:
                round_key_xor = self.add_XOR_component(
                    [current_state, INPUT_KEY],
                    [list(range(64)), list(range(64))],
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
            [list(range(64)), list(range(64))],
            64
        ).id

        current_state = self.add_XOR_component(
            [INPUT_PLAINTEXT, round_constant_xor_key_1],
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
        input_ids2 = input_ids + [INPUT_KEY]
        input_bit_positions = [list(range(4)) for i in range(16)]
        input_bit_positions2 = input_bit_positions + [[i for i in range(64)]]
        current_state = self.add_XOR_component(
            input_ids2,
            input_bit_positions2,
            64
        )
        current_state = self.add_linear_layer_component(
            [current_state.id],
            [list(range(64))],
            64,
            get_m_prime()
        )
        current_state = self.add_XOR_component(
                [current_state.id, INPUT_KEY],
                [list(range(64)), list(range(64, 128))],
                64
            )
        round_constant_11 = self.add_constant_component(64, round_constants[11])
        current_state = self.add_XOR_component(
            [current_state.id, round_constant_11.id],
            [list(range(64)), list(range(64))],
            64
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


    def pos_whitening(self, final_xor):
        return self.add_XOR_component(
            [final_xor.id, INPUT_KEY],
            [list(range(64)), list(range(64,128))],
            64
        )
    def get_last_rounds(self, number_of_rounds, input_ids, input_bit_positions):
        for round_idx in range(number_of_rounds // 2, (number_of_rounds // 2 - 1) + number_of_rounds // 2):
            self.add_round()
            round_constant_0 = self.add_constant_component(64, round_constants[round_idx])
            if round_idx % 2 == 1:  # Check if the round index is odd
                constant_xor_key1 = self.add_XOR_component(
                    [round_constant_0.id, INPUT_KEY],
                    [list(range(64)), list(range(64, 128))],
                    64
                )
            else:  # If the round index is even
                constant_xor_key1 = self.add_XOR_component(
                    [round_constant_0.id, INPUT_KEY],
                    [list(range(64)), list(range(64))],
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
        self.add_cipher_output_component([final_xor.id], [[i for i in range(64)]], 64)
