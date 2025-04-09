# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ****************************************************************************


from claasp.cipher import Cipher
from claasp.name_mappings import INPUT_KEY, INPUT_PLAINTEXT, INPUT_TWEAK

PARAMETERS_CONFIGURATION_LIST = [
    {"number_of_rounds": 10, "number_of_layers": 1, "key_bit_size": 128, "tweak_bit_size": 128}
]


class QARMAv2MixColumnBlockCipher(Cipher):
    """
    Return a cipher object of Qarma v2 Block Cipher.

    This version uses the MixColumn component to model the diffusion layer, resulting in an invertible cipher object.
    However, it may be less efficient that the QARMAv2BlockCipher cipher object for vectorized evaluation.

    INPUT:

    - ``number_of_rounds`` -- **integer** (default: `10`);
      number of rounds of the cipher. Must be greater or equal than 1.
    - ``number_of_layers`` -- **integer** (default: `1`);
      number of layers of the state represented as matrices. Must be equal to 1 or 2.
    - ``key_bit_size`` -- **integer** (default: `128`);
      length of the key in bits. If number_of_layers is equal to 1 it must be equal to 128,
      otherwise it must be equal to 128, 192 or 256.
    - ``tweak_bit_size`` -- **integer** (default: `128`);
      length of the tweak in bits. Must be equal to either 64*number_of_layers or 128*number_of_layers.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.qarmav2_with_mixcolumn_block_cipher import QARMAv2MixColumnBlockCipher
        sage: qarmav2 = QARMAv2MixColumnBlockCipher(number_of_rounds = 4)
        sage: key = 0x0123456789abcdeffedcba9876543210
        sage: tweak = 0x7e5c3a18f6d4b2901eb852fc9630da74
        sage: plaintext = 0x0000000000000000
        sage: ciphertext = 0x2cc660354929f2ca
        sage: qarmav2.evaluate([key, plaintext, tweak]) == ciphertext
        True
    """

    def __init__(self, number_of_rounds=10, number_of_layers=1, key_bit_size=128, tweak_bit_size=128):
        if number_of_layers not in (1, 2):
            raise ValueError("number_of_layers incorrect (should be in [1,2])")
        if number_of_rounds < 1:
            raise ValueError("number_of_rounds incorrect (should be at least 1)")
        if (
            key_bit_size != 128
            and number_of_layers == 1
            or key_bit_size not in (128, 192, 256)
            and number_of_layers == 2
        ):
            raise ValueError("key_bit_size incorrect (should be 128 with 1 layer and 128, 192 or 256 with 2 layers)")
        if tweak_bit_size != 64 * number_of_layers and tweak_bit_size != 128 * number_of_layers:
            raise ValueError("tweak_bit_size incorrect (should be either 64*number_of_layers or 128*number_of_layers)")

        # cipher dictionary initialize
        self.cipher_block_size = 64 * number_of_layers
        self.layer_block_size = 64
        self.key_block_size = self.cipher_block_size
        self.tweak_block_size = self.cipher_block_size
        self.nrounds = number_of_rounds
        self.word_size = 4
        self.sbox_bit_size = self.word_size
        self.layer_sboxes = 16
        self.num_sboxes = self.layer_sboxes * number_of_layers
        self.num_rows = 4
        self.row_size = 4
        self.number_of_layers = number_of_layers

        super().__init__(
            family_name="qarmav2_block_cipher",
            cipher_type="block_cipher",
            cipher_inputs=[INPUT_KEY, INPUT_PLAINTEXT, INPUT_TWEAK],
            cipher_inputs_bit_size=[key_bit_size, self.cipher_block_size, tweak_bit_size],
            cipher_output_bit_size=self.cipher_block_size,
        )

        self.state_shuffle = [0, 11, 6, 13, 10, 1, 12, 7, 5, 14, 3, 8, 15, 4, 9, 2]

        self.sbox = [4, 7, 9, 11, 12, 6, 14, 15, 0, 5, 1, 13, 8, 3, 2, 10]

        self.inverse_sbox = [self.sbox.index(i) for i in range(16)]

        self.rotations_matrix = [0, 1, 2, 3, 3, 0, 1, 2, 2, 3, 0, 1, 1, 2, 3, 0]

        # fmt: off
        self.tweak_permutations = {
            1: [1, 10, 14, 6, 2, 9, 13, 5, 0, 8, 12, 4, 3, 11, 15, 7],
            2: [
                1, 10, 14, 22, 18, 25, 29, 21, 0, 8, 12, 4, 19, 27, 31, 23,
                17, 26, 30, 6, 2, 9, 13, 5, 16, 24, 28, 20, 3, 11, 15, 7,
            ],
        }
        # fmt: on

        self.mix_column_matrix = [
            [0x0, 0x2, 0x4, 0x8],
            [0x8, 0x0, 0x2, 0x4],
            [0x4, 0x8, 0x0, 0x2],
            [0x2, 0x4, 0x8, 0x0],
        ]

        lfsr_matrix = [[0 for _ in range(64)] for _ in range(64)]
        for i in range(63):
            lfsr_matrix[i][i + 1] = 1
        lfsr_matrix[13][0] = 1
        lfsr_matrix[30][0] = 1
        lfsr_matrix[44][0] = 1
        lfsr_matrix[63][0] = 1

        inverse_state_permutation = []
        for i in self.state_shuffle:
            inverse_state_permutation += list(range(4 * i, 4 * i + 4))
        self.inverse_state_permutation = inverse_state_permutation
        state_permutation = [inverse_state_permutation.index(i) for i in range(self.layer_block_size)]
        self.state_permutation = state_permutation
        tweak_permutation = []
        inverse_permutation = []
        for i in self.tweak_permutations[number_of_layers]:
            inverse_permutation += list(range(4 * i, 4 * i + 4))
        self.inverse_permutation = inverse_permutation
        direct_permutation = [inverse_permutation.index(i) for i in range(self.tweak_block_size)]
        tweak_permutation = [inverse_permutation, direct_permutation]

        exchange_rows_permutation = list(range(64, 96)) + list(range(32, 64)) + list(range(32)) + list(range(96, 128))
        self.exchange_rows_permutation = exchange_rows_permutation

        self.add_round()

        # Key initialization
        key_state = self.key_initialization(key_bit_size)

        # Tweak initialization
        tweak_state = self.tweak_initialization(tweak_permutation, tweak_bit_size)

        # Round constants initialization
        constants_states = self.constants_initialization()

        # First round different from others
        state = self.first_round_start(key_state)

        # Direct encryption
        for round_number in range(1, number_of_rounds + 1):
            state, _ = self.direct_round(
                state, key_state, tweak_state, tweak_permutation, constants_states, round_number
            )
            self.add_round()

        # Reflector
        state, key_state = self.reflector(state, key_state)

        # Inverse encryption
        for round_number in list(range(1, number_of_rounds + 1))[::-1]:
            self.add_round()
            state, _ = self.inverse_round(
                state, key_state, tweak_state, tweak_permutation, constants_states, round_number
            )

        # Last round different from others
        self.last_round_end(state, key_state)

    def key_initialization(self, key_bit_size):
        # Key initialization
        key_0 = self.add_permutation_component(
            [INPUT_KEY],
            [list(range(self.key_block_size))],
            self.key_block_size,
            list(range(self.key_block_size)),
        )
        if key_bit_size == 2 * self.key_block_size:
            key_1 = self.add_permutation_component(
                [INPUT_KEY],
                [list(range(self.key_block_size, 2 * self.key_block_size))],
                self.key_block_size,
                list(range(self.key_block_size)),
            )
        elif key_bit_size == self.key_block_size:
            key_1 = key_0
        else:
            key_1 = self.add_permutation_component(
                [INPUT_KEY, majority_function(INPUT_KEY).id],
                [
                    list(range(self.key_block_size / 2)),
                    list(range(self.key_block_size, 3 * self.key_block_size / 2)),
                ],
                self.key_block_size,
                list(range(self.key_block_size)),
            )
        key_state = [key_0, key_1]

        return key_state

    def tweak_initialization(self, tweak_permutation, tweak_bit_size):
        tweak_0 = self.add_permutation_component(
            [INPUT_TWEAK], [list(range(self.tweak_block_size))], self.tweak_block_size, tweak_permutation[1]
        )
        for _ in range(1, self.nrounds - 1):
            perm_tweak = self.add_permutation_component(
                [tweak_0.id], [list(range(self.tweak_block_size))], self.tweak_block_size, tweak_permutation[1]
            )
            tweak_0 = perm_tweak
        if tweak_bit_size == self.tweak_block_size:
            tweak_1 = self.add_permutation_component(
                [INPUT_TWEAK], [list(range(self.tweak_block_size))], self.tweak_block_size, tweak_permutation[1]
            )
        else:
            tweak_1 = self.add_permutation_component(
                [INPUT_TWEAK],
                [list(range(self.tweak_block_size, 2 * self.tweak_block_size))],
                self.tweak_block_size,
                list(range(self.tweak_block_size)),
            )

        tweak_state = [tweak_0, tweak_1]

        return tweak_state

    def constants_initialization(self):
        # Round constants initialization
        round_constant = [self.add_constant_component(self.layer_block_size, 0).id]
        if self.number_of_layers == 2:
            round_constant.append(self.add_constant_component(self.layer_block_size, 0).id)
        round_constant_0 = self.add_constant_component(self.layer_block_size, 0x243F6A8885A308D3).id
        round_constant.append(round_constant_0)
        if self.number_of_layers == 2:
            round_constant_1 = self.update_single_constant(round_constant_0)
            round_constant.append(round_constant_1)
        for _ in range(2, self.nrounds):
            round_constant_0 = self.update_single_constant(round_constant[-1])
            round_constant.append(round_constant_0)
            if self.number_of_layers == 2:
                round_constant_1 = self.update_single_constant(round_constant_0)
                round_constant.append(round_constant_1)

        return round_constant

    def first_round_start(self, key_state):
        # First round different from others
        first_round_add_round_key = self.add_XOR_component(
            [key_state[0].id, INPUT_PLAINTEXT],
            [list(range(self.key_block_size)), list(range(self.cipher_block_size))[::-1]],
            self.cipher_block_size,
        )

        first_round_sboxes = []
        for sb in range(self.num_sboxes):
            sbox = self.add_SBOX_component(
                [first_round_add_round_key.id], [list(range(4 * sb, 4 * sb + 4))], self.sbox_bit_size, self.sbox
            )
            first_round_sboxes.append(sbox)

        round_output = self.add_permutation_component(
            [first_round_sboxes[i].id for i in range(self.num_sboxes)],
            [list(range(self.sbox_bit_size)) for _ in range(self.num_sboxes)],
            self.cipher_block_size,
            list(range(self.cipher_block_size)),
        )

        return round_output

    def direct_round(self, round_output, key_state, tweak_state, tweak_permutation, round_constant, round_number):
        # Direct encryption
        round_key_shuffle = [None] * self.number_of_layers
        for l in range(self.number_of_layers):
            xor = self.add_XOR_component(
                [
                    round_output.id,
                    key_state[round_number % 2].id,
                    tweak_state[round_number % 2].id,
                    round_constant[(round_number - 1) * self.number_of_layers + l],
                ],
                [
                    list(range(64 * l, 64 * l + 64)),
                    list(range(64 * l, 64 * l + 64)),
                    list(range(64 * l, 64 * l + 64)),
                    list(range(64)),
                ],
                self.layer_block_size,
            )
            round_key_shuffle[l] = xor

        tweak_state[round_number % 2] = self.add_permutation_component(
            [tweak_state[round_number % 2].id],
            [list(range(self.tweak_block_size))],
            self.tweak_block_size,
            tweak_permutation[round_number % 2],
        )

        round_state_shuffle = [None] * self.number_of_layers
        for l in range(self.number_of_layers):
            shuffled_state = self.add_permutation_component(
                [round_key_shuffle[l].id],
                [list(range(self.layer_block_size))],
                self.layer_block_size,
                self.state_permutation,
            )
            round_state_shuffle[l] = shuffled_state

        round_state_rotate = [None] * self.number_of_layers * 4
        for l in range(self.number_of_layers):
            for c in range(4):
                rotate = self.add_mix_column_component(
                    [round_state_shuffle[l].id],
                    [
                        list(range(4 * c, 4 * c + 4))
                        + list(range(4 * c + 16, 4 * c + 20))
                        + list(range(4 * c + 32, 4 * c + 36))
                        + list(range(4 * c + 48, 4 * c + 52))
                    ],
                    self.layer_block_size // 4,
                    [self.mix_column_matrix, 0x11, self.sbox_bit_size],
                )
                round_state_rotate[l * 4 + c] = rotate

        round_sboxes = [None] * self.number_of_layers * self.layer_sboxes
        for l in range(self.number_of_layers):
            for sb in range(self.layer_sboxes):
                sbox = self.add_SBOX_component(
                    [round_state_rotate[sb % 4 + 4 * l].id],
                    [list(range(4 * int(sb / 4), 4 * int(sb / 4) + 4))],
                    self.sbox_bit_size,
                    self.sbox,
                )
                round_sboxes[l * self.layer_sboxes + sb] = sbox

        if self.number_of_layers == 2 and (self.nrounds - round_number) % 2 == 0:
            exchanging_rows = self.add_permutation_component(
                [round_sboxes[i].id for i in range(self.num_sboxes)],
                [list(range(self.sbox_bit_size)) for _ in range(self.num_sboxes)],
                self.cipher_block_size,
                self.exchange_rows_permutation,
            )

            round_output = self.add_round_output_component(
                [exchanging_rows.id], [list(range(self.cipher_block_size))], self.cipher_block_size
            )
        else:
            round_output = self.add_round_output_component(
                [round_sboxes[i].id for i in range(self.num_sboxes)],
                [list(range(self.sbox_bit_size)) for _ in range(self.num_sboxes)],
                self.cipher_block_size,
            )

        return round_output, round_key_shuffle

    def reflector(self, round_output, key_state):
        # Reflector
        new_keys = self.o_function(key_state)
        key_state = new_keys
        W = self.o_function(new_keys)

        alpha, beta = self.constants_update()

        key_state = self.key_update(key_state)

        round_state_shuffle = [None] * self.number_of_layers
        for l in range(self.number_of_layers):
            shuffled_state = self.add_permutation_component(
                [round_output.id],
                [list(range(64 * l, 64 * l + 64))],
                self.layer_block_size,
                self.state_permutation,
            )
            mixed_shuffled_state = self.add_XOR_component(
                [shuffled_state.id, W[(self.nrounds + 1) % 2].id],
                [list(range(self.layer_block_size)), list(range(64 * l, 64 * l + 64))],
                self.layer_block_size,
            )
            round_state_shuffle[l] = mixed_shuffled_state

        round_state_rotate = [None] * self.number_of_layers * 4
        for l in range(self.number_of_layers):
            for c in range(4):
                rotate = self.add_mix_column_component(
                    [round_state_shuffle[l].id],
                    [
                        list(range(4 * c, 4 * c + 4))
                        + list(range(4 * c + 16, 4 * c + 20))
                        + list(range(4 * c + 32, 4 * c + 36))
                        + list(range(4 * c + 48, 4 * c + 52))
                    ],
                    self.layer_block_size // 4,
                    [self.mix_column_matrix, 0x11, self.sbox_bit_size],
                )
                round_state_rotate[l * 4 + c] = rotate

        central_keyed_state = [None] * self.number_of_layers * 16
        for l in range(self.number_of_layers):
            for w in range(16):
                central_xor = self.add_XOR_component(
                    [round_state_rotate[w % 4 + 4 * l].id, W[(self.nrounds) % 2].id],
                    [
                        list(range(self.word_size * int(w / 4), self.word_size * int(w / 4) + 4)),
                        list(range(64 * l + 4 * w, 64 * l + 4 * w + 4)),
                    ],
                    self.word_size,
                )
                central_keyed_state[l * 16 + w] = central_xor

        central_shuffled_state = [None] * self.number_of_layers
        for l in range(self.number_of_layers):
            shuffled_state = self.add_permutation_component(
                [central_keyed_state[16 * l + i].id for i in range(16)],
                [list(range(4)) for _ in range(16)],
                self.layer_block_size,
                self.inverse_state_permutation,
            )
            central_shuffled_state[l] = shuffled_state

        round_output = self.add_round_output_component(
            [central_shuffled_state[i].id for i in range(self.number_of_layers)],
            [list(range(self.layer_block_size)) for _ in range(self.number_of_layers)],
            self.cipher_block_size,
        )

        return round_output, key_state

    def inverse_round(self, round_output, key_state, tweak_state, tweak_permutation, round_constant, round_number):
        # Inverse encryption
        if self.number_of_layers == 2 and (self.nrounds - round_number) % 2 == 0:
            exchanging_rows = self.add_permutation_component(
                [round_output.id],
                [list(range(self.cipher_block_size))],
                self.cipher_block_size,
                self.exchange_rows_permutation,
            )
        else:
            exchanging_rows = round_output

        round_sboxes = []
        for sb in range(self.num_sboxes):
            sbox = self.add_SBOX_component(
                [exchanging_rows.id], [list(range(4 * sb, 4 * sb + 4))], self.sbox_bit_size, self.inverse_sbox
            )
            round_sboxes.append(sbox)

        round_state_rotate = []
        for l in range(self.number_of_layers):
            for c in range(4):
                rotate = self.add_mix_column_component(
                    [round_sboxes[c + 4 * i + 16 * l].id for i in range(4)],
                    [list(range(4)) for _ in range(4)],
                    self.layer_block_size // 4,
                    [self.mix_column_matrix, 0x11, self.sbox_bit_size],
                )
                round_state_rotate.append(rotate)

        round_state_shuffle = []
        for l in range(self.number_of_layers):
            shuffled_state = self.add_permutation_component(
                [round_state_rotate[i % 4 + 4 * l].id for i in range(16)],
                [list(range(4 * int(j / 4), 4 * int(j / 4) + 4)) for j in range(16)],
                self.layer_block_size,
                self.inverse_state_permutation,
            )
            round_state_shuffle.append(shuffled_state)

        round_key_shuffle = []
        if round_number == 1:
            for l in range(self.number_of_layers):
                xor = self.add_XOR_component(
                    [
                        round_state_shuffle[l].id,
                        key_state[(round_number + 1) % 2].id,
                        INPUT_TWEAK,
                        round_constant[(round_number - 1) * self.number_of_layers + l],
                    ],
                    [
                        list(range(self.layer_block_size)),
                        list(range(64 * l, 64 * l + 64)),
                        list(range((self.layer_block_size) * l, (self.layer_block_size) * (l + 1))),
                        list(range(64)),
                    ],
                    self.layer_block_size,
                )
                round_key_shuffle.append(xor)
        else:
            for l in range(self.number_of_layers):
                xor = self.add_XOR_component(
                    [
                        round_state_shuffle[l].id,
                        key_state[(round_number + 1) % 2].id,
                        tweak_state[(round_number + 1) % 2].id,
                        round_constant[(round_number - 1) * self.number_of_layers + l],
                    ],
                    [
                        list(range(self.layer_block_size)),
                        list(range(64 * l, 64 * l + 64)),
                        list(range(64 * l, 64 * l + 64)),
                        list(range(64)),
                    ],
                    self.layer_block_size,
                )
                round_key_shuffle.append(xor)

            tweak_state[(round_number + 1) % 2] = self.add_permutation_component(
                [tweak_state[(round_number + 1) % 2].id],
                [list(range(self.tweak_block_size))],
                self.tweak_block_size,
                tweak_permutation[(round_number + 1) % 2],
            )
        if round_number != 1:
            round_output = self.add_round_output_component(
                [round_key_shuffle[i].id for i in range(self.number_of_layers)],
                [list(range(self.layer_block_size)) for j in range(self.number_of_layers)],
                self.cipher_block_size,
            )

        else:
            round_output = self.add_permutation_component(
                [round_key_shuffle[i].id for i in range(self.number_of_layers)],
                [list(range(self.layer_block_size)) for j in range(self.number_of_layers)],
                self.cipher_block_size,
                list(range(self.cipher_block_size)),
            )

        return round_output, round_key_shuffle

    def last_round_end(self, round_output, key_state):
        # Last round different from others
        last_round_sboxes = []
        for sb in range(self.num_sboxes):
            sbox = self.add_SBOX_component(
                [round_output.id], [list(range(4 * sb, 4 * sb + 4))], self.sbox_bit_size, self.inverse_sbox
            )
            last_round_sboxes.append(sbox)

        last_round_add_round_key = []
        for sb in range(self.num_sboxes):
            add_round_key = self.add_XOR_component(
                [key_state[1].id, last_round_sboxes[sb].id],
                [list(range(4 * sb, 4 * sb + 4)), list(range(self.sbox_bit_size))],
                self.sbox_bit_size,
            )
            last_round_add_round_key.append(add_round_key)

        round_output = self.add_round_output_component(
            [last_round_add_round_key[i].id for i in range(self.num_sboxes)],
            [list(range(self.sbox_bit_size)) for j in range(self.num_sboxes)],
            self.cipher_block_size,
        )

        cipher_output = self.add_cipher_output_component(
            [round_output.id], [list(range(self.cipher_block_size))], self.cipher_block_size
        )
        return cipher_output

    # -------------------------------------TOTALS-------------------------------------#

    def key_update(self, key_state):
        alpha, beta = self.constants_update()

        if self.number_of_layers == 2:
            key_state[0] = self.add_XOR_component(
                [key_state[0].id, alpha[0], alpha[1]],
                [
                    list(range(self.key_block_size)),
                    list(range(self.layer_block_size)),
                    list(range(self.layer_block_size)),
                ],
                self.key_block_size,
            )
            key_state[1] = self.add_XOR_component(
                [key_state[1].id, beta[0], beta[1]],
                [
                    list(range(self.key_block_size)),
                    list(range(self.layer_block_size)),
                    list(range(self.layer_block_size)),
                ],
                self.key_block_size,
            )
        else:
            key_state[0] = self.add_XOR_component(
                [key_state[0].id, alpha[0]],
                [list(range(self.key_block_size)), list(range(self.layer_block_size))],
                self.key_block_size,
            )
            key_state[1] = self.add_XOR_component(
                [key_state[1].id, beta[0]],
                [list(range(self.key_block_size)), list(range(self.layer_block_size))],
                self.key_block_size,
            )

        return key_state

    def constants_update(self):
        alpha_0 = self.add_constant_component(self.layer_block_size, 0x13198A2E03707344).id
        alpha = [alpha_0]
        if self.number_of_layers == 2:
            alpha_1 = self.update_single_constant(alpha[0])
            alpha.append(alpha_1)
        beta_0 = self.update_single_constant(alpha[-1])
        beta = [beta_0]
        if self.number_of_layers == 2:
            beta_1 = self.update_single_constant(beta_0)
            beta.append(beta_1)

        return alpha, beta

    # --------------------------------------------------------------------------------#

    def update_single_constant(self, constant):
        spill = self.add_SHIFT_component(
            [constant], [list(range(self.layer_block_size))], self.layer_block_size, 51
        )
        tmp_0 = self.add_SHIFT_component(
            [constant], [list(range(self.layer_block_size))], self.layer_block_size, -13
        )
        tmp_1 = self.add_SHIFT_component(
            [spill.id], [list(range(self.layer_block_size))], self.layer_block_size, -50
        )
        tmp_2 = self.add_SHIFT_component(
            [spill.id], [list(range(self.layer_block_size))], self.layer_block_size, -33
        )
        tmp_3 = self.add_SHIFT_component(
            [spill.id], [list(range(self.layer_block_size))], self.layer_block_size, -19
        )
        tmp = self.add_XOR_component(
            [tmp_0.id, tmp_1.id, tmp_2.id, tmp_3.id, spill.id],
            [list(range(self.layer_block_size)) for j in range(5)],
            self.layer_block_size,
        )
        spill = self.add_SHIFT_component(
            [tmp.id], [list(range(self.layer_block_size))], self.layer_block_size, 54
        )
        tmp_0 = self.add_SHIFT_component(
            [tmp.id], [list(range(self.layer_block_size))], self.layer_block_size, -10
        )
        tmp_1 = self.add_SHIFT_component(
            [spill.id], [list(range(self.layer_block_size))], self.layer_block_size, -50
        )
        tmp_2 = self.add_SHIFT_component(
            [spill.id], [list(range(self.layer_block_size))], self.layer_block_size, -33
        )
        tmp_3 = self.add_SHIFT_component(
            [spill.id], [list(range(self.layer_block_size))], self.layer_block_size, -19
        )
        tmp = self.add_XOR_component(
            [tmp_0.id, tmp_1.id, tmp_2.id, tmp_3.id, spill.id],
            [list(range(self.layer_block_size)) for j in range(5)],
            self.layer_block_size,
        )
        return tmp.id

    def o_function(self, key):
        key_rot_0 = self.add_rotate_component(
            [key[0].id], [list(range(self.key_block_size))], self.key_block_size, 1
        )
        key_shift_0 = self.add_SHIFT_component(
            [key[0].id], [list(range(self.key_block_size))], self.key_block_size, self.key_block_size - 1
        )
        key_1 = self.add_XOR_component(
            [key_rot_0.id, key_shift_0.id],
            [list(range(self.key_block_size)), list(range(self.key_block_size))],
            self.key_block_size,
        )

        key_lshift_1 = self.add_SHIFT_component(
            [key[1].id], [list(range(self.key_block_size))], self.key_block_size, -1
        )
        key_rshift_1 = self.add_SHIFT_component(
            [key_lshift_1.id], [list(range(self.key_block_size))], self.key_block_size, self.key_block_size - 1
        )
        key_rotated_1 = self.add_XOR_component(
            [key[1].id, key_rshift_1.id],
            [list(range(self.key_block_size)), list(range(self.key_block_size))],
            self.key_block_size,
        )
        key_2 = self.add_rotate_component(
            [key_rotated_1.id], [list(range(self.key_block_size))], self.key_block_size, -1
        )
        key_new = [key_1, key_2]
        return key_new

    def majority_function(self, key):
        maj_key_size = self.key_block_size / 2
        and_0_1 = self.add_AND_component(
            [key, key],
            [list(range(maj_key_size)), list(range(maj_key_size, 2 * maj_key_size))],
            maj_key_size,
        )
        and_0_2 = self.add_AND_component(
            [key, key],
            [list(range(maj_key_size)), list(range(2 * maj_key_size, 3 * maj_key_size))],
            maj_key_size,
        )
        and_1_2 = self.add_AND_component(
            [key, key],
            [
                list(range(maj_key_size, 2 * maj_key_size)),
                list(range(2 * maj_key_size, 3 * maj_key_size)),
            ],
            maj_key_size,
        )
        maj_key_rotated = self.add_OR_component(
            [and_0_1, and_0_2, and_1_2], [list(range(maj_key_size)) for _ in range(3)], maj_key_size
        )
        maj_key = self.add_rotate_component([maj_key_rotated], [list(range(maj_key_size))], maj_key_size, 17)
        return maj_key
