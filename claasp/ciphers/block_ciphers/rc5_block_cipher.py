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

from math import ceil, floor, log2
from sage.symbolic.constants import e, golden_ratio

from claasp.cipher import Cipher
from claasp.name_mappings import BLOCK_CIPHER, INPUT_PLAINTEXT, INPUT_KEY

PARAMETERS_CONFIGURATION_LIST = [
    {"number_of_rounds": 16, "word_size": 16, "key_size": 64},
    {"number_of_rounds": 20, "word_size": 32, "key_size": 128},
    {"number_of_rounds": 24, "word_size": 64, "key_size": 192},
]


class RC5BlockCipher(Cipher):
    """
    Return a cipher object of RC5 Block Cipher.

    INPUT:

    - ``number_of_rounds`` -- **integer** (default: `16`); number of rounds of the cipher.
      Can be any value from 0 to 255
    - ``word_size`` -- **integer** (default: `16`); size of each word of the state.
    - ``key_size`` -- **integer** (default: `64`); size of the input key. can be any value from 0 to 2040

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.rc5_block_cipher import RC5BlockCipher
        sage: rc5 = RC5BlockCipher()
        sage: key = 0x0001020304050607
        sage: plaintext = 0x00010203
        sage: ciphertext = 0x23a8d72e
        sage: rc5.evaluate([key, plaintext]) == ciphertext
        True
    """

    def __init__(self, number_of_rounds=16, word_size=16, key_size=64):
        self.cipher_block_size = 2 * word_size

        if key_size == 0:
            self.key_block_size = 1
        else:
            self.key_block_size = key_size
        self.nrounds = number_of_rounds

        self.Lgw = int(floor(log2(word_size)))
        self.u = int(word_size / 8)
        self.t = 2 * (number_of_rounds + 1)
        self.c = int(ceil(self.key_block_size / (8 * self.u)))

        if self.c == 0:
            self.c = 1

        super().__init__(
            family_name="rc5_block_cipher",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_KEY, INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[self.key_block_size, self.cipher_block_size],
            cipher_output_bit_size=self.cipher_block_size,
        )

        # Key Expansion

        self.add_round()
        S, _ = self.key_expansion(word_size)

        # Encryption

        A, B = self.first_round(S, word_size)

        for k in range(number_of_rounds):
            A, B = self.round_function(k, A, B, S, word_size)

        # Output

        big_endian_order_output = [list(range(word_size))[x : x + 8] for x in range(0, word_size, 8)][::-1]
        output_order = []
        for o in big_endian_order_output:
            output_order = output_order + o

        self.add_cipher_output_component([A.id, B.id], [output_order, output_order], 2 * word_size)

    def compute_magic_constants(self, word_size):
        Pw = int((e - 2) * (2**word_size))
        Qw = int((golden_ratio - 1) * (2**word_size))

        if Pw % 2 == 0:
            Pw = Pw + 1

        if Qw % 2 == 0:
            Qw = Qw + 1

        return Pw, Qw

    def key_expansion(self, word_size):
        Pw, Qw = self.compute_magic_constants(word_size)

        # we use a dummy component to generate constant components representing
        # the split parts of the key after the first step of the key expansion

        dummy_component = self.add_constant_component(word_size, 0x0)

        # split bit positions orders to adapt to little endian standard

        little_endian_order = [list(range(self.key_block_size))[x : x + 8] for x in range(0, self.key_block_size, 8)][
            ::-1
        ]

        L = []

        # Key Expansion

        # Step 1 - store the key bytes in an array in groups of 4, using little endian order

        if self.c == 1:
            L.append(dummy_component)
        else:
            for i in range(self.c):
                if i == self.c - 1:
                    block = (i + 1) * self.u - len(little_endian_order)
                else:
                    block = self.u

                L.append(
                    self.add_XOR_component(
                        [dummy_component.id]
                        + [INPUT_KEY for _ in range(min(self.u, len(little_endian_order) - i * self.u))],
                        [list(range(block * 8))]
                        + [
                            little_endian_order[-j - 1]
                            for j in range(i * self.u, min((i + 1) * self.u, len(little_endian_order)))
                        ][::-1],
                        word_size,
                    )
                )

        # Step 2 - initialize the S vector

        S = [self.add_constant_component(word_size, Pw)]
        S_value = [Pw]

        for i in range(1, self.t):
            S_value.append((S_value[i - 1] + Qw) % (2**word_size))

            S.append(self.add_constant_component(word_size, S_value[i]))

        # Step 3 - Mix in the secret key

        i = 0
        j = 0
        A = dummy_component
        B = dummy_component

        for _ in range(3 * max(self.t, self.c)):
            # A = (S[i] + A + B) shift 3

            Si_modadd_A = self.add_MODADD_component(
                [S[i].id, A.id], [list(range(word_size)), list(range(word_size))], word_size
            )

            Si_modadd_A_modadd_B = self.add_MODADD_component(
                [Si_modadd_A.id, B.id], [list(range(word_size)), list(range(word_size))], word_size
            )

            A = self.add_rotate_component([Si_modadd_A_modadd_B.id], [list(range(word_size))], word_size, -3)

            S[i] = A

            # B = (key_array[j] + A + B) shift (A + B)

            A_modadd_B = self.add_MODADD_component(
                [A.id, B.id], [list(range(word_size)), list(range(word_size))], word_size
            )

            shift_amount = self.add_XOR_component(
                [A_modadd_B.id, dummy_component.id],
                [[word_size - 1 - i for i in range(self.Lgw)][::-1], list(range(word_size))],
                self.Lgw,
            )

            Lj_modadd_A = self.add_MODADD_component(
                [L[j].id, A.id], [list(range(word_size)), list(range(word_size))], word_size
            )

            Lj_modadd_A_modadd_B = self.add_MODADD_component(
                [Lj_modadd_A.id, B.id], [list(range(word_size)), list(range(word_size))], word_size
            )

            B = self.add_variable_rotate_component(
                [Lj_modadd_A_modadd_B.id, shift_amount.id],
                [list(range(word_size)), list(range(self.Lgw))],
                word_size,
                -1,
            )

            L[j] = B

            i = (i + 1) % self.t
            j = (j + 1) % self.c

        return S, L

    def first_round(self, S, word_size):
        # Round 1

        dummy_component = self.add_constant_component(word_size, 0x0)

        little_endian_order_pt = [list(range(2 * word_size))[x : x + 8] for x in range(0, 2 * word_size, 8)][::-1]

        A = self.add_XOR_component(
            [INPUT_PLAINTEXT for _ in range(int(word_size / 8))] + [dummy_component.id],
            [little_endian_order_pt[j] for j in range(int(word_size / 8), int(word_size / 4))]
            + [list(range(word_size))],
            word_size,
        )

        B = self.add_XOR_component(
            [INPUT_PLAINTEXT for _ in range(int(word_size / 8))] + [dummy_component.id],
            [little_endian_order_pt[i] for i in range(int(word_size / 8))] + [list(range(word_size))],
            word_size,
        )

        S0_modadd = self.add_MODADD_component(
            [A.id, S[0].id], [list(range(word_size)), list(range(word_size))], word_size
        )

        S1_modadd = self.add_MODADD_component(
            [B.id, S[1].id], [list(range(word_size)), list(range(word_size))], word_size
        )

        A = S0_modadd
        B = S1_modadd

        return A, B

    def round_function(self, k, A, B, S, word_size):
        dummy_component = self.add_constant_component(word_size, 0x0)

        A_xor_B = self.add_XOR_component([A.id, B.id], [list(range(word_size)), list(range(word_size))], word_size)

        shift_amount_B = self.add_XOR_component(
            [B.id, dummy_component.id],
            [[word_size - 1 - i for i in range(self.Lgw)][::-1], list(range(word_size))],
            self.Lgw,
        )

        B_shift = self.add_variable_rotate_component(
            [A_xor_B.id, shift_amount_B.id],
            [list(range(word_size)), list(range(self.Lgw))],
            word_size,
            -1,
        )

        S_2i_modadd = self.add_MODADD_component(
            [B_shift.id, S[2 * (k + 1)].id], [list(range(word_size)), list(range(word_size))], word_size
        )

        A = S_2i_modadd

        B_xor_A = self.add_XOR_component([B.id, A.id], [list(range(word_size)), list(range(word_size))], word_size)

        shift_amount_A = self.add_XOR_component(
            [A.id, dummy_component.id],
            [[word_size - 1 - i for i in range(self.Lgw)][::-1], list(range(word_size))],
            self.Lgw,
        )

        A_shift = self.add_variable_rotate_component(
            [B_xor_A.id, shift_amount_A.id],
            [list(range(word_size)), list(range(self.Lgw))],
            word_size,
            -1,
        )

        S_2i_1_modadd = self.add_MODADD_component(
            [A_shift.id, S[2 * (k + 1) + 1].id], [list(range(word_size)), list(range(word_size))], word_size
        )

        B = S_2i_1_modadd

        if k != self.nrounds - 1:
            self.add_round()

        return A, B
