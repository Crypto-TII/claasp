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
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY

input_types = [INPUT_KEY, INPUT_PLAINTEXT]
PARAMETERS_CONFIGURATION_LIST = [{'block_bit_size': 64, 'key_bit_size': 256, 'number_of_rounds': 32}]


class GostBlockCipher(Cipher):
    """
    Construct an instance of the GostBlockCipher class, as described in RFC4357 (id-GostR3411-94-CryptoProParamSet)

    This class is used to store compact representations of a cipher,
    used to generate the corresponding cipher.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `64`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `256`); cipher key bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `0`); number of rounds of the cipher. The cipher uses the
      corresponding amount given the other parameters (if available) when number_of_rounds is 0
    - ``sub_keys_zero`` -- **boolean** (default: `False`)
    - ``transformations_flag`` -- **boolean** (default: `True`)

    EXAMPLES::
        Source 1: https://www.rfc-editor.org/rfc/rfc5831#section-7
        using id-GostR3411-94-CryptoProParamSet

        sage: from claasp.ciphers.block_ciphers.gost_block_cipher import GostBlockCipher
        sage: gost = GostBlockCipher(number_of_rounds=32)
        sage: gost.evaluate([0x0, 0x733D2C20656865737474676979676120626E737320657369326C656833206D54]) == 0x42ABBCCE32BC0B1B

        sage: from claasp.ciphers.block_ciphers.gost_block_cipher import GostBlockCipher
        sage: gost = GostBlockCipher(number_of_rounds=32)
        sage: gost.evaluate([0x0, 0x110C733D0D166568130E7474064179671D00626E161A2065090D326C4D393320]) == 0x5203EBC85D9BCFFD

        sage: from claasp.ciphers.block_ciphers.gost_block_cipher import GostBlockCipher
        sage: gost = GostBlockCipher(number_of_rounds=32)
        sage: gost.evaluate([0x0, 0x80B111F3730DF216850013F1C7E1F941620C1DFF3ABAE91A3FA109F2F513B239]) == 0x8D34589900FF0E28

        sage: from claasp.ciphers.block_ciphers.gost_block_cipher import GostBlockCipher
        sage: gost = GostBlockCipher(number_of_rounds=32)
        sage: gost.evaluate([0x0, 0xA0E2804EFF1B73F2ECE27A00E7B8C7E1EE1D620CAC0CC5BAA804C05EA18B0AEC]) == 0xE78604190D2A562D

        Source 2: https://datatracker.ietf.org/doc/html/rfc8891
        Magma:
            - S-BOX set is fixed at id-tc26-gost-28147-param-Z (see Appendix C of [RFC7836]);
            - key is parsed as a single big-endian integer (compared to the little-endian approach used in [GOST28147-89]), which results in different subkey values being used;
            - data bytes are also parsed as a single big-endian integer (instead of being parsed as little-endian integer).

        sage: from claasp.ciphers.block_ciphers.gost_block_cipher import GostBlockCipher
        sage: gost = GostBlockCipher(number_of_rounds=32)
        sage: hex(gost.evaluate([0xfedcba9876543210, 0xffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff]))
        '0xeca1a544d33070b'

        Source 3: using GostR3413-2015 (Kuznechik, similar to MAGMA)
        https://github.com/sheroz/crypto_vectors/blob/main/src/gost/r3413_2015.rs
        sage: from claasp.ciphers.block_ciphers.gost_block_cipher import GostBlockCipher
        sage: gost = GostBlockCipher(number_of_rounds=32)
        sage: hex(gost.evaluate([0x92def06b3c130a59, 0xffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff]))

        sage: from claasp.ciphers.block_ciphers.gost_block_cipher import GostBlockCipher
        sage: gost = GostBlockCipher(number_of_rounds=32)
        sage: hex(gost.evaluate([0xdb54c704f8189d20, 0xffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff]))



    """

    def __init__(self, number_of_rounds=32):
        self.block_bit_size = 64
        self.key_bit_size = 256
        self.WORD_SIZE = 32

        # # GOST_R_3411(34.11-94)
        # self.SBOXES = {0: [10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15],
        #                1: [5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8],
        #                2: [7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13],
        #                3: [4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3],
        #                4: [7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5],
        #                5: [7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3],
        #                6: [13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11],
        #                7: [1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12]}

        # id-GostR3411-94-CryptoProParamSet
        self.SBOXES = {0: [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
                       1: [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
                       2: [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
                       3: [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
                       4: [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
                       5: [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
                       6: [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
                       7: [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12]}

        # # id-Gost28147-89-CryptoPro-A-ParamSet
        # self.SBOXES = {0: [0x9, 0x6, 0x3, 0x2, 0x8, 0xB, 0x1, 0x7, 0xA, 0x4, 0xE, 0xF, 0xC, 0x0, 0xD, 0x5],
        #                1: [0x3, 0x7, 0xE, 0x9, 0x8, 0xA, 0xF, 0x0, 0x5, 0x2, 0x6, 0xC, 0xB, 0x4, 0xD, 0x1],
        #                2: [0xE, 0x4, 0x6, 0x2, 0xB, 0x3, 0xD, 0x8, 0xC, 0xF, 0x5, 0xA, 0x0, 0x7, 0x1, 0x9],
        #                3: [0xE, 0x7, 0xA, 0xC, 0xD, 0x1, 0x3, 0x9, 0x0, 0x2, 0xB, 0x4, 0xF, 0x8, 0x5, 0x6],
        #                4: [0xB, 0x5, 0x1, 0x9, 0x8, 0xD, 0xF, 0x0, 0xE, 0x4, 0x2, 0x3, 0xC, 0x7, 0xA, 0x6],
        #                5: [0x3, 0xA, 0xD, 0xC, 0x1, 0x2, 0x0, 0xB, 0x7, 0x5, 0x9, 0x4, 0x8, 0xF, 0xE, 0x6],
        #                6: [0x1, 0xD, 0x2, 0x9, 0x7, 0xA, 0x6, 0x0, 0x8, 0xC, 0x4, 0x5, 0xF, 0x3, 0xB, 0xE],
        #                7: [0xB, 0xA, 0xF, 0x5, 0x0, 0xC, 0xE, 0x8, 0x6, 0x2, 0x3, 0x9, 0x1, 0x7, 0xD, 0x4]}
        #
        # # id-Gost28147-89-CryptoPro-B-ParamSet
        # self.SBOXES = {0: [0x8, 0x4, 0xB, 0x1, 0x3, 0x5, 0x0, 0x9, 0x2, 0xE, 0xA, 0xC, 0xD, 0x6, 0x7, 0xF],
        #                1: [0x0, 0x1, 0x2, 0xA, 0x4, 0xD, 0x5, 0xC, 0x9, 0x7, 0x3, 0xF, 0xB, 0x8, 0x6, 0xE],
        #                2: [0xE, 0xC, 0x0, 0xA, 0x9, 0x2, 0xD, 0xB, 0x7, 0x5, 0x8, 0xF, 0x3, 0x6, 0x1, 0x4],
        #                3: [0x7, 0x5, 0x0, 0xD, 0xB, 0x6, 0x1, 0x2, 0x3, 0xA, 0xC, 0xF, 0x4, 0xE, 0x9, 0x8],
        #                4: [0x2, 0x7, 0xC, 0xF, 0x9, 0x5, 0xA, 0xB, 0x1, 0x4, 0x0, 0xD, 0x6, 0x8, 0xE, 0x3],
        #                5: [0x8, 0x3, 0x2, 0x6, 0x4, 0xD, 0xE, 0xB, 0xC, 0x1, 0x7, 0xF, 0xA, 0x0, 0x9, 0x5],
        #                6: [0x5, 0x2, 0xA, 0xB, 0x9, 0x1, 0xC, 0x3, 0x7, 0x4, 0xD, 0x0, 0x6, 0xF, 0x8, 0xE],
        #                7: [0x0, 0x4, 0xB, 0xE, 0x8, 0x3, 0x7, 0x1, 0xA, 0x2, 0x9, 0x6, 0xF, 0xD, 0x5, 0xC]}
        #
        # # id-Gost28147-89-CryptoPro-C-ParamSet
        # self.SBOXES = {0: [0x1, 0xB, 0xC, 0x2, 0x9, 0xD, 0x0, 0xF, 0x4, 0x5, 0x8, 0xE, 0xA, 0x7, 0x6, 0x3],
        #                1: [0x0, 0x1, 0x7, 0xD, 0xB, 0x4, 0x5, 0x2, 0x8, 0xE, 0xF, 0xC, 0x9, 0xA, 0x6, 0x3],
        #                2: [0x8, 0x2, 0x5, 0x0, 0x4, 0x9, 0xF, 0xA, 0x3, 0x7, 0xC, 0xD, 0x6, 0xE, 0x1, 0xB],
        #                3: [0x3, 0x6, 0x0, 0x1, 0x5, 0xD, 0xA, 0x8, 0xB, 0x2, 0x9, 0x7, 0xE, 0xF, 0xC, 0x4],
        #                4: [0x8, 0xD, 0xB, 0x0, 0x4, 0x5, 0x1, 0x2, 0x9, 0x3, 0xC, 0xE, 0x6, 0xF, 0xA, 0x7],
        #                5: [0xC, 0x9, 0xB, 0x1, 0x8, 0xE, 0x2, 0x4, 0x7, 0x3, 0x6, 0x5, 0xA, 0x0, 0xF, 0xD],
        #                6: [0xA, 0x9, 0x6, 0x8, 0xD, 0xE, 0x2, 0x0, 0xF, 0x3, 0x5, 0xB, 0x4, 0x1, 0xC, 0x7],
        #                7: [0x7, 0x4, 0x0, 0x5, 0xA, 0x2, 0xF, 0xE, 0xC, 0x6, 0x1, 0xB, 0xD, 0x9, 0x3, 0x8]}
        #
        # # id-Gost28147-89-CryptoPro-D-ParamSet
        # self.SBOXES = {0: [0xF, 0xC, 0x2, 0xA, 0x6, 0x4, 0x5, 0x0, 0x7, 0x9, 0xE, 0xD, 0x1, 0xB, 0x8, 0x3],
        #                1: [0xB, 0x6, 0x3, 0x4, 0xC, 0xF, 0xE, 0x2, 0x7, 0xD, 0x8, 0x0, 0x5, 0xA, 0x9, 0x1],
        #                2: [0x1, 0xC, 0xB, 0x0, 0xF, 0xE, 0x6, 0x5, 0xA, 0xD, 0x4, 0x8, 0x9, 0x3, 0x7, 0x2],
        #                3: [0x1, 0x5, 0xE, 0xC, 0xA, 0x7, 0x0, 0xD, 0x6, 0x2, 0xB, 0x4, 0x9, 0x3, 0xF, 0x8],
        #                4: [0x0, 0xC, 0x8, 0x9, 0xD, 0x2, 0xA, 0xB, 0x7, 0x3, 0x6, 0x5, 0x4, 0xE, 0xF, 0x1],
        #                5: [0x8, 0x0, 0xF, 0x3, 0x2, 0x5, 0xE, 0xB, 0x1, 0xA, 0x4, 0x7, 0xC, 0x9, 0xD, 0x6],
        #                6: [0x3, 0x0, 0x6, 0xF, 0x1, 0xE, 0x9, 0x2, 0xD, 0x8, 0xC, 0x4, 0xB, 0xA, 0x5, 0x7],
        #                7: [0x1, 0xA, 0x6, 0x8, 0xF, 0xB, 0x0, 0x4, 0xC, 0x3, 0x5, 0x9, 0x7, 0xD, 0x2, 0xE]}
        #
        # # id-tc26-gost-28147-param-Z
        # self.SBOXES = {0: [0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1],
        #                1: [0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF],
        #                2: [0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0],
        #                3: [0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB],
        #                4: [0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC],
        #                5: [0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0],
        #                6: [0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7],
        #                7: [0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2]}

        super().__init__(family_name="gost",
                         cipher_type="block_cipher",
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                         cipher_inputs_bit_size=[self.block_bit_size, self.key_bit_size],
                         cipher_output_bit_size=self.block_bit_size)

        state = INPUT_PLAINTEXT
        key = INPUT_KEY

        for round_i in range(number_of_rounds):
            self.add_round()
            if round_i < 24:
                round_key = self.add_round_key_output_component([key], [list(range((7-round_i % 8) * 32, ((7-round_i % 8) + 1) * 32))], 32).id
            else:
                round_key = self.add_round_key_output_component([key], [
                    list(range((round_i % 8) * 32, ((round_i % 8) + 1) * 32))], 32).id
            # MAGMA
            # if round_i < 24:
            #     round_key = self.add_round_key_output_component([key], [list(range((round_i % 8) * 32, ((round_i % 8) + 1) * 32))], 32).id
            # else:
            #     round_key = self.add_round_key_output_component([key], [
            #         list(range((7 - round_i % 8) * 32, ((7 - round_i % 8) + 1) * 32))], 32).id
            state = self.round_function(state, round_key)
        self.add_cipher_output_component([state, state], [list(range(32, 64)), list(range(32))], 64)

    def round_function(self, x, k):
        after_key_add = self.add_MODADD_component([x, k], [list(range(32, 64))] + [list(range(32))], 32).id
        sb_outputs = [self.add_SBOX_component([after_key_add], [list(range(i * 4, (i + 1) * 4))], 4,
                                              self.SBOXES[7-i]).id for i in range(8)]
        sb_outputs_rotated = self.add_rotate_component(sb_outputs, [list(range(4)) for _ in range(8)], 32, -11).id
        new_right_word = self.add_XOR_component([x, sb_outputs_rotated],
                                               [list(range(32)), list(range(32))], 32).id
        round_output = self.add_round_output_component([x, new_right_word], [list(range(32, 64)), list(range(32))], 64).id
        return round_output
