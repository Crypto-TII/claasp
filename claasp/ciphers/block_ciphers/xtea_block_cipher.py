
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

PARAMETERS_CONFIGURATION_LIST = [{'block_bit_size': 64, 'key_bit_size': 128, 'number_of_rounds': 32}]
reference_code = """
def xtea_encrypt(plaintext, key):
    from claasp.utils.integer_functions import bytearray_to_wordlist, wordlist_to_bytearray

    plaintext_size = {0}
    key_size = {1}
    rounds = {2}
    right_shift_amount = {3}
    left_shift_amount = {4}

    delta = 0x9E3779B9
    sum = 0

    block_size = plaintext_size // 2

    v = bytearray_to_wordlist(plaintext, block_size, plaintext_size)
    k = bytearray_to_wordlist(key, block_size, key_size)

    for _ in range(rounds):

        v[0] += (((v[1] << left_shift_amount) ^ (v[1] >> right_shift_amount)) + v[1]) ^ (sum + k[sum & 3])
        v[0] = v[0] % 2**block_size

        sum += delta

        v[1] += (((v[0] << left_shift_amount) ^ (v[0] >> right_shift_amount)) + v[0]) ^ (sum + k[(sum>>11) & 3])
        v[1] = v[1] % 2**block_size

    return wordlist_to_bytearray(v, block_size, plaintext_size)
"""


class XTeaBlockCipher(Cipher):
    """
    Construct an instance of the XTeaBlockCipher class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `64`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `128`); cipher key bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `0`); number of rounds of the cipher. The cipher uses the
      corresponding amount given the other parameters (if available) when number_of_rounds is 0
    - ``right_shift_amount`` -- **integer** (default: `5`); number of bits to be shifted in each right shift of the
      cipher
    - ``left_shift_amount`` -- **integer** (default: `4`); number of bits to be shifted in each left shift of the cipher

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.xtea_block_cipher import XTeaBlockCipher
        sage: xtea = XTeaBlockCipher()
        sage: xtea.number_of_rounds
        32

        sage: xtea.component_from(0, 0).id
        'shift_0_0'
    """

    def __init__(self, block_bit_size=64, key_bit_size=128,
                 number_of_rounds=0, right_shift_amount=5, left_shift_amount=4):
        self.word_size = block_bit_size // 2

        if number_of_rounds == 0:
            n = None
            for parameters in PARAMETERS_CONFIGURATION_LIST:
                if parameters['block_bit_size'] == block_bit_size and parameters['key_bit_size'] == key_bit_size:
                    n = parameters['number_of_rounds']
                    break
            if n is None:
                raise ValueError("No available number of rounds for the given parameters.")
        else:
            n = number_of_rounds

        super().__init__(family_name="xtea",
                         cipher_type="block_cipher",
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                         cipher_inputs_bit_size=[block_bit_size, key_bit_size],
                         cipher_output_bit_size=block_bit_size,
                         cipher_reference_code=reference_code.format(block_bit_size, key_bit_size, n,
                                                                     right_shift_amount, left_shift_amount))

        data = [(INPUT_PLAINTEXT, list(range(i * self.word_size, (i + 1) * self.word_size))) for i in range(2)]
        key = [(INPUT_KEY, list(range(i * self.word_size, (i + 1) * self.word_size))) for i in range(4)]

        word_bit_positions = list(range(self.word_size))

        for round_number in range(n):
            self.add_round()

            # OPERATION 1
            # v1 << l
            ls1_id = self.add_SHIFT_component([data[1][0]], [data[1][1]], self.word_size, -left_shift_amount).id

            # (v1 >> r)
            rs1_id = self.add_SHIFT_component([data[1][0]], [data[1][1]], self.word_size, right_shift_amount).id

            # (v1 << l) ^ (v1 >> r)
            xor1_id = self.add_XOR_component([ls1_id, rs1_id], [word_bit_positions] * 2, self.word_size).id

            # ((v1 << l) ^ (v1 >> r)) + v1
            sum1_id = self.add_MODADD_component([xor1_id, data[1][0]],
                                                [word_bit_positions, data[1][1]], self.word_size).id

            # sum constant
            sum_constant = (round_number * 0x9E3779B9) % 2 ** self.word_size
            sum_constant_id = self.add_constant_component(self.word_size, sum_constant).id

            # sum + key[sum & 3]
            i = sum_constant & 3
            sum2_id = self.add_MODADD_component([sum_constant_id, key[i][0]],
                                                [word_bit_positions, key[i][1]], self.word_size).id

            # (((v1 << l) ^ (v1 >> r)) + v1) ^ (sum + key[sum & 3])
            xor2_id = self.add_XOR_component([sum1_id, sum2_id], [word_bit_positions] * 2, self.word_size).id

            # v0 = v0 + ((((v1 << l) ^ (v1 >> r)) + v1) ^ (sum + key[sum & 3]))
            v0 = self.add_MODADD_component([data[0][0], xor2_id], [data[0][1], word_bit_positions], self.word_size).id

            # OPERATION 2
            # sum = sum + delta
            sum_constant = (sum_constant + 0x9E3779B9) % 2 ** self.word_size
            sum_constant_id = self.add_constant_component(self.word_size, sum_constant).id

            # v0 << l
            ls2_id = self.add_SHIFT_component([v0], [word_bit_positions], self.word_size, -left_shift_amount).id

            # v0 >> r
            rs2_id = self.add_SHIFT_component([v0], [word_bit_positions], self.word_size, right_shift_amount).id

            # (v0 << l) ^ (v0 >> r)
            xor3_id = self.add_XOR_component([ls2_id, rs2_id], [word_bit_positions] * 2, self.word_size).id

            # ((v0 << l) ^ (v0 >> r)) + v0
            sum3_id = self.add_MODADD_component([xor3_id, v0], [word_bit_positions] * 2, self.word_size).id

            # sum + key[(sum>>11) & 3]
            i = (sum_constant >> 11) & 3
            sum4_id = self.add_MODADD_component([sum_constant_id, key[i][0]],
                                                [word_bit_positions, key[i][1]], self.word_size).id

            # (((v0 << l) ^ (v0 >> r)) + v0) ^ (sum + key[(sum>>11) & 3])
            xor4_id = self.add_XOR_component([sum3_id, sum4_id], [word_bit_positions] * 2, self.word_size).id

            # v1 = v1 + ((((v0 << l) ^ (v0 >> r)) + v0) ^ (sum + key[(sum>>11) & 3]))
            v1 = self.add_MODADD_component([data[1][0], xor4_id], [data[1][1], word_bit_positions], self.word_size).id

            # ROUND OUTPUT
            data[0] = v0, word_bit_positions
            data[1] = v1, word_bit_positions

            self.add_round_output_component([data[0][0], data[1][0]], [data[0][1], data[1][1]], block_bit_size)

        self.add_cipher_output_component([data[0][0], data[1][0]], [data[0][1], data[1][1]], block_bit_size)
