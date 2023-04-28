
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
def tea_encrypt(plaintext, key):
    from claasp.utils.integer_functions import bytearray_to_wordlist, wordlist_to_bytearray

    plaintext_size = {0}
    key_size = {1}
    rounds = {2}
    right_shift_amount = {3}
    left_shift_amount = {4}

    delta = 0x9E3779B9
    round_sum = 0

    block_size = plaintext_size // 2

    v = bytearray_to_wordlist(plaintext, block_size, plaintext_size)
    k = bytearray_to_wordlist(key, block_size, key_size)

    for _ in range(rounds):
        round_sum += delta

        v[0] += ((v[1] << left_shift_amount) + k[0]) ^ (v[1] + round_sum) ^ ((v[1] >> right_shift_amount) + k[1])
        v[0] = v[0] % 2**block_size

        v[1] += ((v[0] << left_shift_amount) + k[2]) ^ (v[0] + round_sum) ^ ((v[0] >> right_shift_amount) + k[3])
        v[1] = v[1] % 2**block_size

    return wordlist_to_bytearray(v, block_size, plaintext_size)
"""


class TeaBlockCipher(Cipher):
    """
    Construct an instance of the TeaBlockCipher class.

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

        sage: from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
        sage: tea = TeaBlockCipher()
        sage: tea.number_of_rounds
        32

        sage: tea.component_from(0, 0).id
        'shift_0_0'
    """

    def __init__(self, block_bit_size=64, key_bit_size=128, number_of_rounds=0, right_shift_amount=5,
                 left_shift_amount=4):
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

        super().__init__(family_name="tea",
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

            # UPDATE OF V0
            # OPERAND 1
            # v1 << l
            ls1_id = self.add_SHIFT_component([data[1][0]], [data[1][1]], self.word_size, -left_shift_amount).id

            # (v1 << l) + k0
            sum1_id = self.add_MODADD_component([ls1_id, key[0][0]], [word_bit_positions, key[0][1]], self.word_size).id

            # sum = delta * (round+1)
            round_constant_id = self.add_constant_component(self.word_size,
                                                            ((round_number + 1) * 0x9E3779B9) % 2 ** self.word_size).id

            # OPERAND 2
            # v1 + sum
            sum2_id = self.add_MODADD_component([data[1][0], round_constant_id], [data[1][1], word_bit_positions],
                                                self.word_size).id

            # OPERAND 3
            # v1 >> r
            rs1_id = self.add_SHIFT_component([data[1][0]], [data[1][1]], self.word_size, right_shift_amount).id

            # (v1 >> r) + k1
            sum3_id = self.add_MODADD_component([rs1_id, key[1][0]], [word_bit_positions, key[1][1]], self.word_size).id

            # FINAL
            # ((v1 << l) + k0) XOR (v1 + sum) XOR ((v1 >> r) + k1)
            xor1_id = self.add_XOR_component([sum1_id, sum2_id, sum3_id], [word_bit_positions] * 3, self.word_size).id

            # v0 + (((v1 << l) + k0) XOR (v1 + sum) XOR ((v1 >> r) + k1))
            v0 = self.add_MODADD_component([data[0][0], xor1_id], [data[0][1], word_bit_positions], self.word_size).id

            # UPDATE OF V1
            # OPERAND 1
            # v0 << l
            ls2_id = self.add_SHIFT_component([v0], [word_bit_positions], self.word_size, -left_shift_amount).id

            # (v0 << l) + k2
            sum4_id = self.add_MODADD_component([ls2_id, key[2][0]], [word_bit_positions, key[2][1]], self.word_size).id

            # OPERAND 2
            # v0 + sum
            sum5_id = self.add_MODADD_component([v0, round_constant_id], [word_bit_positions] * 2, self.word_size).id

            # OPERAND 3
            # v0 >> r
            rs2_id = self.add_SHIFT_component([v0], [word_bit_positions], self.word_size, right_shift_amount).id

            # (v0 >> r) + k3
            sum6_id = self.add_MODADD_component([rs2_id, key[3][0]], [word_bit_positions, key[3][1]], self.word_size).id

            # FINAL
            # ((v0 << l) + k2) XOR (v0 + sum) XOR ((v0 >> r) + k3)
            xor2_id = self.add_XOR_component([sum4_id, sum5_id, sum6_id], [word_bit_positions] * 3, self.word_size).id

            # v1 + (((v0 << l) + k2) XOR (v0 + sum) XOR ((v0 >> r) + k3))
            v1 = self.add_MODADD_component([data[1][0], xor2_id], [data[1][1], word_bit_positions], self.word_size).id

            # ROUND OUTPUT
            data[0] = v0, word_bit_positions
            data[1] = v1, word_bit_positions

            self.add_round_output_component([data[0][0], data[1][0]], [data[0][1], data[1][1]], block_bit_size)

        self.add_cipher_output_component([data[0][0], data[1][0]], [data[0][1], data[1][1]], block_bit_size)
