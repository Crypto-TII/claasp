
# ****************************************************************************
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

PARAMETERS_CONFIGURATION_LIST = [{'block_bit_size': 64, 'key_bit_size': 128, 'number_of_rounds': 16}]
reference_code = """
def raiden_encrypt(plaintext, key):
    from claasp.utils.integer_functions import bytearray_to_wordlist, wordlist_to_bytearray

    plaintext_size = {0}
    key_size = {1}
    rounds = {2}
    right_shift_amount = {3}
    left_shift_amount = {4}

    block_size = plaintext_size // 2

    b = bytearray_to_wordlist(plaintext, block_size, plaintext_size)
    k = bytearray_to_wordlist(key, block_size, key_size)

    for i in range(rounds):
        k[i%4] = ((k[0] + k[1]) + ((k[2] + k[3]) ^ (k[0] << (k[2] % block_size))))
        sk = k[i%4] = k[i%4] % 2**block_size

        b[0] +=\
            ((sk + b[1]) << left_shift_amount) ^ (((sk - b[1])) ^ ((sk + b[1]) % 2**block_size) >> right_shift_amount)
        b[0] %= 2**block_size

        b[1] +=\
            ((sk + b[0]) << left_shift_amount) ^ ((((sk - b[0])) ^ ((sk + b[0]) % 2**block_size) >> right_shift_amount))
        b[1] %= 2**block_size

    return wordlist_to_bytearray(b, block_size, plaintext_size)
"""


class RaidenBlockCipher(Cipher):
    """
    Construct an instance of the RaidenBlockCipher class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `64`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `128`); cipher key bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `0`); number of rounds of the cipher. The cipher uses the
      corresponding amount given the other parameters (if available) when number_of_rounds is 0
    - ``right_shift_amount`` -- **integer** (default: `14`); number of bits to be shifted in each right shift of the cipher
    - ``left_shift_amount`` -- **integer** (default: `9`); number of bits to be shifted in each left shift of the cipher

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.raiden_block_cipher import RaidenBlockCipher
        sage: raiden = RaidenBlockCipher()
        sage: raiden.number_of_rounds
        16
        sage: raiden.component_from(0, 0).id
        'modadd_0_0'
    """

    def __init__(self, block_bit_size=64, key_bit_size=128, number_of_rounds=0,
                 right_shift_amount=14, left_shift_amount=9):
        self.word_size = block_bit_size // 2

        if number_of_rounds == 0:
            n = None

            for parameters in PARAMETERS_CONFIGURATION_LIST:
                if parameters['block_bit_size'] == block_bit_size and \
                        parameters['key_bit_size'] == key_bit_size:
                    n = parameters['number_of_rounds']
                    break

            if n is None:
                raise ValueError("No available number of rounds for the given parameters.")
        else:
            n = number_of_rounds

        super().__init__(family_name="raiden",
                         cipher_type="block_cipher",
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                         cipher_inputs_bit_size=[block_bit_size, key_bit_size],
                         cipher_output_bit_size=block_bit_size,
                         cipher_reference_code=reference_code.format(block_bit_size, key_bit_size,
                                                                     n, right_shift_amount, left_shift_amount))

        data = [(INPUT_PLAINTEXT, list(range(i * self.word_size, (i + 1) * self.word_size))) for i in range(2)]
        key = [(INPUT_KEY, list(range(i * self.word_size, (i + 1) * self.word_size))) for i in range(4)]

        word_bit_positions = list(range(self.word_size))

        for round_number in range(n):
            self.add_round()

            # OPERATION 1
            # k0 + k1
            sum1_id = self.add_MODADD_component([key[0][0], key[1][0]], [key[0][1], key[1][1]], self.word_size).id

            # k2 + k3
            sum2_id = self.add_MODADD_component([key[2][0], key[3][0]], [key[2][1], key[3][1]], self.word_size).id

            # k0 << k2
            ls1_id = \
                self.add_variable_shift_component([key[0][0], key[2][0]], [key[0][1], key[2][1]], self.word_size, -1).id

            # (k2 + k3) ^ (k0 << k2)
            xor1_id = self.add_XOR_component([sum2_id, ls1_id], [word_bit_positions] * 2, self.word_size).id

            # (k0 + k1) + ((k2 + k3) ^ (k0 << k2))
            sk_id = self.add_MODADD_component([sum1_id, xor1_id], [word_bit_positions] * 2, self.word_size).id

            # OPERATION 2
            # sk + v1
            sum3_id = self.add_MODADD_component(
                [sk_id, data[1][0]], [word_bit_positions, data[1][1]], self.word_size).id

            # (sk + v1) << ls
            ls2_id = self.add_SHIFT_component([sum3_id], [word_bit_positions], self.word_size, -left_shift_amount).id

            # sk - v1
            sub1_id = self.add_MODSUB_component(
                [sk_id, data[1][0]], [word_bit_positions, data[1][1]], self.word_size).id

            # (sk + v1) >> rs
            rs1_id = self.add_SHIFT_component([sum3_id], [word_bit_positions], self.word_size, right_shift_amount).id

            # ((sk + v1) << ls) ^ ((sk - v1) ^ ((sk + v1) >> rs))
            xor2_id = self.add_XOR_component([ls2_id, sub1_id, rs1_id], [word_bit_positions] * 3, self.word_size).id

            # v0 = v0 + ((sk + v1) << ls) ^ ((sk - v1) ^ ((sk + v1) >> rs))
            v0 = self.add_MODADD_component([data[0][0], xor2_id], [data[0][1], word_bit_positions], self.word_size).id

            # OPERATION 3
            # sk + v0
            sum4_id = self.add_MODADD_component([sk_id, v0], [word_bit_positions] * 2, self.word_size).id

            # (sk + v0) << ls
            ls3_id = self.add_SHIFT_component([sum4_id], [word_bit_positions], self.word_size, -left_shift_amount).id

            # sk - v0
            sub2_id = self.add_MODSUB_component([sk_id, v0], [word_bit_positions] * 2, self.word_size).id

            # (sk + v0) >> rs
            rs2_id = self.add_SHIFT_component([sum4_id], [word_bit_positions], self.word_size, right_shift_amount).id

            # ((sk + v0) << ls) ^ (sk - v0) ^ ((sk + v0) >> rs)
            xor3_id = self.add_XOR_component([ls3_id, sub2_id, rs2_id], [word_bit_positions] * 3, self.word_size).id

            # v1 = v1 + (((sk + v0) << ls) ^ (sk - v0) ^ ((sk + v0) >> rs))
            v1 = self.add_MODADD_component([data[1][0], xor3_id], [data[1][1], word_bit_positions], self.word_size).id

            # ROUND KEY OUTPUT
            key[round_number % 4] = sk_id, word_bit_positions

            self.add_round_key_output_component([key[0][0], key[1][0], key[2][0], key[3][0]],
                                                [key[0][1], key[1][1], key[2][1], key[3][1]],
                                                key_bit_size)

            # ROUND OUTPUT
            data[0] = v0, word_bit_positions
            data[1] = v1, word_bit_positions

            self.add_round_output_component([data[0][0], data[1][0]], [data[0][1], data[1][1]], block_bit_size)

        self.add_cipher_output_component([data[0][0], data[1][0]], [data[0][1], data[1][1]], block_bit_size)
