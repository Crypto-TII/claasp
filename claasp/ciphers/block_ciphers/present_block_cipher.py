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
from claasp.utils.utils import extract_inputs
from claasp.name_mappings import BLOCK_CIPHER, INPUT_PLAINTEXT, INPUT_KEY

sbox = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]
# fmt: off
permutations = [
    0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
    4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
    8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
    12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63
]
# fmt: on
PARAMETERS_CONFIGURATION_LIST = [
    {"key_bit_size": 80, "number_of_rounds": 31},
    {"key_bit_size": 128, "number_of_rounds": 31},
]
reference_code = f"""
def present_encrypt(plaintext, key):
    from claasp.utils.integer_functions import (
        wordlist_to_int,
        int_to_wordlist,
        wordlist_to_int,
        bytearray_to_int,
        bytearray_to_wordlist,
        int_to_bytearray,
    )

    key_size = {{0}}
    rounds = {{1}}

    sbox = {sbox}
    permutations = {permutations}

    def permutation_layer(state):
        pl = int_to_wordlist(state, 1, 64)
        pl[:] = [pl[permutations.index(i)] for i in range(64)]

        return wordlist_to_int(pl, 1)

    def sbox_layer(state):
        pl = int_to_wordlist(state, 4, 64)
        pl[:] = [sbox[i] for i in pl]

        return wordlist_to_int(pl, 4)

    def add_round_key(state, rk):
        return state ^ rk

    def update_key_register(key_register, key_size, i):
        # [k0, k1, ... , k78, k79] = [k61, k62, ... , k59, k60]
        key_register[:] = key_register[61:] + key_register[:61]

        # [k0, k1, k2, k3] = S[k0, k1, k2, k3]
        sbox_output = sbox[wordlist_to_int(key_register[:4], 1)]
        key_register[:4] = int_to_wordlist(sbox_output, 1, 4)

        if key_size == 80:
            # [k60, k61, k62, k63, k64] = [k60, k61, k62, k63, k64] ^ i
            key_register[60:65] = int_to_wordlist(wordlist_to_int(key_register[60:65], 1) ^ i, 1, 5)
        elif key_size == 128:
            # [k4, k5, k6, k7] = S[k4, k5, k6, k7]
            sbox_output = sbox[wordlist_to_int(key_register[4:8], 1)]
            key_register[4:8] = int_to_wordlist(sbox_output, 1, 4)

            # [k61, k62, k63, k64, k65] = [k61, k62, k63, k64, k65] ^ i
            key_register[61:66] = int_to_wordlist(wordlist_to_int(key_register[61:66], 1) ^ i, 1, 5)

    if key_size != 128 and key_size != 80:
        raise ValueError("Key size must either be 80 or 128 bits.")

    state = bytearray_to_int(plaintext)
    key_register = bytearray_to_wordlist(key, 1, key_size)

    for i in range(rounds):
        rk = wordlist_to_int(key_register[:64], 1)

        state = add_round_key(state, rk)
        state = sbox_layer(state)
        state = permutation_layer(state)
        update_key_register(key_register, key_size, i + 1)

    rk = wordlist_to_int(key_register[:64], 1)
    state = add_round_key(state, rk)

    return int_to_bytearray(state, 64)
"""


class PresentBlockCipher(Cipher):
    """
    Construct an instance of the PresentBlockCipher class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

    - ``key_bit_size`` -- **integer** (default: `80`); cipher key bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `None`); number of rounds of the cipher. The cipher uses the
      corresponding amount given the other parameters (if available) when number_of_rounds is None

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
        sage: present = PresentBlockCipher()
        sage: present.number_of_rounds
        31

        sage: present.component_from(0, 0).id
        'xor_0_0'
    """

    def __init__(self, key_bit_size=80, number_of_rounds=None):
        self.block_bit_size = 64
        self.key_bit_size = key_bit_size

        if number_of_rounds is None:
            n = None

            for parameters in PARAMETERS_CONFIGURATION_LIST:
                if parameters["key_bit_size"] == self.key_bit_size:
                    n = parameters["number_of_rounds"]
                    break

            if n is None:
                raise ValueError("No available number of rounds for the given parameters.")
        else:
            n = number_of_rounds

        super().__init__(
            family_name="present",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[self.block_bit_size, self.key_bit_size],
            cipher_output_bit_size=self.block_bit_size,
            cipher_reference_code=reference_code.format(self.key_bit_size, n),
        )

        data = [INPUT_PLAINTEXT], [list(range(self.block_bit_size))]
        key = [INPUT_KEY], [list(range(self.key_bit_size))]

        for r in range(n):
            self.add_round()

            data = self.add_round_key(data, key)
            data = self.sbox_layer(data)
            data = self.permutation_layer(data)

            key = self.update_key_register(key, r + 1)

            if r == n - 1:
                data = self.add_round_key(data, key)

            self.add_round_key_output_component(key[0], key[1], self.key_bit_size)
            self.add_round_output_component(data[0], data[1], self.block_bit_size)

        self.add_cipher_output_component(data[0], data[1], self.block_bit_size)

    def add_round_key(self, data, key):
        key_id_list, key_bit_positions = extract_inputs(*key, list(range(self.block_bit_size)))
        new_data_id = self.add_XOR_component(data[0] + key_id_list, data[1] + key_bit_positions, self.block_bit_size).id

        return [new_data_id], [list(range(self.block_bit_size))]

    def permutation_layer(self, data):
        new_data_id = self.add_permutation_component(data[0], data[1], self.block_bit_size, permutations).id

        return [new_data_id], [list(range(self.block_bit_size))]

    def sbox_layer(self, data):
        sbox_output = [""] * 16

        for i in range(16):
            sbox_output[i] = self.add_SBOX_component(data[0], [data[1][0][i * 4 : (i + 1) * 4]], 4, sbox).id

        return sbox_output, [list(range(4))] * 16

    def update_key_register(self, key, r):
        rot = self.add_rotate_component(key[0], key[1], self.key_bit_size, -61).id

        sbox_1 = self.add_SBOX_component([rot], [list(range(4))], 4, sbox).id

        constant_id = self.add_constant_component(8, r).id

        if self.key_bit_size == 80:
            xor = self.add_XOR_component([rot, constant_id], [list(range(60, 65)), list(range(3, 8))], 5).id
            return [sbox_1, rot, xor, rot], [list(range(4)), list(range(4, 60)), list(range(5)), list(range(65, 80))]

        if self.key_bit_size == 128:
            xor = self.add_XOR_component([rot, constant_id], [list(range(61, 66)), list(range(3, 8))], 5).id
            sbox_2 = self.add_SBOX_component([rot], [list(range(4, 8))], 4, sbox).id
            return [sbox_1, sbox_2, rot, xor, rot], [
                list(range(4)),
                list(range(4)),
                list(range(8, 61)),
                list(range(5)),
                list(range(66, 128)),
            ]
