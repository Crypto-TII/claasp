
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


from math import log2

from claasp.cipher import Cipher
from claasp.utils.utils import extract_inputs
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY

INPUT_TWEAK = "tweak"
round_constants = [
    [[14, 16], [46, 36, 19, 37], [24, 13, 8, 47, 8, 17, 22, 37]],
    [[52, 57], [33, 27, 14, 42], [38, 19, 10, 55, 49, 18, 23, 52]],
    [[23, 40], [17, 49, 36, 39], [33, 4, 51, 13, 34, 41, 59, 17]],
    [[5, 37], [44, 9, 54, 56], [5, 20, 48, 41, 47, 28, 16, 25]],
    [[25, 33], [39, 30, 34, 24], [41, 9, 37, 31, 12, 47, 44, 30]],
    [[46, 12], [13, 50, 10, 17], [16, 34, 56, 51, 4, 53, 42, 41]],
    [[58, 22], [25, 29, 39, 43], [31, 44, 47, 46, 19, 42, 44, 25]],
    [[32, 32], [8, 35, 56, 22], [9, 48, 35, 52, 23, 31, 37, 20]]
]
permutations = [
    [0, 3, 2, 1],
    [2, 1, 4, 7, 6, 5, 0, 3],
    [0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1]
]
PARAMETERS_CONFIGURATION_LIST = [
    {'block_bit_size': 256, 'key_bit_size': 256, 'tweak_bit_size': 128, 'number_of_rounds': 72},
    {'block_bit_size': 512, 'key_bit_size': 512, 'tweak_bit_size': 128, 'number_of_rounds': 72},
    {'block_bit_size': 1024, 'key_bit_size': 1024, 'tweak_bit_size': 128, 'number_of_rounds': 80}
]
reference_code = f"""
def threefish_encrypt(plaintext, key, tweak):
    from claasp.utils.integer_functions import bytearray_to_wordlist, wordlist_to_bytearray, lor

    plaintext_size = {{0}}
    key_size = {{1}}
    tweak_size = {{2}}
    rounds = {{3}}

    from math import log

    def mix(pt, d):
        n = int(log(len(pt), 2)) - 2

        for j in range(len(pt) // 2):
            x0 = pt[2*j]
            x1 = pt[2*j+1]
            r = round_constants[d % 8][n][j]

            #y0 := (x0 + x1) mod 2**64
            pt[2*j] = (x0 + x1) % 2**64
            #y1 := (x1 <<< round_constant) ^ y0
            pt[2*j+1] = lor(x1, r, 64) ^ pt[2*j]

    def word_permutation(pt):
        n = int(log(len(pt), 2)) - 2

        pt[:] = [pt[p] for p in permutations[n]]

    def subkey_schedule(k, t, d):
        s = d // 4
        subkey = [k[(s+i) % len(k)] for i in range(len(k) - 1)]

        subkey[-3] = (subkey[-3] + t[s % 3]) % 2**64
        subkey[-2] = (subkey[-2] + t[(s+1) % 3]) % 2**64
        subkey[-1] = (subkey[-1] + s) % 2**64

        return subkey

    def add_subkey(pt, subkey):
        for i in range(len(pt)):
            pt[i] += subkey[i]
            pt[i] = pt[i] % 2**64

    round_constants = {round_constants}
    permutations = {permutations}

    if plaintext_size != 256 and plaintext_size != 512 and plaintext_size != 1024:
        raise ValueError("Plaintext size must either be 256, 512 or 1024 bits.")
    if plaintext_size != key_size:
        raise ValueError("Key size must be equal to plaintext size.")
    if tweak_size != 128:
        raise ValueError("Tweak size must be 128 bits.")

    pt = bytearray_to_wordlist(plaintext, 64, plaintext_size)
    k = bytearray_to_wordlist(key, 64, plaintext_size)
    t = bytearray_to_wordlist(tweak, 64, 128)

    C = 0x1BD11BDAA9FC1A22

    k.append(C)

    for k_word in k[:-1]:
        k[-1] ^= k_word

    t.append(t[0] ^ t[1])

    for d in range(rounds):
        if d % 4 == 0:
            subkey = subkey_schedule(k, t, d)
            add_subkey(pt, subkey)

        mix(pt, d)
        word_permutation(pt)

    subkey = subkey_schedule(k, t, rounds)
    add_subkey(pt, subkey)

    return wordlist_to_bytearray(pt, 64, plaintext_size)
"""


class ThreefishBlockCipher(Cipher):
    """
    Construct an instance of the ThreefishBlockCipher class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `256`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `256`); cipher key bit size of the cipher
    - ``tweak_bit_size`` -- **integer** (default: `128`); cipher tweak bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `0`); number of rounds of the cipher. The cipher uses the
      corresponding amount given the other parameters (if available) when number_of_rounds is 0

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.threefish_block_cipher import ThreefishBlockCipher
        sage: threefish = ThreefishBlockCipher()
        sage: threefish.number_of_rounds
        72

        sage: threefish.component_from(0, 0).id
        'constant_0_0'
    """

    def __init__(self, block_bit_size=256, key_bit_size=256, tweak_bit_size=128, number_of_rounds=0):
        self.block_bit_size = block_bit_size
        self.word_size = 64
        self.nw = self.block_bit_size // self.word_size
        self.n = int(log2(self.nw)) - 2

        if number_of_rounds == 0:
            n = None
            for parameters in PARAMETERS_CONFIGURATION_LIST:
                if parameters['block_bit_size'] == self.block_bit_size and \
                        parameters['key_bit_size'] == key_bit_size and \
                        parameters['tweak_bit_size'] == tweak_bit_size:
                    n = parameters['number_of_rounds']
                    break
            if n is None:
                raise ValueError("No available number of rounds for the given parameters.")
        else:
            n = number_of_rounds

        super().__init__(family_name="threefish",
                         cipher_type="block_cipher",
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY, INPUT_TWEAK],
                         cipher_inputs_bit_size=[self.block_bit_size, key_bit_size, tweak_bit_size],
                         cipher_output_bit_size=self.block_bit_size,
                         cipher_reference_code=reference_code.format(self.block_bit_size,
                                                                     key_bit_size,
                                                                     tweak_bit_size, n))

        data = [INPUT_PLAINTEXT], [list(range(self.block_bit_size))]
        key = [INPUT_KEY], [list(range(key_bit_size))]
        tweak = [INPUT_TWEAK], [list(range(tweak_bit_size))]

        self.add_round()

        constant = self.add_constant_component(64, 0x1BD11BDAA9FC1A22).id

        key_id_list, key_bit_positions = extract_inputs(*key, list(range(self.block_bit_size)))
        xor_1 = self.add_XOR_component([constant] + key_id_list, [list(range(64))] + key_bit_positions, 64).id
        key = key_id_list + [xor_1], key_bit_positions + [list(range(64))]

        xor_2 = self.add_XOR_component(*tweak, 64).id
        tweak = tweak[0] + [xor_2], tweak[1] + [list(range(64))]

        for round_number in range(n):
            if round_number % 4 == 0:
                subkey = self.subkey_schedule(key, tweak, round_number)
                data = self.add_subkey(data, subkey)

                self.add_round_key_output_component(*subkey, self.block_bit_size)

            data = self.mix(data, round_number)
            data = self.word_permutation(data)

            if round_number != n - 1:
                self.add_round_output_component(*data, self.block_bit_size)
                self.add_round()

        subkey = self.subkey_schedule(key, tweak, n)
        data = self.add_subkey(data, subkey)

        self.add_round_output_component(*data, self.block_bit_size)
        self.add_round_key_output_component(*subkey, self.block_bit_size)

        self.add_cipher_output_component(*data, self.block_bit_size)

    def add_subkey(self, data, subkey):
        new_data = [''] * self.nw

        for i in range(self.nw):
            data_id_list, data_bit_positions = extract_inputs(*data, list(range(i * 64, (i + 1) * 64)))
            subkey_id_list, subkey_bit_positions = extract_inputs(*subkey, list(range(i * 64, (i + 1) * 64)))
            new_data[i] = self.add_MODADD_component(data_id_list + subkey_id_list,
                                                    data_bit_positions + subkey_bit_positions, 64).id

        return new_data, [list(range(64))] * self.nw

    def mix(self, data, d):
        new_data = [''] * self.nw

        for j in range(self.nw // 2):
            r = round_constants[d % 8][self.n][j]

            data_id_list, data_bit_positions = extract_inputs(*data, list(range(2 * j * 64, (2 * j + 2) * 64)))
            new_data[2 * j] = self.add_MODADD_component(data_id_list, data_bit_positions, 64).id

            data_id_list, data_bit_positions = \
                extract_inputs(*data, list(range((2 * j + 1) * 64, (2 * j + 2) * 64)))
            lrot = self.add_rotate_component(data_id_list, data_bit_positions, 64, -r).id

            new_data[2 * j + 1] = self.add_XOR_component([lrot, new_data[2 * j]], [list(range(64))] * 2, 64).id

        return new_data, [list(range(64))] * self.nw

    def subkey_schedule(self, key, tweak, d):
        s = d // 4

        subkey_id_list = []
        subkey_bit_positions = []

        for i in range(self.nw - 3):
            j = (s + i) % (self.nw + 1)
            key_id_list, key_bit_positions = extract_inputs(*key, list(range(j * 64, (j + 1) * 64)))

            subkey_id_list.extend(key_id_list)
            subkey_bit_positions.extend(key_bit_positions)

        subkey_id_list += [''] * 3
        subkey_bit_positions += [list(range(64))] * 3

        i = s % 3
        j = (s + self.nw - 3) % (self.nw + 1)
        key_id_list, key_bit_positions = extract_inputs(*key, list(range(j * 64, (j + 1) * 64)))
        tweak_id_list, tweak_bit_positions = extract_inputs(*tweak, list(range(i * 64, (i + 1) * 64)))
        subkey_id_list[-3] = self.add_MODADD_component(key_id_list + tweak_id_list,
                                                       key_bit_positions + tweak_bit_positions, 64).id

        i = (s + 1) % 3
        j = (s + self.nw - 2) % (self.nw + 1)
        key_id_list, key_bit_positions = extract_inputs(*key, list(range(j * 64, (j + 1) * 64)))
        tweak_id_list, tweak_bit_positions = extract_inputs(*tweak, list(range(i * 64, (i + 1) * 64)))
        subkey_id_list[-2] = self.add_MODADD_component(key_id_list + tweak_id_list,
                                                       key_bit_positions + tweak_bit_positions, 64).id

        s_const = self.add_constant_component(64, s).id
        j = (s + self.nw - 1) % (self.nw + 1)
        key_id_list, key_bit_positions = extract_inputs(*key, list(range(j * 64, (j + 1) * 64)))
        subkey_id_list[-1] = self.add_MODADD_component(key_id_list + [s_const], key_bit_positions + [list(range(64))],
                                                       64).id

        return subkey_id_list, subkey_bit_positions

    def word_permutation(self, data):
        wperm_id = self.add_word_permutation_component(*data, self.block_bit_size, permutations[self.n],
                                                       self.word_size).id

        return [wperm_id], [list(range(self.block_bit_size))]
