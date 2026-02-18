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
from claasp.name_mappings import BLOCK_CIPHER, INPUT_PLAINTEXT, INPUT_KEY
from claasp.utils.utils import get_number_of_rounds_from, extract_inputs

PARAMETERS_CONFIGURATION_LIST = [
    {"block_bit_size": 64, "key_bit_size": 128, "number_of_rounds": 8, "steps": 3},
    {"block_bit_size": 128, "key_bit_size": 128, "number_of_rounds": 8, "steps": 4},
    {"block_bit_size": 128, "key_bit_size": 256, "number_of_rounds": 10, "steps": 4},
]
reference_code = """
def sparx_encrypt(plaintext, key):
    from claasp.utils.integer_functions import bytearray_to_wordlist, wordlist_to_bytearray, lor, ror

    plaintext_size = {0}
    key_size = {1}
    steps = {2}
    arx_rounds = {3}

    def lambda_2(c):
        x = c[0]
        y = c[1]

        new_x = y ^ x ^ lor(x, 8, 32) ^ ror(x, 8, 32)
        new_y = x

        return [new_x, new_y]

    def lambda_4(c):
        x = c[0]
        y = c[1]

        t = ror(x ^ y, 8, 32) ^ lor(x ^ y, 8, 32)
        high = x ^ t
        low = y ^ t

        new_x = (low & 0xFFFF0000) | (high % 2**16)
        new_y = (high & 0xFFFF0000) | (low % 2**16)

        return [c[2] ^ new_x, c[3] ^ new_y, c[0], c[1]]

    def K_4_64(key, r):
        k = key[:]

        # Update k[0]
        k[0] = arx_box(k[0])

        # Update k[1]
        k0_high = k[0] // 2**16
        k0_low = k[0] % 2**16

        k1_high = k[1] // 2**16
        k1_low = k[1] % 2**16

        k[1] = ((k1_high + k0_high) % 2**16) * 2**16 + ((k1_low + k0_low) % 2**16)

        # Update k[3]
        k[3] = (k[3] // 2**16) * 2**16 + (k[3] + r) % 2**16  # can be changed?

        # rotate words in key
        k = k[-1:] + k[:-1]

        return k

    def K_4_128(key, r):
        k = key[:]

        # k1
        k1 = arx_box(k[0])
        k1_high = k1 // 2**16
        k1_low = k1 % 2**16

        # k2
        k2_high = ((k[1] // 2**16) + k1_high) % 2**16
        k2_low = (k[1] + k1_low) % 2**16
        k2 = k2_high * 2**16 | k2_low

        # k3
        k3 = arx_box(k[2])
        k3_high = k3 // 2**16
        k3_low = k3 % 2**16

        # k0
        k0_high = (k[3] // 2**16 + k3_high) % 2**16
        k0_low = (k[3] + r + k3_low) % 2**16
        k0 = k0_high * 2**16 | k0_low

        return [k0, k1, k2, k3]

    def K_8_256(key, r):
        k3 = arx_box(key[0])
        k3_high = k3 // 2**16
        k3_low = k3 % 2**16

        k4_low = (k3_low + key[1]) % 2**16
        k4_high = (k3_high + (key[1] // 2**16)) % 2**16
        k4 = k4_high * 2**16 | k4_low

        k7 = arx_box(key[4])
        k7_high = k7 // 2**16
        k7_low = k7 % 2**16

        k0_high = (k7_high + (key[5] // 2**16)) % 2**16
        k0_low = (k7_low + r + (key[5] % 2**16)) % 2**16
        k0 = k0_high * 2**16 | k0_low
        return [k0, key[6], key[7], k3, k4, key[2], key[3], k7]

    def arx_box(v):
        a = v // 2**16
        b = v % 2**16

        new_a = (ror(a, 7, 16) + b) % 2**16
        new_b = lor(b, 2, 16) ^ new_a

        return new_a * 2**16 + new_b

    if plaintext_size != 64 and plaintext_size != 128:
        raise ValueError("Plaintext size must either be 64 or 128 bits.")
    elif plaintext_size == 64 and key_size != 128:
        raise ValueError("Key size must be 128 bits with a plaintext of 64 bits.")
    elif plaintext_size == 128 and key_size != 128 and key_size != 256:
        raise ValueError("Key size must be 128 or 256 bits with a plaintext of 128 bits.")

    c = bytearray_to_wordlist(plaintext, 32, plaintext_size)
    k = bytearray_to_wordlist(key, 32, key_size)

    # assign the right functions
    if plaintext_size == 64:
        lambda_w = lambda_2
        key_permutation = K_4_64
    else:
        lambda_w = lambda_4
        if key_size == 128:
            key_permutation = K_4_128
        else:
            key_permutation = K_8_256

    for s in range(steps):
        for i in range(len(c)):
            for r in range(arx_rounds):
                c[i] = arx_box(c[i] ^ k[r])
            k = key_permutation(k, s * len(c) + i + 1)
        c = lambda_w(c)

    for i in range(len(c)):
        c[i] ^= k[i]

    return wordlist_to_bytearray(c, 32, plaintext_size)
"""


def get_number_of_steps_from(block_bit_size, key_bit_size, steps):
    if steps == 0:
        s = None
        for parameters in PARAMETERS_CONFIGURATION_LIST:
            if parameters["block_bit_size"] == block_bit_size and parameters["key_bit_size"] == key_bit_size:
                s = parameters["steps"]
                break
        if s is None:
            raise ValueError("No available number of steps for the given parameters.")
    else:
        s = steps

    return s


class SparxBlockCipher(Cipher):
    """
    Construct an instance of the SparxBlockCipher class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `64`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `128`); cipher key bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `0`); number of rounds of the cipher. The cipher uses the
      corresponding amount given the other parameters (if available) when number_of_rounds is 0
    - ``steps`` -- **integer** (default: `0`); number of steps for the ARX function. The cipher uses the corresponding
      amount given the other parameters (if available) when number_of_rounds is 0

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.sparx_block_cipher import SparxBlockCipher
        sage: sparx = SparxBlockCipher()
        sage: sparx.number_of_rounds
        8

        sage: sparx.component_from(0, 0).id
        'xor_0_0'

        sage: sparx.print_cipher_structure_as_python_dictionary_to_file(  # doctest: +SKIP
        ....: "claasp/graph_representations/block_ciphers/" + cipher.file_name)  # doctest: +SKIP
    """

    def __init__(self, block_bit_size=64, key_bit_size=128, number_of_rounds=0, steps=0):
        n = get_number_of_rounds_from(block_bit_size, key_bit_size, number_of_rounds, PARAMETERS_CONFIGURATION_LIST)
        s = get_number_of_steps_from(block_bit_size, key_bit_size, steps)

        super().__init__(
            family_name="sparx",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[block_bit_size, key_bit_size],
            cipher_output_bit_size=block_bit_size,
            cipher_reference_code=reference_code.format(block_bit_size, key_bit_size, n, s),
        )

        data = [INPUT_PLAINTEXT], [list(range(block_bit_size))]
        key = [INPUT_KEY], [list(range(key_bit_size))]
        key_permutation, lambda_w = self.assign_functions_based_on(block_bit_size, key_bit_size)
        self.word_number = block_bit_size // 32

        for round_number in range(n):
            self.add_round()
            new_data_words = [extract_inputs(*data, list(range(i * 32, (i + 1) * 32))) for i in range(self.word_number)]

            for i in range(self.word_number):
                for t in range(s):
                    # c[i] ^ k[r]
                    key_id_list, key_bit_positions = extract_inputs(*key, list(range(t * 32, (t + 1) * 32)))
                    xor_id = self.add_XOR_component(
                        new_data_words[i][0] + key_id_list, new_data_words[i][1] + key_bit_positions, 32
                    ).id
                    # c[i] = arx_box(c[i] ^ k[r])
                    arx_input = [xor_id], [list(range(32))]
                    new_data_words[i] = self.arx_box(arx_input, 0)

                key = key_permutation(key, round_number * self.word_number + i + 1)

            new_data_id_list = []
            new_data_bit_positions = []
            for word in new_data_words:
                new_data_id_list.extend(word[0])
                new_data_bit_positions.extend(word[1])
            data = new_data_id_list, new_data_bit_positions
            data = lambda_w(data)

            if round_number == n - 1:
                new_data_id_list = [""] * self.word_number
                for i in range(self.word_number):
                    data_id_list, data_bit_positions = extract_inputs(*data, list(range(i * 32, (i + 1) * 32)))
                    key_id_list, key_bit_positions = extract_inputs(*key, list(range(i * 32, (i + 1) * 32)))
                    new_data_id_list[i] = self.add_XOR_component(
                        data_id_list + key_id_list, data_bit_positions + key_bit_positions, 32
                    ).id
                data = new_data_id_list, [list(range(32))] * self.word_number

            self.add_round_output_component(*data, block_bit_size)

        self.add_cipher_output_component(*data, block_bit_size)

    def assign_functions_based_on(self, block_bit_size, key_bit_size):
        if block_bit_size == 64:
            lambda_w = self.lambda_2
            key_permutation = self.K_4_64
        else:
            lambda_w = self.lambda_4
            if key_bit_size == 128:
                key_permutation = self.K_4_128
            else:
                key_permutation = self.K_8_256

        return key_permutation, lambda_w

    def K_4_64(self, key, r):
        # k1 = arx_box(key[0])
        new_k1 = self.arx_box(key, 0)
        new_k1_high = [new_k1[0][0]], [new_k1[1][0]]
        new_k1_low = [new_k1[0][1]], [new_k1[1][1]]

        # k2 = key[1]_h + k1_h || k[1]_l + k1_l
        k1_high = extract_inputs(*key, list(range(32, 48)))
        new_k2_high_id = self.add_MODADD_component(k1_high[0] + new_k1_high[0], k1_high[1] + new_k1_high[1], 16).id

        k1_low = extract_inputs(*key, list(range(48, 64)))
        new_k2_low_id = self.add_MODADD_component(k1_low[0] + new_k1_low[0], k1_low[1] + new_k1_low[1], 16).id

        # k[3] = (k[3] // 2**16) * 2**16 + (k[3] + r) % 2**16 #can be changed?
        r_id = self.add_constant_component(16, r).id

        k3_low = extract_inputs(*key, list(range(112, 128)))
        new_k0_low_id = self.add_MODADD_component(k3_low[0] + [r_id], k3_low[1] + [list(range(16))], 16).id

        # Concatenate parts
        k3_high = extract_inputs(*key, list(range(96, 112)))
        k2 = extract_inputs(*key, list(range(64, 96)))
        new_key_id_list = k3_high[0] + [new_k0_low_id] + new_k1[0] + [new_k2_high_id, new_k2_low_id] + k2[0]
        new_key_bit_positions = k3_high[1] + [list(range(16))] + new_k1[1] + [list(range(16))] * 2 + k2[1]

        self.add_intermediate_output_component(new_key_id_list, new_key_bit_positions, 128, "key_permutation")

        return new_key_id_list, new_key_bit_positions

    def K_4_128(self, key, r):
        # k1 = arx_box(key[0])
        new_k1 = self.arx_box(key, 0)
        new_k1_high = [new_k1[0][0]], [new_k1[1][0]]
        new_k1_low = [new_k1[0][1]], [new_k1[1][1]]

        # k[2] = k1_h + k1_h || k1_l + k1_l
        k1_high = extract_inputs(*key, list(range(32, 48)))
        new_k2_high_id = self.add_MODADD_component(k1_high[0] + new_k1_high[0], k1_high[1] + new_k1_high[1], 16).id

        k1_low = extract_inputs(*key, list(range(48, 64)))
        new_k2_low_id = self.add_MODADD_component(k1_low[0] + new_k1_low[0], k1_low[1] + new_k1_low[1], 16).id

        # k[3] = arx_box(k[2])
        new_k3 = self.arx_box(key, 2)
        new_k3_high = [new_k3[0][0]], [new_k3[1][0]]
        new_k3_low = [new_k3[0][1]], [new_k3[1][1]]

        # k[0] =
        r_id = self.add_constant_component(16, r).id

        k3_high = extract_inputs(*key, list(range(96, 112)))
        new_k0_high_id = self.add_MODADD_component(k3_high[0] + new_k3_high[0], k3_high[1] + new_k3_high[1], 16).id

        k3_low = extract_inputs(*key, list(range(112, 128)))
        new_k0_low_id = self.add_MODADD_component(
            k3_low[0] + new_k3_low[0] + [r_id], k3_low[1] + new_k3_low[1] + [list(range(16))], 16
        ).id

        # Concatenate parts
        new_key_id_list = [new_k0_high_id, new_k0_low_id] + new_k1[0] + [new_k2_high_id, new_k2_low_id] + new_k3[0]
        new_key_bit_positions = [list(range(16))] * 2 + new_k1[1] + [list(range(16))] * 2 + new_k3[1]

        self.add_intermediate_output_component(new_key_id_list, new_key_bit_positions, 128, "key_permutation")

        return new_key_id_list, new_key_bit_positions

    def K_8_256(self, key, r):
        #
        new_k3 = self.arx_box(key, 0)
        new_k3_high = [new_k3[0][0]], [new_k3[1][0]]
        new_k3_low = [new_k3[0][1]], [new_k3[1][1]]

        # k1_low = (k3_low + key[1]) % 2**16
        k1_high = extract_inputs(*key, list(range(32, 48)))
        new_k4_high_id = self.add_MODADD_component(new_k3_high[0] + k1_high[0], new_k3_high[1] + k1_high[1], 16).id

        k1_low = extract_inputs(*key, list(range(48, 64)))
        new_k4_low_id = self.add_MODADD_component(new_k3_low[0] + k1_low[0], new_k3_low[1] + k1_low[1], 16).id

        # k7
        new_k7 = self.arx_box(key, 4)
        new_k7_high = [new_k7[0][0]], [new_k7[1][0]]
        new_k7_low = [new_k7[0][1]], [new_k7[1][1]]

        # k0_high = (k7_high + (key[5] // 2**16)) % 2**16
        r_id = self.add_constant_component(16, r).id

        k5_low = extract_inputs(*key, list(range(160, 176)))
        new_k0_high_id = self.add_MODADD_component(new_k7_high[0] + k5_low[0], new_k7_high[1] + k5_low[1], 16).id

        k5_high = extract_inputs(*key, list(range(176, 192)))
        new_k0_low_id = self.add_MODADD_component(
            new_k7_low[0] + k5_high[0] + [r_id], new_k7_low[1] + k5_high[1] + [list(range(16))], 16
        ).id

        # Concatenate parts
        k6_7 = extract_inputs(*key, list(range(192, 256)))
        k2_3 = extract_inputs(*key, list(range(64, 128)))
        new_key_id_list = (
            [new_k0_high_id, new_k0_low_id]
            + k6_7[0]
            + new_k3[0]
            + [new_k4_high_id, new_k4_low_id]
            + k2_3[0]
            + new_k7[0]
        )
        new_key_bit_positions = (
            [list(range(16))] * 2 + k6_7[1] + new_k3[1] + [list(range(16))] * 2 + k2_3[1] + new_k7[1]
        )

        self.add_intermediate_output_component(new_key_id_list, new_key_bit_positions, 256, "key_permutation")

        return new_key_id_list, new_key_bit_positions

    def arx_box(self, arx_input, i):
        # a >>> 7
        high_i_word = extract_inputs(*arx_input, list(range(i * 32, (i * 32) + 16)))
        rrot_id = self.add_rotate_component(*high_i_word, 16, 7).id

        # new_a = (a >>> 7) + b
        low_i_word = extract_inputs(*arx_input, list(range((i * 32) + 16, (i + 1) * 32)))
        new_a = self.add_MODADD_component([rrot_id] + low_i_word[0], [list(range(16))] + low_i_word[1], 16).id

        # b <<< 2
        lrot_id = self.add_rotate_component(*low_i_word, 16, -2).id

        # new_b = (b <<< 2) ^ new_a
        new_b = self.add_XOR_component([lrot_id, new_a], [list(range(16))] * 2, 16).id

        return [new_a, new_b], [list(range(16))] * 2

    def lambda_2(self, data):
        high_data_id_list, high_data_bit_positions = extract_inputs(*data, list(range(32)))

        # x <<< 8
        lrot = self.add_rotate_component(high_data_id_list, high_data_bit_positions, 32, -8).id

        # x >>> 8
        rrot = self.add_rotate_component(high_data_id_list, high_data_bit_positions, 32, 8).id

        # x ^ y ^ (x <<< 8) ^ (x >>> 8)
        xor_id = self.add_XOR_component(data[0] + [lrot, rrot], data[1] + [list(range(32))] * 2, 32).id

        return [xor_id] + high_data_id_list, [list(range(32))] + high_data_bit_positions

    def lambda_4(self, data):
        high_data_id_list, high_data_bit_positions = extract_inputs(*data, list(range(64)))

        # t = ror(x ^ y, 8, 32) ^ lor(x ^ y, 8, 32)
        xor1 = self.add_XOR_component(high_data_id_list, high_data_bit_positions, 32).id
        rrot = self.add_rotate_component([xor1], [list(range(32))], 32, 8).id
        lrot = self.add_rotate_component([xor1], [list(range(32))], 32, -8).id
        t = self.add_XOR_component([rrot, lrot], [list(range(32))] * 2, 32).id

        data_0_id_list, data_0_bit_positions = extract_inputs(*data, list(range(32)))
        data_1_id_list, data_1_bit_positions = extract_inputs(*data, list(range(32, 64)))

        # x ^ t
        xor_a = self.add_XOR_component(data_0_id_list + [t], data_0_bit_positions + [list(range(32))], 32).id

        # y ^ t
        xor_b = self.add_XOR_component(data_1_id_list + [t], data_1_bit_positions + [list(range(32))], 32).id

        data_2_id_list, data_2_bit_positions = extract_inputs(*data, list(range(64, 96)))
        data_3_id_list, data_3_bit_positions = extract_inputs(*data, list(range(96, 128)))

        # c[2] ^
        c0 = self.add_XOR_component(
            data_2_id_list + [xor_b, xor_a], data_2_bit_positions + [list(range(16)), list(range(16, 32))], 32
        ).id
        c1 = self.add_XOR_component(
            data_3_id_list + [xor_a, xor_b], data_3_bit_positions + [list(range(16)), list(range(16, 32))], 32
        ).id

        return [c0, c1] + high_data_id_list, [list(range(32))] * 2 + high_data_bit_positions
