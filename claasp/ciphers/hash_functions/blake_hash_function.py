
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


from math import sqrt

from claasp.cipher import Cipher
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_STATE


PARAMETERS_CONFIGURATION_LIST = [
    {'block_bit_size': 512, 'state_bit_size': 512, 'number_of_rounds': 28},
    {'block_bit_size': 1024, 'state_bit_size': 1024, 'number_of_rounds': 32, 'word_size': 64}
]
default_permutations = {
    16: [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]
    ],
    8: [
        [0, 1, 2, 3, 4, 5, 6, 7],
        [4, 6, 1, 0, 2, 7, 5, 3],
        [0, 5, 2, 3, 6, 7, 1, 4],
        [7, 3, 1, 2, 6, 5, 4, 0],
    ],
    4: [
        [0, 1, 2, 3],
        [1, 0, 2, 3],
        [0, 2, 3, 1],
        [3, 1, 2, 0],
    ]
}
default_rot_amounts = {
    128: {
        4: [64, 48, 32, 127]
    },
    64: {
        4: [32, 25, 16, 11]
    },
    32: {
        4: [16, 12, 8, 7],
        3: [4, 3, 2]
    },
    16: {
        4: [8, 6, 4, 15]
    },
    8: {
        4: [4, 3, 2, 7]
    },
    4: {
        4: [2, 3, 1, 3],
        2: [2, 1]
    }
}
default_constants = {
    64: [
        0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89,
        0x452821e638d01377, 0xbe5466cf34e90c6c, 0xc0ac29b7c97c50dd, 0x3f84d5b5b5470917,
        0x9216d5d98979fb1b, 0xd1310ba698dfb5ac, 0x2ffd72dbd01adfb7, 0xb8e1afed6a267e96,
        0xba7c9045f12c7f99, 0x24a19947b3916cf7, 0x0801f2e2858efc16, 0x636920d871574e69
    ],
    32: [
        0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
        0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917
    ]
}
reference_code = f"""
def blake_encrypt(plaintext, state):
    from math import sqrt
    from claasp.utils.integer_functions import bytearray_to_wordlist, wordlist_to_bytearray, ror

    plaintext_size = {{0}}
    state_size = {{1}}
    rounds = {{2}}
    word_size = {{3}}

    ###CONSTANTS
    permutations = {{4}}
    rot_amounts = {{5}}
    constants = {{6}}

    def state_transformation(data_words, state_words, m0, m1):

        if n == 4:
            m = [m0, None, m1, None]
            c = [m1, None, m0, None]
        elif n == 3:
            m = [m0, None, m1]
            c = [m1, None, m0]
        elif n == 2:
            m = [m0, m1]
            c = [m1, m0]

        j = 0

        for i in range(n):
            if m[i] is None:
                opt_xor = 0
            else:
                opt_xor = constants[c[i]] ^ data_words[m[i]]

            state_words[j] = (state_words[j] + state_words[(j+1)%n] + opt_xor) % 2**word_size
            state_words[(j-1) % n] = ror(state_words[(j-1)%n] ^ state_words[j], rot_amounts[i], word_size)
            j = (j - 2) % n

    def column_step(data_words, state_words, r):
        for i in range(n):
            column_state_words = [state_words[i+j*n] for j in range(n)]

            m0 = permutations[(r//2) % len(permutations)][(2*i) % len(state)]
            m1 = permutations[(r//2) % len(permutations)][(2*i + 1) % len(state)]
            state_transformation(data_words, column_state_words, m0, m1)

            for j in range(n):
                state_words[i+j*n] = column_state_words[j]

    def diagonal_step(data_words, state_words, r):
        for i in range(n):
            diagonal_state_words = [state_words[j*n + ((i + j) % n)] for j in range(n)]

            m0 = permutations[(r//2) % len(permutations)][(2*n + 2*i) % len(state)]
            m1 = permutations[(r//2) % len(permutations)][(2*n + 2*i + 1) % len(state)]
            state_transformation(data_words, diagonal_state_words, m0, m1)

            for j in range(n):
                state_words[j*n + ((i + j) % n)] = diagonal_state_words[j]

    if plaintext_size != state_size:
        raise ValueError("Plaintext size must be equal to state size.")

    data_words = bytearray_to_wordlist(plaintext, word_size, plaintext_size)
    state_words = bytearray_to_wordlist(state, word_size, state_size)

    #number of cells in the message matrix
    n = int(sqrt(plaintext_size // word_size))

    for r in range(rounds):
        #STATE TRANSFORMATION
        if r % 2 == 0:
            #column step
            column_step(data_words, state_words, r)
        else:
            #diagonal step
            diagonal_step(data_words, state_words, r)

    #return state
    return wordlist_to_bytearray(state_words, word_size, state_size)
"""


# blake256 -> 512, 512, 28
class BlakeHashFunction(Cipher):
    """
    Construct an instance of the BlakeHashFunction class.

    This class is used to store compact representations of a cipher,
    used to generate the corresponding cipher.

    .. NOTE::

        In this cipher we are considering 0.5 rounds. So, if you need to run the first round according Blake
        specifications you need to set ``number_of_rounds`` equal to 2.
        If you need to run the first two rounds according Blake specifications you need to set ``number_of_rounds``
        equal to 4, and so on.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `512`); input block bit size of the hash
    - ``state_bit_size`` -- **integer** (default: `512`); state bit size of the hash
    - ``number_of_rounds`` -- **integer** (default: `0`); number of rounds of the hash. The cipher uses the corresponding
      amount given the other parameters (if available) when number_of_rounds is 0
    - ``word_size`` -- **integer** (default: `32`); word size in bits, used to split each parameter accordingly
      (plaintext and state)
    - ``permutations`` -- **list** (default: `None`); list of index (from 0 to block_bit_size//word_size-1)
      permutations. The cipher uses the standard permutation for the chosen configuration
    - ``rot_amounts`` -- **list** (default: `None`); list of amounts of bits to be rotated for rotation operations.
      The cipher uses the standard rotation amounts for the chosen configuration
    - ``constants`` -- **list** (default: `None`); list of constants used in the column and diagonal steps. The cipher
      uses the standard constants for the chosen configuration

    EXAMPLES::

        sage: from claasp.ciphers.hash_functions.blake_hash_function import BlakeHashFunction
        sage: blake = BlakeHashFunction()
        sage: blake.number_of_rounds
        28

        sage: blake.component_from(0, 0).id
        'constant_0_0'
    """

    def __init__(self, block_bit_size=512, state_bit_size=512, number_of_rounds=0, word_size=32, permutations=None,
                 rot_amounts=None, constants=None):
        self.block_bit_size = block_bit_size
        self.word_size = word_size
        self.state_size_in_words = self.block_bit_size // self.word_size
        self.n = int(sqrt(self.state_size_in_words))

        if self.n < 2 or self.n > 4:
            raise ValueError(f'Number of words in state not allowed ({self.state_size_in_words}).')

        self.permutations = self.define_permutations(permutations)
        self.rot_amounts = self.define_rotation_amounts(rot_amounts)
        self.constants = self.define_constants(constants)
        number_of_rounds = self.define_number_of_rounds(number_of_rounds, state_bit_size)

        super().__init__(family_name="blake",
                         cipher_type="hash_function",
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_STATE],
                         cipher_inputs_bit_size=[self.block_bit_size, state_bit_size],
                         cipher_output_bit_size=state_bit_size,
                         cipher_reference_code=reference_code.format(self.block_bit_size, state_bit_size,
                                                                     number_of_rounds, word_size, self.permutations,
                                                                     self.rot_amounts, self.constants))

        data_word_ids = [INPUT_PLAINTEXT] * self.state_size_in_words
        data_word_ranges = [list(range(i * self.word_size, (i + 1) * self.word_size))
                            for i in range(self.state_size_in_words)]
        state_word_ids = [INPUT_STATE] * self.state_size_in_words
        state_word_ranges = [list(range(i * self.word_size, (i + 1) * self.word_size))
                             for i in range(self.state_size_in_words)]

        for r in range(number_of_rounds):
            self.add_round()

            # STATE TRANSFORMATION
            if (r % 2) == 0:
                state_word_ids, state_word_ranges = self.column_step(data_word_ids, data_word_ranges,
                                                                     state_word_ids, state_word_ranges, r)
                self.add_round_output_component(state_word_ids, state_word_ranges, self.word_size * 16)
            else:
                state_word_ids, state_word_ranges = self.diagonal_step(data_word_ids, data_word_ranges,
                                                                       state_word_ids, state_word_ranges, r)
                self.add_round_output_component(state_word_ids, state_word_ranges, self.word_size * 16)

        self.add_cipher_output_component(state_word_ids, state_word_ranges, state_bit_size)

    def column_step(self, data_word_ids, data_word_ranges, state_word_ids, state_word_ranges, r):
        new_state_word_ids = state_word_ids.copy()
        new_state_word_ranges = state_word_ranges.copy()

        n_perm = len(self.permutations)

        for i in range(self.n):
            word_indexes = [i + j * self.n for j in range(self.n)]

            m0 = self.permutations[(r // 2) % n_perm][2 * i]
            m1 = self.permutations[(r // 2) % n_perm][2 * i + 1]

            new_state_words = self.state_transformation(data_word_ids, data_word_ranges, state_word_ids,
                                                        state_word_ranges, word_indexes, m0, m1)

            for j in range(self.n):
                new_state_word_ids[word_indexes[j]] = new_state_words[j]
                new_state_word_ranges[word_indexes[j]] = list(range(self.word_size))

        self.add_intermediate_output_component(new_state_word_ids, new_state_word_ranges,
                                               self.block_bit_size, 'column_step_output')

        return new_state_word_ids, new_state_word_ranges

    def define_constants(self, constants):
        if constants is None:
            return default_constants[self.word_size]
        return constants

    def define_number_of_rounds(self, number_of_rounds, state_bit_size):
        if number_of_rounds == 0:
            custom_number_of_rounds = None
            for parameters in PARAMETERS_CONFIGURATION_LIST:
                if parameters['block_bit_size'] == self.block_bit_size \
                        and parameters['state_bit_size'] == state_bit_size:
                    custom_number_of_rounds = parameters['number_of_rounds']
                    break
            if custom_number_of_rounds is None:
                raise ValueError("No available number of rounds for the given parameters.")
        else:
            custom_number_of_rounds = number_of_rounds

        return custom_number_of_rounds

    def define_permutations(self, permutations):
        if permutations is None:
            return default_permutations[self.state_size_in_words]

        return permutations

    def define_rotation_amounts(self, rot_amounts):
        if rot_amounts is None:
            return default_rot_amounts[self.word_size][self.n]

        return rot_amounts

    def diagonal_step(self, data_word_ids, data_word_ranges, state_word_ids, state_word_ranges, r):
        new_state_word_ids = state_word_ids.copy()
        new_state_word_ranges = state_word_ranges.copy()

        n_perm = len(self.permutations)

        for i in range(self.n):
            word_indexes = [j * self.n + ((i + j) % self.n) for j in range(self.n)]

            m0 = self.permutations[(r // 2) % n_perm][(2 * self.n + 2 * i) % self.state_size_in_words]
            m1 = self.permutations[(r // 2) % n_perm][(2 * self.n + 2 * i + 1) % self.state_size_in_words]

            new_state_words = self.state_transformation(data_word_ids, data_word_ranges, state_word_ids,
                                                        state_word_ranges, word_indexes, m0, m1)

            for j in range(self.n):
                new_state_word_ids[word_indexes[j]] = new_state_words[j]
                new_state_word_ranges[word_indexes[j]] = list(range(self.word_size))

        self.add_intermediate_output_component(new_state_word_ids, new_state_word_ranges,
                                               self.block_bit_size, 'diagonal_step_output')

        return new_state_word_ids, new_state_word_ranges

    def state_transformation(self, data_word_ids, data_word_ranges, state_word_ids,
                             state_word_ranges, word_indexes, m0, m1):
        m = c = None
        if self.n == 4:
            m = [m0, None, m1, None]
            c = [m1, None, m0, None]
        elif self.n == 3:
            m = [m0, None, m1]
            c = [m1, None, m0]
        elif self.n == 2:
            m = [m0, m1]
            c = [m1, m0]

        new_state_id = []
        new_state_range = []

        for i in word_indexes:
            new_state_id.append(state_word_ids[i])
            new_state_range.append(state_word_ranges[i])

        j = 0

        for i in range(self.n):
            if m[i] is None:
                new_state_id[j] = self.add_MODADD_component([new_state_id[j], new_state_id[(j + 1) % self.n]],
                                                            [new_state_range[j], new_state_range[(j + 1) % self.n]],
                                                            self.word_size).id
            else:
                const_id = self.add_constant_component(self.word_size, self.constants[c[i]]).id
                opt_xor_id = self.add_XOR_component([data_word_ids[m[i]], const_id],
                                                    [data_word_ranges[m[i]], list(range(self.word_size))],
                                                    self.word_size).id
                temp_add_id = self.add_MODADD_component([new_state_id[j], new_state_id[(j + 1) % self.n]],
                                                        [new_state_range[j], new_state_range[(j + 1) % self.n]],
                                                        self.word_size).id
                new_state_id[j] = self.add_MODADD_component([temp_add_id, opt_xor_id],
                                                            [list(range(self.word_size)), list(range(self.word_size))],
                                                            self.word_size).id

            new_state_range[j] = list(range(self.word_size))

            xor_id = self.add_XOR_component([new_state_id[(j - 1) % self.n], new_state_id[j]],
                                            [new_state_range[(j - 1) % self.n], new_state_range[j]],
                                            self.word_size).id

            new_state_id[(j - 1) % self.n] = self.add_rotate_component([xor_id],
                                                                       [list(range(self.word_size))],
                                                                       self.word_size,
                                                                       self.rot_amounts[i]).id
            new_state_range[(j - 1) % self.n] = list(range(self.word_size))

            j = (j - 2) % self.n

        return new_state_id
