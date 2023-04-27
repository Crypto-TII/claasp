
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


from os.path import exists
from os.path import dirname
from os.path import realpath

from claasp.cipher import Cipher
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY
from claasp.ciphers.block_ciphers import lowmc_generate_matrices

PARAMETERS_CONFIGURATION_LIST = [
    # See https://tches.iacr.org/index.php/TCHES/article/view/8680/8239 Table 6
    # for a complete description of the parameter sets of Picnic
    # picnic-L1-FS/UR
    {'block_bit_size': 128, 'key_bit_size': 128, 'number_of_rounds': 20, 'number_of_sboxes': 10},
    # picnic-L1-full / picnic3-L1
    {'block_bit_size': 129, 'key_bit_size': 129, 'number_of_rounds': 4, 'number_of_sboxes': 43},
    # picnic3-5-L1
    {'block_bit_size': 129, 'key_bit_size': 129, 'number_of_rounds': 5, 'number_of_sboxes': 43},

    # picnic-L3-FS
    {'block_bit_size': 192, 'key_bit_size': 192, 'number_of_rounds': 30, 'number_of_sboxes': 10},
    {'block_bit_size': 192, 'key_bit_size': 192, 'number_of_rounds': 4, 'number_of_sboxes': 64},
    {'block_bit_size': 192, 'key_bit_size': 192, 'number_of_rounds': 5, 'number_of_sboxes': 64},
    # L5
    {'block_bit_size': 256, 'key_bit_size': 256, 'number_of_rounds': 38, 'number_of_sboxes': 10},
    {'block_bit_size': 255, 'key_bit_size': 255, 'number_of_rounds': 4, 'number_of_sboxes': 85},
    {'block_bit_size': 255, 'key_bit_size': 255, 'number_of_rounds': 5, 'number_of_sboxes': 85}
]


class LowMCBlockCipher(Cipher):
    """
    Construct an instance of the LowMCBlockCipher class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `128`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `128`); cipher key bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `0`); number of rounds of the cipher. The cipher uses the corresponding
      amount given the other parameters (if available) when number_of_rounds is 0
    - ``number_of_sboxes`` -- **integer** (default: `0`); number of sboxes per round of the cipher. The cipher uses
      the corresponding amount given the other parameters (if available) when number_of_rounds is 0

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.lowmc_block_cipher import LowMCBlockCipher
        sage: lowmc = LowMCBlockCipher() # long time
        sage: lowmc.number_of_rounds # long time
        20
        sage: lowmc.component_from(0, 0).id # long time
        'linear_layer_0_0'
    """

    def __init__(self, block_bit_size=128, key_bit_size=128, number_of_rounds=0, number_of_sboxes=0):
        self.block_bit_size = block_bit_size
        self.key_bit_size = key_bit_size
        self.WORD_SIZE = self.block_bit_size // 2
        self.sbox = [0x00, 0x01, 0x03, 0x06, 0x07, 0x04, 0x05, 0x02]
        self.matrices_for_linear_layer = []
        self.ROUND_CONSTANTS = []
        # Round key derivation matrices
        self.KMATRICES = []

        super().__init__(family_name="lowmc",
                         cipher_type="block_cipher",
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                         cipher_inputs_bit_size=[self.block_bit_size, self.key_bit_size],
                         cipher_output_bit_size=self.block_bit_size)

        number_of_rounds = self.define_number_of_rounds(number_of_rounds)
        self.N_SBOX = self.define_number_of_sboxes(number_of_rounds, number_of_sboxes)

        self.constants = f'lowmc_constants_p{block_bit_size}_k{key_bit_size}_r{number_of_rounds}.dat'

        # Only generate constant data if needed
        if not exists(dirname(realpath(__file__)) + "/" + self.constants):
            lowmc_generate_matrices.main([block_bit_size, key_bit_size, number_of_rounds])

        self.load_constants(number_of_rounds)
        self.add_round()

        # Whitening key
        rk_id = self.update_key_register(INPUT_KEY, 0)
        plaintext_id = self.add_round_key(INPUT_PLAINTEXT, rk_id)

        for r in range(number_of_rounds):
            # Nonlinear layer
            sbox_layer_picnic = self.sbox_layer_picnic(plaintext_id)

            # Affine layer
            linear_layer = self.linear_layer(sbox_layer_picnic, r)
            round_constant = self.add_round_constant(linear_layer, r)

            # Generate round key and add to the state
            rk_id = self.update_key_register(INPUT_KEY, r + 1)
            round_key = self.add_round_key(round_constant, rk_id)

            plaintext_id = self.add_output_component(number_of_rounds, plaintext_id, r, round_key)

    def add_output_component(self, number_of_rounds, plaintext_id, r, round_key):
        if r == number_of_rounds - 1:
            self.add_cipher_output_component([round_key],
                                             [list(range(self.block_bit_size))],
                                             self.block_bit_size)
        else:
            plaintext_id = self.add_round_output_component([round_key],
                                                           [list(range(self.block_bit_size))],
                                                           self.block_bit_size).id
            self.add_round()

        return plaintext_id

    def add_round_constant(self, plaintext_id, round):
        constant_id = self.add_constant_component(self.block_bit_size, self.ROUND_CONSTANTS[round]).id

        return self.add_XOR_component([plaintext_id, constant_id],
                                      [list(range(self.block_bit_size))] * 2,
                                      self.block_bit_size).id

    def add_round_key(self, plaintext_id, rk_id):
        return self.add_XOR_component([plaintext_id, rk_id],
                                      [list(range(self.block_bit_size))] * 2,
                                      self.block_bit_size).id

    def define_number_of_rounds(self, number_of_rounds):
        if number_of_rounds == 0:
            custom_number_of_rounds = None
            for parameters in PARAMETERS_CONFIGURATION_LIST:
                if parameters['block_bit_size'] == self.block_bit_size \
                        and parameters['key_bit_size'] == self.key_bit_size:
                    custom_number_of_rounds = parameters['number_of_rounds']
                    break
            if custom_number_of_rounds is None:
                raise ValueError("No available number of rounds for the given parameters.")
        else:
            custom_number_of_rounds = number_of_rounds

        return custom_number_of_rounds

    def define_number_of_sboxes(self, number_of_rounds, n_sbox):
        if n_sbox == 0:
            number_of_sboxes = None

            for parameters in PARAMETERS_CONFIGURATION_LIST:
                if parameters['block_bit_size'] == self.block_bit_size \
                        and parameters['key_bit_size'] == self.key_bit_size \
                        and parameters['number_of_rounds'] == number_of_rounds:
                    number_of_sboxes = parameters['number_of_sboxes']
                    break

            if number_of_sboxes is None:
                raise ValueError("No available number of sboxes for the given parameters.")
        else:
            number_of_sboxes = n_sbox

        return number_of_sboxes

    def linear_layer(self, plaintext_id, round):
        return self.add_linear_layer_component([plaintext_id],
                                               [list(range(self.block_bit_size))],
                                               self.block_bit_size,
                                               self.matrices_for_linear_layer[round]).id

    def load_constants(self, n):
        """
        Adapted from https://github.com/ThorKn/Python-LowMC/blob/master/lowmc/lowmc.py.

        Loads the precomputed matrices for the linear layer, the key schedule and the round constants
        from a .dat file generated using lowmc_generate_matrices.py
        """

        with open(dirname(realpath(__file__)) + "/" + self.constants, 'r') as f:
            data = f.read().split('\n')

        # Checking file
        assert data[0] == str(self.block_bit_size), "Wrong blocksize in data file."
        assert data[1] == str(self.key_bit_size), "Wrong keysize in data file."
        assert data[2] == str(n), "Wrong number of rounds in data file."
        assert (len(data) - 1) == 3 + (((n * 2) + 1) * self.block_bit_size) + n, "Wrong file size (number of lines)."

        # Linear layer matrices
        lines_offset = 3
        lin_layer = data[lines_offset:(lines_offset + n * self.block_bit_size)]
        lin_layer_array = [list([int(i) for i in j]) for j in lin_layer]

        for r in range(n):
            mat = []
            for s in range(self.block_bit_size):
                mat.append(lin_layer_array[(r * self.block_bit_size) + s])
            # adding transpose of corresponding matrices
            # to use add_linear_layer() method
            self.matrices_for_linear_layer.append([list(i) for i in zip(*mat)])

        # Round constants
        lines_offset += (n * self.block_bit_size)
        round_consts = data[lines_offset:(lines_offset + n)]

        """
        EDIT: The following is not needed since the new round constant addition

        Round constant is reencoded as an integer whose size in bits is the nearest higher multiple of 8
        to avoid shifts due to int conversion
        e.g
            * for the 255-bit case, for n = 4 the first round constant is:

            c = '0b00100011101011110111111000110101100110100011010010100110101111100100100011000000000011010100011111\
            010110101000011111110010010001011100011110011010110000101000101110101100000011111001001101001010110010001\
            0110000001101000100010010001010011010111001110100010'

            hex(int(c,2)) = 0x11d7bf1acd1a535f246006a3eb50fe48b8f358517581f26959160688914d73a2
                              ^
            but we expect hex(int(c,2) = 0x23af7e359a34a6be48c00d47d6a1fc9171e6b0a2eb03e4d2b22c0d11229ae74, 0b010
            The reason is that int(c,2) converts c as a 256-bit int, thus, an extra 0 is prepended to it
            Since only the 255 first bits are considered when using the XOR component, computation is wrong
            To overcome this, c is shifted by 1 bit to the left, this does not affect computation since the xor
            operation will ignore the extra 0 appended.

            * for the 129-bit case for the constant:

            c = '0b010101000100101101111101101110110011010101010001110001100000100001101010001011001110001100001010001\
            000100101000001101101110000111'

            hex(int(c,2)) = 0xa896fb766aa38c10d459c61444a0db87

            but we expect hex(int(c,2)) = 0x544B7DBB3551C6086A2CE30A22506DC3, 0b1
            so shift c by 7 bits to the left

        """
        round_consts_array = [int(j, 2) for j in round_consts]

        for line in round_consts_array:
            self.ROUND_CONSTANTS.append(line)

        # Round key matrices
        lines_offset += n
        round_key_mats = data[lines_offset:(lines_offset + (n + 1) * self.block_bit_size)]
        round_key_mats_array = [list([int(i) for i in j]) for j in round_key_mats]

        for r in range(n + 1):
            mat = []
            for s in range(self.block_bit_size):
                mat.append(round_key_mats_array[(r * self.block_bit_size) + s])
            self.KMATRICES.append([list(i) for i in zip(*mat)])

    def sbox_layer(self, plaintext_id):
        sbox_output = [''] * self.N_SBOX

        # m computations of 3 - bit sbox
        # remaining n - 3m bits remain the same
        for i in range(self.N_SBOX):
            sbox_output[i] = self.add_SBOX_component([plaintext_id], [list(range(3 * i, 3 * (i + 1)))], 3, self.sbox).id

        return self.add_concatenate_component(sbox_output + [plaintext_id],
                                              [list(range(3))] * self.N_SBOX +
                                              [list(range(3 * self.N_SBOX, self.block_bit_size))],
                                              self.block_bit_size).id

    def sbox_layer_picnic(self, plaintext_id):
        """
        In the Picnic-Ref-Implementation, each 3-bit chunk is first reversed before applying the Sbox.

        The output is also reversed when added back to the state

        e.g.
          state[0:3] = '110' becomes '011', then is mapped to '110' via the
          Sbox finally, it is reversed to '011' for the state-update.
        """

        sbox_output = [''] * self.N_SBOX

        # m computations of 3 - bit sbox
        # remaining n - 3m bits remain the same
        for i in range(self.N_SBOX):
            sbox_output[i] = self.add_SBOX_component([plaintext_id], [list(range(3 * i, 3 * (i + 1)))[::-1]],
                                                     3, self.sbox).id

        return self.add_concatenate_component(sbox_output + [plaintext_id],
                                              [list(range(3))[::-1]] * self.N_SBOX +
                                              [list(range(3 * self.N_SBOX, self.block_bit_size))],
                                              self.block_bit_size).id

    def update_key_register(self, key_id, round):
        rk_id = self.add_linear_layer_component([key_id],
                                                [list(range(self.key_bit_size))],
                                                self.key_bit_size,
                                                self.KMATRICES[round]).id

        return self.add_round_key_output_component([rk_id], [list(range(self.key_bit_size))], self.key_bit_size).id
