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


from os.path import dirname
from os.path import exists
from os.path import realpath

from claasp.cipher import Cipher
from claasp.ciphers.block_ciphers import lowmc_generate_matrices
from claasp.name_mappings import BLOCK_CIPHER, INPUT_PLAINTEXT, INPUT_KEY

PARAMETERS_CONFIGURATION_LIST = [
    # See https://tches.iacr.org/index.php/TCHES/article/view/8680/8239 Table 6
    # for a complete description of the parameter sets of Picnic
    # picnic-L1-FS/UR
    {"block_bit_size": 128, "key_bit_size": 128, "number_of_rounds": 20, "number_of_sboxes": 10},
    # picnic-L1-full / picnic3-L1
    {"block_bit_size": 129, "key_bit_size": 129, "number_of_rounds": 4, "number_of_sboxes": 43},
    # picnic3-5-L1
    {"block_bit_size": 129, "key_bit_size": 129, "number_of_rounds": 5, "number_of_sboxes": 43},
    # picnic-L3-FS
    {"block_bit_size": 192, "key_bit_size": 192, "number_of_rounds": 30, "number_of_sboxes": 10},
    {"block_bit_size": 192, "key_bit_size": 192, "number_of_rounds": 4, "number_of_sboxes": 64},
    {"block_bit_size": 192, "key_bit_size": 192, "number_of_rounds": 5, "number_of_sboxes": 64},
    # L5
    {"block_bit_size": 256, "key_bit_size": 256, "number_of_rounds": 38, "number_of_sboxes": 10},
    {"block_bit_size": 255, "key_bit_size": 255, "number_of_rounds": 4, "number_of_sboxes": 85},
    {"block_bit_size": 255, "key_bit_size": 255, "number_of_rounds": 5, "number_of_sboxes": 85},
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

        # All test vectors below are taken from the Picnic reference implementation:
        # https://github.com/microsoft/Picnic/blob/master/unit_test.c

        # Vectorsets for Picnic-L1-20

        sage: from claasp.ciphers.block_ciphers.lowmc_block_cipher import LowMCBlockCipher
        sage: lowmc = LowMCBlockCipher(key_bit_size=128) # long time
        sage: key = 0x80000000000000000000000000000000 # long time
        sage: plaintext = 0xABFF0000000000000000000000000000 # long time
        sage: ciphertext = 0x0E30720B9F64D5C2A7771C8C238D8F70 # long time
        sage: assert lowmc.evaluate([plaintext, key]) == ciphertext # long time

        sage: from claasp.ciphers.block_ciphers.lowmc_block_cipher import LowMCBlockCipher
        sage: lowmc = LowMCBlockCipher(key_bit_size=128) # long time
        sage: key = 0xB5DF537B000000000000000000000000 # long time
        sage: plaintext = 0xF77DB57B000000000000000000000000 # long time
        sage: ciphertext = 0x0E5961E9992153B13245AF243DD7DDC0 # long time
        sage: assert lowmc.evaluate([plaintext, key]) == ciphertext # long time

        # Vectorsets for Picnic-L3-30

        sage: from claasp.ciphers.block_ciphers.lowmc_block_cipher import LowMCBlockCipher
        sage: lowmc = LowMCBlockCipher(block_bit_size=192, key_bit_size=192) # long time
        sage: key = 0x800000000000000000000000000000000000000000000000 # long time
        sage: plaintext = 0xABFF00000000000000000000000000000000000000000000 # long time
        sage: ciphertext = 0xA85B8244344A2E1B10A17BAB043073F6BB649AE6AF659F6F # long time
        sage: assert lowmc.evaluate([plaintext, key]) == ciphertext # long time

        sage: from claasp.ciphers.block_ciphers.lowmc_block_cipher import LowMCBlockCipher
        sage: lowmc = LowMCBlockCipher(block_bit_size=192, key_bit_size=192) # long time
        sage: key = 0xB5DF537B0000000000000000000000000000000000000000 # long time
        sage: plaintext = 0xF77DB57B0000000000000000000000000000000000000000 # long time
        sage: ciphertext = 0x210BBC4A434B32DB1E85AE7A27FEE9E41582FAC21D035AA1 # long time
        sage: assert lowmc.evaluate([plaintext, key]) == ciphertext # long time

        # Vectorsets for Picnic-L5-38

        sage: from claasp.ciphers.block_ciphers.lowmc_block_cipher import LowMCBlockCipher
        sage: lowmc = LowMCBlockCipher(block_bit_size=256, key_bit_size=256) # long time
        sage: key = 0x8000000000000000000000000000000000000000000000000000000000000000 # long time
        sage: plaintext = 0xABFF000000000000000000000000000000000000000000000000000000000000 # long time
        sage: ciphertext = 0xB8F20A888A0A9EC4E495F1FB439ABDDE18C1D3D29CF20DF4B10A567AA02C7267 # long time
        sage: assert lowmc.evaluate([plaintext, key]) == ciphertext # long time

        sage: from claasp.ciphers.block_ciphers.lowmc_block_cipher import LowMCBlockCipher
        sage: lowmc = LowMCBlockCipher(block_bit_size=256, key_bit_size=256) # long time
        sage: key = 0xF77DB57B00000000000000000000000000000000000000000000000000000000 # long time
        sage: plaintext = 0xB5DF537B00000000000000000000000000000000000000000000000000000000 # long time
        sage: ciphertext = 0xEEECCE6A584A93306DAEA07519B47AD6402C11DD942AA3166541444977A214C5 # long time
        sage: assert lowmc.evaluate([plaintext, key]) == ciphertext # long time

        # Vectorsets for Picnic3-L1-4
        # Note that all values need to be truncated to exact block_bit_size value
        # (129 bits, 136 might raise an error at some point)

        sage: from claasp.ciphers.block_ciphers.lowmc_block_cipher import LowMCBlockCipher
        sage: lowmc = LowMCBlockCipher(block_bit_size=129, key_bit_size=129) # long time
        sage: key = 0x8000000000000000000000000000000000 >> 7 # long time
        sage: plaintext = 0xabff000000000000000000000000000000 >> 7 # long time
        sage: ciphertext = 0x2fd7d5425ee35e667c972f12fb153e9d80 >> 7 # long time
        sage: assert lowmc.evaluate([plaintext, key]) == ciphertext # long time

        sage: from claasp.ciphers.block_ciphers.lowmc_block_cipher import LowMCBlockCipher
        sage: lowmc = LowMCBlockCipher(block_bit_size=129, key_bit_size=129) # long time
        sage: key = 0xab22425149aa612d7fff137220275b1680 >> 7 # long time
        sage: plaintext = 0x4b992353a60665bf992d035482c1d27900 >> 7 # long time
        sage: ciphertext = 0x2a4062d835c593ea19f822ad242477d280 >> 7 # long time
        sage: assert lowmc.evaluate([plaintext, key]) == ciphertext # long time

        sage: from claasp.ciphers.block_ciphers.lowmc_block_cipher import LowMCBlockCipher
        sage: lowmc = LowMCBlockCipher(block_bit_size=129, key_bit_size=129) # long time
        sage: key = 0xe73af29cfc7ae53e5220d31e2e5917da80 >> 7 # long time
        sage: plaintext = 0x304ba7a8de2b5cf887f9a48ab7561bf680 >> 7 # long time
        sage: ciphertext = 0x5cd2c355328efde9f378c16123d33fb300 >> 7 # long time
        sage: assert lowmc.evaluate([plaintext, key]) == ciphertext # long time

        sage: from claasp.ciphers.block_ciphers.lowmc_block_cipher import LowMCBlockCipher
        sage: lowmc = LowMCBlockCipher(block_bit_size=129, key_bit_size=129) # long time
        sage: key = 0x30f33488532d7eb8a5f8fb4f2e63ba5600 >> 7 # long time
        sage: plaintext = 0xc26a5df906158dcb6ac7891da9f49f7800 >> 7 # long time
        sage: ciphertext = 0xb43b65f7c535006cf27e86f551bd01580 >> 7 # long time
        sage: assert lowmc.evaluate([plaintext, key]) == ciphertext # long time

        # Vectorsets for Picnic3-L3-4

        sage: from claasp.ciphers.block_ciphers.lowmc_block_cipher import LowMCBlockCipher
        sage: lowmc = LowMCBlockCipher(block_bit_size=192, key_bit_size=192, number_of_rounds=4) # long time
        sage: key = 0x800000000000000000000000000000000000000000000000 # long time
        sage: plaintext = 0xABFF00000000000000000000000000000000000000000000 # long time
        sage: ciphertext = 0xf8f7a225de77123129107a20f5543afa7833076653ba2b29 # long time
        sage: assert lowmc.evaluate([plaintext, key]) == ciphertext # long time

        sage: from claasp.ciphers.block_ciphers.lowmc_block_cipher import LowMCBlockCipher
        sage: lowmc = LowMCBlockCipher(block_bit_size=192, key_bit_size=192, number_of_rounds=4) # long time
        sage: key = 0x81b85dfe40f612275aa3f9199139ebaae8dff8366f2dd34e # long time
        sage: plaintext = 0xb865ccf3fcda8ddbed527dc34dd4150d4a482dcbf7e9643c # long time
        sage: ciphertext = 0x95ef9ed7c37872a7b4602a3fa9c46ebcb84254ed0e44ee9f # long time
        sage: assert lowmc.evaluate([plaintext, key]) == ciphertext # long time

        sage: from claasp.ciphers.block_ciphers.lowmc_block_cipher import LowMCBlockCipher
        sage: lowmc = LowMCBlockCipher(block_bit_size=192, key_bit_size=192, number_of_rounds=4) # long time
        sage: key = 0x2405978fdaad9b6d8dcdd18a0c2c0ec68b69dd0a3754fe38 # long time
        sage: plaintext = 0x33e8b4552e95ef5279497706bce01ecb4acb860141b7fc43 # long time
        sage: ciphertext = 0xddaf0f9d9edd572069a8949faea0d1fd2d91ef262b411caf # long time
        sage: assert lowmc.evaluate([plaintext, key]) == ciphertext # long time

        sage: from claasp.ciphers.block_ciphers.lowmc_block_cipher import LowMCBlockCipher
        sage: lowmc = LowMCBlockCipher(block_bit_size=192, key_bit_size=192, number_of_rounds=4) # long time
        sage: key = 0x569d7d822300943d9483477427e88ea227a2e3172c04bcd3 # long time
        sage: plaintext = 0xaeeb9d5b61a2a56dd598f7da26dfd78cc992e0aea3fc2e39 # long time
        sage: ciphertext = 0x869870ae6547ad0afef27793170d96bc78e040096944808f # long time
        sage: assert lowmc.evaluate([plaintext, key]) == ciphertext # long time

        # Vectorsets for Picnic3-L5-4
        # Note that all values need to be truncated to exact block_bit_size value
        # (255 bits, 256 might raise an error at some point)

        sage: from claasp.ciphers.block_ciphers.lowmc_block_cipher import LowMCBlockCipher
        sage: lowmc = LowMCBlockCipher(block_bit_size=255, key_bit_size=255, number_of_rounds=4) # long time
        sage: key = 0x8000000000000000000000000000000000000000000000000000000000000000 >> 1 # long time
        sage: plaintext = 0xABFF000000000000000000000000000000000000000000000000000000000000 >> 1 # long time
        sage: ciphertext = 0xD4721D846DD14DBA3A2C41501C02DA282ECAFD72DF77992F3967EFD6E8F3F356 >> 1 # long time
        sage: assert lowmc.evaluate([plaintext, key]) == ciphertext # long time

        sage: from claasp.ciphers.block_ciphers.lowmc_block_cipher import LowMCBlockCipher
        sage: lowmc = LowMCBlockCipher(block_bit_size=255, key_bit_size=255, number_of_rounds=4) # long time
        sage: key = 0x7c20be53b6d6008149e19a34b97d9684a0914caf9f7f38b2499811369c3f53da >> 1 # long time
        sage: plaintext = 0x8863f129c0387ae5a402a49bd64927c4c65964fb8531b0d761b161b4c97b755e >> 1 # long time
        sage: ciphertext = 0x3b6e4b63cc8b08268b6781d5a629d6e03020c1c048d4684161b90ad73339126 >> 1 # long time
        sage: assert lowmc.evaluate([plaintext, key]) == ciphertext # long time

        sage: from claasp.ciphers.block_ciphers.lowmc_block_cipher import LowMCBlockCipher
        sage: lowmc = LowMCBlockCipher(block_bit_size=255, key_bit_size=255, number_of_rounds=4) # long time
        sage: key = 0x6df9e78d0fc1b870dabe520514b959636a42304bf43a2408524506c81ea30b14 >> 1 # long time
        sage: plaintext = 0x9e5178420520b8cca529595b80c4703b2dcf2a0730643a6f412798605f052b68 >> 1 # long time
        sage: ciphertext = 0x0f19fcc8bc18869aab8e4fe81e9767d18cfe715081929f92963b4000000626f8 >> 1 # long time
        sage: assert lowmc.evaluate([plaintext, key]) == ciphertext # long time

        sage: from claasp.ciphers.block_ciphers.lowmc_block_cipher import LowMCBlockCipher
        sage: lowmc = LowMCBlockCipher(block_bit_size=255, key_bit_size=255, number_of_rounds=4) # long time
        sage: key = 0xb071c6d4a377e551254c5dc401a3d08acb99609f418a8c2207f5122b5a17fe9a >> 1 # long time
        sage: plaintext = 0xf7616dc514fd0e1028561d098aafa54c34be728cf24a5024df17b9cc2e33fbfa >> 1 # long time
        sage: ciphertext = 0x4448c70ac3863021be232c63381687cd5defb50ba28d7b268e19727baebc679a >> 1 # long time
        sage: assert lowmc.evaluate([plaintext, key]) == ciphertext # long time

    """

    def __init__(self, block_bit_size=128, key_bit_size=128, number_of_rounds=0, number_of_sboxes=0):
        self.block_bit_size = block_bit_size
        self.key_bit_size = key_bit_size
        self.word_size = self.block_bit_size // 2
        self.sbox = [0x0, 0x7, 0x6, 0x5, 0x4, 0x1, 0x3, 0x2]
        self.matrices_for_linear_layer = []
        self.round_constants = []
        # Round key derivation matrices
        self.kmatrices = []

        super().__init__(
            family_name="lowmc",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[self.block_bit_size, self.key_bit_size],
            cipher_output_bit_size=self.block_bit_size,
        )

        number_of_rounds = self.define_number_of_rounds(number_of_rounds)
        self.n_sbox = self.define_number_of_sboxes(number_of_rounds, number_of_sboxes)

        self.constants = f"lowmc_constants_p{block_bit_size}_k{key_bit_size}_r{number_of_rounds}.dat"

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
            sbox_layer = self.sbox_layer(plaintext_id)

            # Affine layer
            linear_layer = self.linear_layer(sbox_layer, r)
            round_constant = self.add_round_constant(linear_layer, r)

            # Generate round key and add to the state
            rk_id = self.update_key_register(INPUT_KEY, r + 1)
            round_key = self.add_round_key(round_constant, rk_id)

            plaintext_id = self.add_output_component(number_of_rounds, plaintext_id, r, round_key)

    def add_output_component(self, number_of_rounds, plaintext_id, r, round_key):
        if r == number_of_rounds - 1:
            self.add_cipher_output_component([round_key], [list(range(self.block_bit_size))], self.block_bit_size)
        else:
            plaintext_id = self.add_round_output_component(
                [round_key], [list(range(self.block_bit_size))], self.block_bit_size
            ).id
            self.add_round()

        return plaintext_id

    def add_round_constant(self, plaintext_id, round_number):
        constant_id = self.add_constant_component(self.block_bit_size, self.round_constants[round_number]).id

        return self.add_XOR_component(
            [plaintext_id, constant_id], [list(range(self.block_bit_size))] * 2, self.block_bit_size
        ).id

    def add_round_key(self, plaintext_id, rk_id):
        return self.add_XOR_component(
            [plaintext_id, rk_id], [list(range(self.block_bit_size))] * 2, self.block_bit_size
        ).id

    def define_number_of_rounds(self, number_of_rounds):
        if number_of_rounds == 0:
            custom_number_of_rounds = None
            for parameters in PARAMETERS_CONFIGURATION_LIST:
                if (
                    parameters["block_bit_size"] == self.block_bit_size
                    and parameters["key_bit_size"] == self.key_bit_size
                ):
                    custom_number_of_rounds = parameters["number_of_rounds"]
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
                if (
                    parameters["block_bit_size"] == self.block_bit_size
                    and parameters["key_bit_size"] == self.key_bit_size
                    and parameters["number_of_rounds"] == number_of_rounds
                ):
                    number_of_sboxes = parameters["number_of_sboxes"]
                    break

            if number_of_sboxes is None:
                raise ValueError("No available number of sboxes for the given parameters.")
        else:
            number_of_sboxes = n_sbox

        return number_of_sboxes

    def linear_layer(self, plaintext_id, round_number):
        return self.add_linear_layer_component(
            [plaintext_id],
            [list(range(self.block_bit_size))],
            self.block_bit_size,
            self.matrices_for_linear_layer[round_number],
        ).id

    def load_constants(self, n):
        """
        Adapted from https://github.com/ThorKn/Python-LowMC/blob/master/lowmc/lowmc.py.

        Loads the precomputed matrices for the linear layer, the key schedule and the round constants
        from a .dat file generated using lowmc_generate_matrices.py
        """

        with open(dirname(realpath(__file__)) + "/" + self.constants, "r") as f:
            data = f.read().split("\n")

        # Checking file
        assert data[0] == str(self.block_bit_size), "Wrong blocksize in data file."
        assert data[1] == str(self.key_bit_size), "Wrong keysize in data file."
        assert data[2] == str(n), "Wrong number of rounds in data file."
        assert (len(data) - 1) == 3 + (((n * 2) + 1) * self.block_bit_size) + n, "Wrong file size (number of lines)."

        # Linear layer matrices
        lines_offset = 3
        lin_layer = data[lines_offset : (lines_offset + n * self.block_bit_size)]
        lin_layer_array = [list([int(i) for i in j]) for j in lin_layer]

        for r in range(n):
            mat = []
            for s in range(self.block_bit_size):
                mat.append(lin_layer_array[(r * self.block_bit_size) + s])
            # adding transpose of corresponding matrices
            # to use add_linear_layer() method
            self.matrices_for_linear_layer.append([list(i) for i in zip(*mat)])

        # Round constants
        lines_offset += n * self.block_bit_size
        round_consts = data[lines_offset : (lines_offset + n)]

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
            self.round_constants.append(line)

        # Round key matrices
        lines_offset += n
        round_key_mats = data[lines_offset : (lines_offset + (n + 1) * self.block_bit_size)]
        round_key_mats_array = [list([int(i) for i in j]) for j in round_key_mats]

        for r in range(n + 1):
            mat = []
            for s in range(self.block_bit_size):
                mat.append(round_key_mats_array[(r * self.block_bit_size) + s])
            self.kmatrices.append([list(i) for i in zip(*mat)])

    def sbox_layer(self, plaintext_id):
        sbox_output = [""] * self.n_sbox

        # m computations of 3 - bit sbox
        # remaining n - 3m bits remain the same
        for i in range(self.n_sbox):
            sbox_output[i] = self.add_SBOX_component([plaintext_id], [list(range(3 * i, 3 * (i + 1)))], 3, self.sbox).id

        return self.add_concatenate_component(
            sbox_output + [plaintext_id],
            [list(range(3))] * self.n_sbox + [list(range(3 * self.n_sbox, self.block_bit_size))],
            self.block_bit_size,
        ).id

    def update_key_register(self, key_id, round_number):
        rk_id = self.add_linear_layer_component(
            [key_id], [list(range(self.key_bit_size))], self.key_bit_size, self.kmatrices[round_number]
        ).id

        return self.add_round_key_output_component([rk_id], [list(range(self.key_bit_size))], self.key_bit_size).id
