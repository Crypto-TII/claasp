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


from os.path import dirname, exists, realpath

from claasp_next.graph.bit_builder import BitGraphPrimitive

# LowMC uses only vetted primitive-owned constant data
from claasp_next.primitive_inputs import BLOCK_CIPHER, INPUT_KEY, INPUT_PLAINTEXT

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


class LowMC(BitGraphPrimitive):
    """
    Construct an instance of the LowMC class.

    This class is used to store compact representations of a primitive, used to generate the corresponding primitive.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `128`); primitive input and output block bit size of the primitive
    - ``key_bit_size`` -- **integer** (default: `128`); primitive key bit size of the primitive
    - ``number_of_rounds`` -- **integer** (default: `0`); number of rounds of the primitive. The primitive uses the corresponding
      amount given the other parameters (if available) when number_of_rounds is 0
    - ``number_of_sboxes`` -- **integer** (default: `0`); number of sboxes per round of the primitive. The primitive uses
      the corresponding amount given the other parameters (if available) when number_of_rounds is 0

    EXAMPLES::

        >>> primitive = LowMC()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x50a25dfe7c67ab48', 127)
    """

    def __init__(
        self,
        block_bit_size=128,
        key_bit_size=128,
        number_of_rounds=None,
        number_of_sboxes=None,
    ):
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
            primitive_type=BLOCK_CIPHER,
            primitive_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            primitive_inputs_bit_size=[self.block_bit_size, self.key_bit_size],
            primitive_output_bit_size=self.block_bit_size,
        )

        number_of_rounds = self.define_number_of_rounds(number_of_rounds)
        self.n_sbox = self.define_number_of_sboxes(number_of_rounds, number_of_sboxes)

        self.constants = (
            f"lowmc_constants_p{block_bit_size}_k{key_bit_size}_r{number_of_rounds}.dat"
        )
        if not exists(dirname(realpath(__file__)) + "/data/" + self.constants):
            raise ValueError("unsupported LowMC parameter set: no vetted constant data is packaged")

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
        """Add the output component stage to this primitive's typed operation graph."""
        if r == number_of_rounds - 1:
            self.add_primitive_output_component(
                [round_key], [list(range(self.block_bit_size))], self.block_bit_size
            )
        else:
            plaintext_id = self.add_round_output_component(
                [round_key], [list(range(self.block_bit_size))], self.block_bit_size
            ).id
            self.add_round()

        return plaintext_id

    def add_round_constant(self, plaintext_id, round_number):
        """Add the round constant stage to this primitive's typed operation graph."""
        constant_id = self.add_constant_component(
            self.block_bit_size, self.round_constants[round_number]
        ).id

        return self.add_xor_component(
            [plaintext_id, constant_id], [list(range(self.block_bit_size))] * 2, self.block_bit_size
        ).id

    def add_round_key(self, plaintext_id, rk_id):
        return self.add_xor_component(
            [plaintext_id, rk_id], [list(range(self.block_bit_size))] * 2, self.block_bit_size
        ).id

    def define_number_of_rounds(self, number_of_rounds):
        """Define the number of rounds used while authoring this primitive graph."""
        if number_of_rounds is None:
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

        if (
            not isinstance(custom_number_of_rounds, int)
            or isinstance(custom_number_of_rounds, bool)
            or custom_number_of_rounds <= 0
        ):
            raise ValueError("number_of_rounds must be a positive integer")

        return custom_number_of_rounds

    def define_number_of_sboxes(self, number_of_rounds, n_sbox):
        """Define the number of sboxes used while authoring this primitive graph."""
        if n_sbox is None:
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

        if (
            not isinstance(number_of_sboxes, int)
            or isinstance(number_of_sboxes, bool)
            or number_of_sboxes <= 0
        ):
            raise ValueError("number_of_sboxes must be a positive integer")

        return number_of_sboxes

    def linear_layer(self, input_state, round_number):
        """Build the linear layer stage in this primitive's typed operation graph."""
        input_id_links, input_bit_positions = input_state
        return self.add_linear_layer_component(
            input_id_links,
            input_bit_positions,
            self.block_bit_size,
            self.matrices_for_linear_layer[round_number],
        ).id

    def load_constants(self, n):
        """
        Load the fixed LowMC matrices and round constants from package data.

        The file layout is adapted from the Python-LowMC generator and is
        validated against this instance's block size, key size, and round count.
        """

        with open(dirname(realpath(__file__)) + "/data/" + self.constants) as f:
            data = f.read().split("\n")

        # Checking file
        assert data[0] == str(self.block_bit_size), "Wrong blocksize in data file."
        assert data[1] == str(self.key_bit_size), "Wrong keysize in data file."
        assert data[2] == str(n), "Wrong number of rounds in data file."
        assert (len(data) - 1) == 3 + (((n * 2) + 1) * self.block_bit_size) + n, (
            "Wrong file size (number of lines)."
        )

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
        """Build the sbox layer stage in this primitive's typed operation graph."""
        sbox_output = [""] * self.n_sbox

        # m computations of 3 - bit sbox
        # remaining n - 3m bits remain the same
        for i in range(self.n_sbox):
            sbox_output[i] = self.add_sbox_component(
                [plaintext_id], [list(range(3 * i, 3 * (i + 1)))], 3, self.sbox
            ).id

        return (
            sbox_output + [plaintext_id],
            [list(range(3))] * self.n_sbox + [list(range(3 * self.n_sbox, self.block_bit_size))],
        )

    def update_key_register(self, key_id, round_number):
        """Build the update key register transition in this primitive's typed operation graph."""
        rk_id = self.add_linear_layer_component(
            [key_id],
            [list(range(self.key_bit_size))],
            self.key_bit_size,
            self.kmatrices[round_number],
        ).id

        return self.add_round_key_output_component(
            [rk_id], [list(range(self.key_bit_size))], self.key_bit_size
        ).id
