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

PARAMETERS_CONFIGURATION_LIST = [
    {"block_bit_size": 32, "key_bit_size": 64, "number_of_rounds": 32},
    {"block_bit_size": 48, "key_bit_size": 72, "number_of_rounds": 36},
    {"block_bit_size": 48, "key_bit_size": 96, "number_of_rounds": 36},
    {"block_bit_size": 64, "key_bit_size": 96, "number_of_rounds": 42},
    {"block_bit_size": 64, "key_bit_size": 128, "number_of_rounds": 44},
    {"block_bit_size": 96, "key_bit_size": 96, "number_of_rounds": 52},
    {"block_bit_size": 96, "key_bit_size": 144, "number_of_rounds": 54},
    {"block_bit_size": 128, "key_bit_size": 128, "number_of_rounds": 68},
    {"block_bit_size": 128, "key_bit_size": 192, "number_of_rounds": 69},
    {"block_bit_size": 128, "key_bit_size": 256, "number_of_rounds": 72},
]
Z = [
    0x3E8958737D12B0E6,
    0x23BE4C2D477C985A,
    0x2BDC0D262847E5B3,
    0x36EB19781229CD0F,
    0x3479AD88170CA4EF,
]
WORDSIZE_TO_ZINDEX = {16: {4: 0}, 24: {3: 0, 4: 1}, 32: {3: 2, 4: 3}, 48: {2: 2, 3: 3}, 64: {2: 2, 3: 3, 4: 4}}
# fmt: off
SBOX = [
    0X00, 0X00, 0X00, 0X01, 0X00, 0X00, 0X02, 0X03, 0X00, 0X00, 0X00, 0X01, 0X04, 0X04, 0X06, 0X07,
    0X00, 0X00, 0X00, 0X01, 0X00, 0X00, 0X02, 0X03, 0X08, 0X08, 0X08, 0X09, 0X0C, 0X0C, 0X0E, 0X0F,
    0X00, 0X00, 0X00, 0X01, 0X00, 0X00, 0X02, 0X03, 0X00, 0X00, 0X00, 0X01, 0X04, 0X04, 0X06, 0X07,
    0X10, 0X10, 0X10, 0X11, 0X10, 0X10, 0X12, 0X13, 0X18, 0X18, 0X18, 0X19, 0X1C, 0X1C, 0X1E, 0X1F,
    0X00, 0X00, 0X00, 0X01, 0X00, 0X00, 0X02, 0X03, 0X00, 0X00, 0X00, 0X01, 0X04, 0X04, 0X06, 0X07,
    0X00, 0X00, 0X00, 0X01, 0X00, 0X00, 0X02, 0X03, 0X08, 0X08, 0X08, 0X09, 0X0C, 0X0C, 0X0E, 0X0F,
    0X20, 0X20, 0X20, 0X21, 0X20, 0X20, 0X22, 0X23, 0X20, 0X20, 0X20, 0X21, 0X24, 0X24, 0X26, 0X27,
    0X30, 0X30, 0X30, 0X31, 0X30, 0X30, 0X32, 0X33, 0X38, 0X38, 0X38, 0X39, 0X3C, 0X3C, 0X3E, 0X3F,
    0X00, 0X00, 0X00, 0X01, 0X00, 0X00, 0X02, 0X03, 0X00, 0X00, 0X00, 0X01, 0X04, 0X04, 0X06, 0X07,
    0X00, 0X00, 0X00, 0X01, 0X00, 0X00, 0X02, 0X03, 0X08, 0X08, 0X08, 0X09, 0X0C, 0X0C, 0X0E, 0X0F,
    0X00, 0X00, 0X00, 0X01, 0X00, 0X00, 0X02, 0X03, 0X00, 0X00, 0X00, 0X01, 0X04, 0X04, 0X06, 0X07,
    0X10, 0X10, 0X10, 0X11, 0X10, 0X10, 0X12, 0X13, 0X18, 0X18, 0X18, 0X19, 0X1C, 0X1C, 0X1E, 0X1F,
    0X40, 0X40, 0X40, 0X41, 0X40, 0X40, 0X42, 0X43, 0X40, 0X40, 0X40, 0X41, 0X44, 0X44, 0X46, 0X47,
    0X40, 0X40, 0X40, 0X41, 0X40, 0X40, 0X42, 0X43, 0X48, 0X48, 0X48, 0X49, 0X4C, 0X4C, 0X4E, 0X4F,
    0X60, 0X60, 0X60, 0X61, 0X60, 0X60, 0X62, 0X63, 0X60, 0X60, 0X60, 0X61, 0X64, 0X64, 0X66, 0X67,
    0X70, 0X70, 0X70, 0X71, 0X70, 0X70, 0X72, 0X73, 0X78, 0X78, 0X78, 0X79, 0X7C, 0X7C, 0X7E, 0X7F,
    0X00, 0X00, 0X00, 0X01, 0X00, 0X00, 0X02, 0X03, 0X00, 0X00, 0X00, 0X01, 0X04, 0X04, 0X06, 0X07,
    0X00, 0X00, 0X00, 0X01, 0X00, 0X00, 0X02, 0X03, 0X08, 0X08, 0X08, 0X09, 0X0C, 0X0C, 0X0E, 0X0F,
    0X00, 0X00, 0X00, 0X01, 0X00, 0X00, 0X02, 0X03, 0X00, 0X00, 0X00, 0X01, 0X04, 0X04, 0X06, 0X07,
    0X10, 0X10, 0X10, 0X11, 0X10, 0X10, 0X12, 0X13, 0X18, 0X18, 0X18, 0X19, 0X1C, 0X1C, 0X1E, 0X1F,
    0X00, 0X00, 0X00, 0X01, 0X00, 0X00, 0X02, 0X03, 0X00, 0X00, 0X00, 0X01, 0X04, 0X04, 0X06, 0X07,
    0X00, 0X00, 0X00, 0X01, 0X00, 0X00, 0X02, 0X03, 0X08, 0X08, 0X08, 0X09, 0X0C, 0X0C, 0X0E, 0X0F,
    0X20, 0X20, 0X20, 0X21, 0X20, 0X20, 0X22, 0X23, 0X20, 0X20, 0X20, 0X21, 0X24, 0X24, 0X26, 0X27,
    0X30, 0X30, 0X30, 0X31, 0X30, 0X30, 0X32, 0X33, 0X38, 0X38, 0X38, 0X39, 0X3C, 0X3C, 0X3E, 0X3F,
    0X80, 0X80, 0X80, 0X81, 0X80, 0X80, 0X82, 0X83, 0X80, 0X80, 0X80, 0X81, 0X84, 0X84, 0X86, 0X87,
    0X80, 0X80, 0X80, 0X81, 0X80, 0X80, 0X82, 0X83, 0X88, 0X88, 0X88, 0X89, 0X8C, 0X8C, 0X8E, 0X8F,
    0X80, 0X80, 0X80, 0X81, 0X80, 0X80, 0X82, 0X83, 0X80, 0X80, 0X80, 0X81, 0X84, 0X84, 0X86, 0X87,
    0X90, 0X90, 0X90, 0X91, 0X90, 0X90, 0X92, 0X93, 0X98, 0X98, 0X98, 0X99, 0X9C, 0X9C, 0X9E, 0X9F,
    0XC0, 0XC0, 0XC0, 0XC1, 0XC0, 0XC0, 0XC2, 0XC3, 0XC0, 0XC0, 0XC0, 0XC1, 0XC4, 0XC4, 0XC6, 0XC7,
    0XC0, 0XC0, 0XC0, 0XC1, 0XC0, 0XC0, 0XC2, 0XC3, 0XC8, 0XC8, 0XC8, 0XC9, 0XCC, 0XCC, 0XCE, 0XCF,
    0XE0, 0XE0, 0XE0, 0XE1, 0XE0, 0XE0, 0XE2, 0XE3, 0XE0, 0XE0, 0XE0, 0XE1, 0XE4, 0XE4, 0XE6, 0XE7,
    0XF0, 0XF0, 0XF0, 0XF1, 0XF0, 0XF0, 0XF2, 0XF3, 0XF8, 0XF8, 0XF8, 0XF9, 0XFC, 0XFC, 0XFE, 0XFF,
]
# fmt: on


class SimonSboxBlockCipher(Cipher):
    """
    Construct an instance of the SimonSboxBlockCipher class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `32`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `64`); cipher key bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `None`); number of rounds of the cipher. The cipher uses the
      corresponding amount given the other parameters (if available) when number_of_rounds is None
    - ``rotation_amount`` -- **tuple** (default: `(-1, -8, -2)`); the tuple containing the 3 rotation amounts for the
      round function

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.simon_sbox_block_cipher import SimonSboxBlockCipher
        sage: simon_sbox = SimonSboxBlockCipher()
        sage: simon_sbox.number_of_rounds
        32

        sage: simon_sbox.component_from(0, 0).id
        'intermediate_output_0_0'
    """

    def __init__(self, block_bit_size=32, key_bit_size=64, number_of_rounds=None, rotation_amounts=(-1, -8, -2)):
        self.block_bit_size = block_bit_size
        self.key_bit_size = key_bit_size
        self.word_size = self.block_bit_size // 2
        self.number_of_key_words = key_bit_size // self.word_size
        self.rotation_amounts = rotation_amounts
        self.z = Z[WORDSIZE_TO_ZINDEX[self.word_size][self.number_of_key_words]]
        self.c = 2**self.word_size - 4
        self.number_of_sboxes = self.word_size // 8

        if number_of_rounds is None:
            for parameters in PARAMETERS_CONFIGURATION_LIST:
                if (
                    parameters["block_bit_size"] == self.block_bit_size
                    and parameters["key_bit_size"] == self.key_bit_size
                ):
                    number_of_rounds = parameters["number_of_rounds"]
                    break
            if number_of_rounds is None:
                raise ValueError("No available number of rounds for the given parameters.")

        super().__init__(
            family_name="simon_sbox",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[self.block_bit_size, key_bit_size],
            cipher_output_bit_size=self.block_bit_size,
        )

        x = INPUT_PLAINTEXT, list(range(self.word_size))
        y = INPUT_PLAINTEXT, list(range(self.word_size, 2 * self.word_size))

        round_keys = [None] * number_of_rounds

        for round_number in range(number_of_rounds):
            self.add_round()
            self.generate_round_key(round_keys, round_number)
            x, y = self.feistel_function(x, y, round_keys[round_number])

        self.add_cipher_output_component([x[0], y[0]], [x[1], y[1]], self.block_bit_size)

    def f(self, x):
        # f(x) = ((x <<< 1) & (x <<< 8)) ^ (x <<< 2)
        input_positions_pattern = (1, 8, 15, 22, 29, 36, 43, 50, 57)
        output_positions_pattern = (0, 7, 14, 21, 28, 35, 42, 49)
        output_ids = [""] * self.word_size
        output_positions = [0] * self.word_size
        for i in range(self.number_of_sboxes):
            sbox_input_positions = [(position + 8 * i) % self.word_size for position in input_positions_pattern]
            sbox_id = self.add_SBOX_component([x[0]], [sbox_input_positions], 8, SBOX).id
            sbox_output_positions = [(position + 8 * i) % self.word_size for position in output_positions_pattern]
            for j, sbox_output_position in enumerate(sbox_output_positions):
                output_ids[sbox_output_position] = sbox_id
                output_positions[sbox_output_position] = j
        sboxes_ids = [output_ids[0]]
        sboxes_positions = [[output_positions[0]]]
        for i in range(1, self.word_size):
            if output_ids[i] != sboxes_ids[-1]:
                sboxes_ids.append(output_ids[i])
                sboxes_positions.append([output_positions[i]])
            else:
                sboxes_positions[-1].append(output_positions[i])

        s2_x_input_positions = list(map(int(self.word_size).__rmod__, range(2, 2 + self.word_size)))
        feistel_id = self.add_XOR_component(
            [*sboxes_ids, x[0]], [*sboxes_positions, s2_x_input_positions], self.word_size
        ).id

        return feistel_id, list(range(self.word_size))

    def feistel_function(self, x, y, k):
        # Rk(x, y) = (y ⊕ f(x) ⊕ k, x)
        feistel_id, feistel_positions = self.f(x)
        new_x_id = self.add_XOR_component([y[0], feistel_id, k[0]], [y[1], feistel_positions, k[1]], self.word_size).id

        self.add_round_output_component([new_x_id, x[0]], [list(range(self.word_size)), x[1]], self.block_bit_size).id

        return (new_x_id, list(range(self.word_size))), (x[0], x[1])

    def generate_round_key(self, round_keys, round_number):
        if round_number < self.number_of_key_words:
            key_index = self.number_of_key_words - round_number - 1

            self.add_round_key_output_component(
                [INPUT_KEY], [list(range(self.word_size * key_index, self.word_size * (key_index + 1)))], self.word_size
            ).id
            round_keys[round_number] = (
                INPUT_KEY,
                list(range(self.word_size * key_index, self.word_size * (key_index + 1))),
            )

        else:
            constant_index = round_number - self.number_of_key_words

            # c ^ z[j][i]
            round_constant = self.add_constant_component(
                self.word_size, self.c ^ ((self.z >> (61 - (constant_index % 62))) & 1)
            ).id

            s3_x_input_positions = [(i - 3) % self.word_size for i in range(self.word_size)]
            s1_x_input_positions = [(i - 1) % self.word_size for i in range(self.word_size)]
            s4_x_input_positions = [(i - 4) % self.word_size for i in range(self.word_size)]

            if self.number_of_key_words == 4:
                op = self.add_XOR_component(
                    [round_keys[round_number - 1][0], round_keys[round_number - 3][0]],
                    [s3_x_input_positions, round_keys[round_number - 3][1]],
                    self.word_size,
                ).id
                op = self.add_XOR_component(
                    [op, op], [s1_x_input_positions, list(range(self.word_size))], self.word_size
                ).id
            else:
                op = self.add_XOR_component(
                    [round_keys[round_number - 1][0], round_keys[round_number - 1][0]],
                    [s4_x_input_positions, s3_x_input_positions],
                    self.word_size,
                ).id

            xor_id = self.add_XOR_component(
                [round_constant, op, round_keys[constant_index][0]],
                [list(range(self.word_size))] * 2 + [round_keys[constant_index][1]],
                self.word_size,
            ).id

            self.add_round_key_output_component([xor_id], [list(range(self.word_size))], self.word_size).id
            round_keys[round_number] = xor_id, list(range(self.word_size))
