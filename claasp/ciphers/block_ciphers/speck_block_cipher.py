
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
from claasp.DTOs.component_state import ComponentState
from claasp.utils.utils import get_number_of_rounds_from
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY

PARAMETERS_CONFIGURATION_LIST = [
    {'block_bit_size': 32, 'key_bit_size': 64, 'number_of_rounds': 22},
    {'block_bit_size': 48, 'key_bit_size': 72, 'number_of_rounds': 22},
    {'block_bit_size': 48, 'key_bit_size': 96, 'number_of_rounds': 23},
    {'block_bit_size': 64, 'key_bit_size': 96, 'number_of_rounds': 26},
    {'block_bit_size': 64, 'key_bit_size': 128, 'number_of_rounds': 27},
    {'block_bit_size': 96, 'key_bit_size': 96, 'number_of_rounds': 28},
    {'block_bit_size': 96, 'key_bit_size': 144, 'number_of_rounds': 29},
    {'block_bit_size': 128, 'key_bit_size': 128, 'number_of_rounds': 32},
    {'block_bit_size': 128, 'key_bit_size': 192, 'number_of_rounds': 33},
    {'block_bit_size': 128, 'key_bit_size': 256, 'number_of_rounds': 34}
]


class SpeckBlockCipher(Cipher):
    """
    Construct an instance of the SpeckBlockCipher class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `32`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `64`); cipher key bit size of the cipher
    - ``rotation_alpha`` -- **integer** (default: `None`)
    - ``rotation_beta`` -- **integer** (default: `None`)
    - ``number_of_rounds`` -- **integer** (default: `0`); number of rounds of the cipher. The cipher uses the
      corresponding amount given the other parameters (if available) when number_of_rounds is 0

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: speck = SpeckBlockCipher()
        sage: speck.number_of_rounds
        22

        sage: speck.component_from(0, 0).id
        'rot_0_0'
    """

    def __init__(self, block_bit_size=32, key_bit_size=64, rotation_alpha=None, rotation_beta=None, number_of_rounds=0):
        self.WORD_SIZE = int(block_bit_size / 2)
        if self.WORD_SIZE == 16:
            self.ROT_ALPHA = 7 if rotation_alpha is None else rotation_alpha
            self.ROT_BETA = 2 if rotation_beta is None else rotation_beta
        else:
            self.ROT_ALPHA = 8 if rotation_alpha is None else rotation_alpha
            self.ROT_BETA = 3 if rotation_beta is None else rotation_beta

        super().__init__(family_name="speck",
                         cipher_type="block_cipher",
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                         cipher_inputs_bit_size=[block_bit_size, key_bit_size],
                         cipher_output_bit_size=block_bit_size)

        key_schedule, left_schedule = self.key_initialization(key_bit_size)
        p1, p2 = self.round_initialization()

        # round function
        n = get_number_of_rounds_from(block_bit_size, key_bit_size, number_of_rounds, PARAMETERS_CONFIGURATION_LIST)

        for round_number in range(n):
            self.add_round()

            # key schedule
            if round_number != 0:
                # constant r-1
                self.add_constant_component(self.WORD_SIZE, round_number - 1)
                self.get_current_component().set_tags(["key_schedule"])
                const_r = ComponentState([self.get_current_component_id()], [list(range(self.WORD_SIZE))])
                key_left, key_right = self.round_function(key_left, key_right, const_r, "key_schedule")
                left_schedule.append(key_left)
                key_schedule.append(key_right)

            # round parameter
            key_left = left_schedule[round_number]
            key_right = key_schedule[round_number]

            # round encryption
            p1, p2 = self.round_function(p1, p2, key_right, "data_schedule")
            self.add_round_key_output_component(key_right.id, key_right.input_bit_positions, self.WORD_SIZE)
            self.get_current_component().set_tags(["key_schedule"])
            self.add_output_component(block_bit_size, n, p1, p2, round_number)
            self.get_current_component().set_tags(["data_schedule"])

    def add_output_component(self, block_bit_size, n, p1, p2, round_number):
        if round_number == n - 1:
            self.add_cipher_output_component(p1.id + p2.id,
                                             p1.input_bit_positions + p2.input_bit_positions,
                                             block_bit_size)
        else:
            self.add_round_output_component(p1.id + p2.id,
                                            p1.input_bit_positions + p2.input_bit_positions,
                                            block_bit_size)

    def key_initialization(self, key_bit_size):
        l_schedule = []
        key_schedule = []
        for i in range(0, key_bit_size - self.WORD_SIZE, self.WORD_SIZE):
            l_component = ComponentState([INPUT_KEY], [list(range(i, i + self.WORD_SIZE))])
            l_schedule.append(l_component)
        l_schedule.reverse()
        key_component = ComponentState([INPUT_KEY], [[(key_bit_size - j) for j in range(self.WORD_SIZE, 0, -1)]])
        key_schedule.append(key_component)

        return key_schedule, l_schedule

    def round_function(self, p1, p2, key, tag=None):
        def set_tag():
            if tag is not None:
                self.get_current_component().set_tags([tag])
        # p1 >>> alpha
        self.add_rotate_component(p1.id, p1.input_bit_positions, self.WORD_SIZE, self.ROT_ALPHA)
        set_tag()
        p1 = ComponentState([self.get_current_component_id()], [list(range(self.WORD_SIZE))])

        # p1 = modadd(p1, p2)
        self.add_MODADD_component(p1.id + p2.id, p1.input_bit_positions + p2.input_bit_positions, self.WORD_SIZE)
        set_tag()
        p1 = ComponentState([self.get_current_component_id()], [list(range(self.WORD_SIZE))])

        # p1 = p1 ^ round_key
        self.add_XOR_component(p1.id + key.id, p1.input_bit_positions + key.input_bit_positions, self.WORD_SIZE)
        set_tag()
        p1 = ComponentState([self.get_current_component_id()], [list(range(self.WORD_SIZE))])

        # p2 <<< beta
        self.add_rotate_component(p2.id, p2.input_bit_positions, self.WORD_SIZE, -self.ROT_BETA)
        set_tag()
        p2 = ComponentState([self.get_current_component_id()], [list(range(self.WORD_SIZE))])

        # p2 = p1 ^ p2
        self.add_XOR_component(p1.id + p2.id, p1.input_bit_positions + p2.input_bit_positions, self.WORD_SIZE)
        set_tag()
        p2 = ComponentState([self.get_current_component_id()], [list(range(self.WORD_SIZE))])

        return p1, p2

    def round_initialization(self):
        p1 = ComponentState([INPUT_PLAINTEXT], [list(range(self.WORD_SIZE))])
        p2 = ComponentState([INPUT_PLAINTEXT], [[(i + self.WORD_SIZE) for i in range(self.WORD_SIZE)]])

        return p1, p2
