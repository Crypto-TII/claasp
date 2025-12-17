
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


from claasp.DTOs.component_state import ComponentState
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation, ROUND_MODE_HALF, ROUND_MODE_SINGLE
from claasp.utils.utils import bytes_positions_to_little_endian_for_multiple_of_32
from claasp.name_mappings import STREAM_CIPHER, INPUT_PLAINTEXT, INPUT_NONCE, INPUT_BLOCK_COUNT, INPUT_KEY

INPUT_CONSTANTS = "chacha_constants"
PARAMETERS_CONFIGURATION_LIST = [{'block_bit_size': 512, 'key_bit_size': 256, 'number_of_rounds': 20}]


def init_state_plaintext(input_state_of_components):
    nonce_lst = list(range(96))
    key_lst = list(range(256))
    nonce_bit_positions = bytes_positions_to_little_endian_for_multiple_of_32(nonce_lst, 3)
    key_bit_positions = bytes_positions_to_little_endian_for_multiple_of_32(key_lst, 8)

    for i in range(0, 4):
        for j in range(0, 4):
            if i == 3 and j == 0:
                component_state = ComponentState(INPUT_BLOCK_COUNT, [list(range(32))])
            elif i == 3 and j > 0:
                component_state = ComponentState(INPUT_NONCE, [nonce_bit_positions[j - 1]])
            elif i == 0 and j >= 0:
                component_state = ComponentState(INPUT_CONSTANTS,
                                                 [list(range(j * 32 + i * 128, j * 32 + 32 + i * 128))])
            else:
                ii = i - 1
                component_state = ComponentState(INPUT_KEY, [key_bit_positions[ii * 4 + j]])
            input_state_of_components[i][j] = component_state


class ChachaStreamCipher(ChachaPermutation):
    """
    Construct an instance of the ChachaStreamCipher class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

        - ``block_bit_size`` -- **integer** (default: `512`); cipher input and output block bit size of the cipher
        - ``key_bit_size`` -- **integer** (default: `256`); cipher key bit size of the cipher
        - ``number_of_rounds`` -- **integer** (default: `20`); number of rounds of the cipher
        - ``block_count`` -- **integer** (default: `1`)
        - ``chacha_constants`` -- **integer** (default: `0x617078653320646e79622d326b206574`)
        - ``round_mode`` -- **string** (default: `"single"`); matches ``round_mode`` in :class:`ChachaPermutation`

    EXAMPLES::

        sage: from claasp.ciphers.stream_ciphers.chacha_stream_cipher import ChachaStreamCipher
        sage: sp = ChachaStreamCipher(number_of_rounds=1)
        sage: sp.number_of_rounds
        1
    """

    def __init__(self, block_bit_size=512, key_bit_size=256, number_of_rounds=20,
                 block_count=1, chacha_constants=0x617078653320646e79622d326b206574, round_mode=ROUND_MODE_SINGLE):
        self.WORD_SIZE = 32

        input_state_of_components = [
            [None, None, None, None],
            [None, None, None, None],
            [None, None, None, None],
            [None, None, None, None],
        ]
        state_of_final_components = [
            [None, None, None, None],
            [None, None, None, None],
            [None, None, None, None],
            [None, None, None, None],
        ]

        init_state_plaintext(input_state_of_components)

        super().__init__(number_of_rounds=number_of_rounds,
                         cipher_type=STREAM_CIPHER,
                         cipher_family="chacha_stream_cipher",
                         inputs=[INPUT_PLAINTEXT, INPUT_KEY, INPUT_NONCE],
                 cipher_inputs_bit_size=[block_bit_size, key_bit_size, self.WORD_SIZE * 3],
                 round_mode=round_mode)
        state_of_components_permutation = self.state_of_components

        self.add_constant_component(self.WORD_SIZE * 4, chacha_constants)
        constants_id = self.get_current_component_id()
        self.add_constant_component(self.WORD_SIZE, block_count)
        block_count_id = self.get_current_component_id()
        for i in range(4):
            for j in range(4):
                if input_state_of_components[i][j].id == "chacha_constants":
                    input_state_of_components[i][j] = \
                        ComponentState(constants_id, input_state_of_components[i][j].input_bit_positions)
                if input_state_of_components[i][j].id == "input_block_count":
                    input_state_of_components[i][j] = \
                        ComponentState(block_count_id, input_state_of_components[i][j].input_bit_positions)

        lst_ids = []
        for i in range(4):
            for j in range(4):
                state_of_final_components[i][j] = self.add_MODADD_component(
                    [input_state_of_components[i][j].id] + [state_of_components_permutation[i][j].id],
                    input_state_of_components[i][j].input_bit_positions + [list(range(32))],
                    self.WORD_SIZE
                )
                lst_ids.append(state_of_final_components[i][j].id)

        last_round = self.number_of_rounds - 1

        for component_number in range(self.get_number_of_components_in_round(last_round)):
            component = self.component_from(last_round, component_number)
            if component.type == "cipher_output":
                component.set_input_id_links(lst_ids)

        self.sort_cipher()
