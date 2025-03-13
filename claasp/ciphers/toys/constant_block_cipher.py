
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

KEY_ID = "id"
KEY_POS = "bit_positions"
PARAMETERS_CONFIGURATION_LIST = [{'block_bit_size': 3, 'number_of_rounds': 3}]


class ConstantBlockCipher(Cipher):
    """
    Create an instance of ConstantBlockCipher class which will always output the constant value of last round number.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `3`); cipher input and output block bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `3`); number of rounds of the cipher

    EXAMPLES::

        sage: from claasp.ciphers.toys.constant_block_cipher import ConstantBlockCipher
        sage: constant = ConstantBlockCipher(block_bit_size=3, number_of_rounds=3)
        sage: constant.number_of_rounds
        3

        sage: constant.component_from(0, 0).id
        'constant_0_0'

        sage: constant.print_as_python_dictionary()
        cipher = {
        'cipher_id': 'constant_o3_r3',
        'cipher_type': 'block_cipher',
        'cipher_inputs': [],
        'cipher_inputs_bit_size': [],
        'cipher_output_bit_size': 3,
        'cipher_number_of_rounds': 3,
        'cipher_rounds' : [
          # round 0
          [
          {
            # round = 0 - round component = 0
            'id': 'constant_0_0',
            'type': 'constant',
            'input_bit_size': 0,
            'input_id_link': [''],
            'input_bit_positions': [[]],
            'output_bit_size': 3,
            'description': ['0b000'],
          },
          {
            # round = 0 - round component = 1
            'id': 'intermediate_output_0_1',
            'type': 'intermediate_output',
            'input_bit_size': 3,
            'input_id_link': ['constant_0_0'],
            'input_bit_positions': [[0, 1, 2]],
            'output_bit_size': 3,
            'description': ['round_output'],
          },
          ],
          # round 1
          [
          {
            # round = 1 - round component = 0
            'id': 'constant_1_0',
            'type': 'constant',
            'input_bit_size': 0,
            'input_id_link': [''],
            'input_bit_positions': [[]],
            'output_bit_size': 3,
            'description': ['0b001'],
          },
          {
            # round = 1 - round component = 1
            'id': 'intermediate_output_1_1',
            'type': 'intermediate_output',
            'input_bit_size': 3,
            'input_id_link': ['constant_1_0'],
            'input_bit_positions': [[0, 1, 2]],
            'output_bit_size': 3,
            'description': ['round_output'],
          },
          ],
          # round 2
          [
          {
            # round = 2 - round component = 0
            'id': 'constant_2_0',
            'type': 'constant',
            'input_bit_size': 0,
            'input_id_link': [''],
            'input_bit_positions': [[]],
            'output_bit_size': 3,
            'description': ['0b010'],
          },
          {
            # round = 2 - round component = 1
            'id': 'cipher_output_2_1',
            'type': 'cipher_output',
            'input_bit_size': 3,
            'input_id_link': ['constant_2_0'],
            'input_bit_positions': [[0, 1, 2]],
            'output_bit_size': 3,
            'description': ['cipher_output'],
          },
          ],
          ],
        'cipher_reference_code': None,
        }
    """

    def __init__(self, block_bit_size=3, number_of_rounds=3):
        super().__init__(family_name="constant",
                         cipher_type="block_cipher",
                         cipher_inputs=[],
                         cipher_inputs_bit_size=[],
                         cipher_output_bit_size=block_bit_size)

        self.create_rounds(block_bit_size, number_of_rounds)

    def create_rounds(self, block_bit_size, number_of_rounds):
        for round_number in range(number_of_rounds):
            self.add_round()
            self.add_constant_component(block_bit_size, round_number)
            state = ComponentState([self.get_current_component_id()], [list(range(block_bit_size))])
            if round_number == number_of_rounds - 1:
                self.add_cipher_output_component(state.id, state.input_bit_positions, block_bit_size)
            else:
                self.add_round_output_component(state.id, state.input_bit_positions, block_bit_size)
