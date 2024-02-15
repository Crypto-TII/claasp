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

import time

from claasp.cipher_modules.models.sat.sat_model import SatModel
from claasp.cipher_modules.models.utils import set_component_solution
from claasp.name_mappings import (CIPHER_OUTPUT, CONSTANT, DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL,
                                  INTERMEDIATE_OUTPUT, INPUT_PLAINTEXT, LINEAR_LAYER, MIX_COLUMN, SBOX, WORD_OPERATION)


class SatWordwiseDeterministicTruncatedXorDifferentialModel(SatModel):

    def __init__(self, cipher):
        super().__init__(cipher)
        self._word_size = 4
        if self._cipher.is_spn():
            for component in self._cipher.get_all_components():
                if SBOX in component.type:
                    self._word_size = int(component.output_bit_size)
                    break

    def build_wordwise_deterministic_truncated_xor_differential_trail_model(self, fixed_words=[]):
        """
        Build the model for the search of wordwise deterministic truncated XOR differential trails.

        INPUT:

        - ``fixed_words`` -- *list of dict*, the word variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_wordwise_deterministic_truncated_xor_differential_model import SatWordwiseDeterministicTruncatedXorDifferentialModel
            sage: sat = SatWordwiseDeterministicTruncatedXorDifferentialModel(aes)
            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(16),
                                                  bit_values=[0, 1, 0, 3] + [0] * 12)
            sage: sat.build_wordwise_deterministic_truncated_xor_differential_trail_model(fixed_words=[plaintext])
            ...
        """
        variables = []
        constraints = self.fix_variables_value_constraints(fixed_words)
        self._variables_list = []
        self._model_constraints = constraints
        component_types = (CIPHER_OUTPUT, CONSTANT, INTERMEDIATE_OUTPUT, LINEAR_LAYER, MIX_COLUMN, SBOX)
        operation_types = ('XOR',)
        self._model_constraints = constraints

        for component in self._cipher.get_all_components():
            operation = component.description[0]
            if component.type in component_types and (component.type != WORD_OPERATION or operation in operation_types):
                variables, constraints = component.sat_wordwise_deterministic_truncated_xor_differential_constraints(self)
            else:
                print(f'{component.id} not yet implemented')

            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)
