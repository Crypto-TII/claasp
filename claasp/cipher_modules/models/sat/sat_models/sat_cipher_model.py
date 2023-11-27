
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
from claasp.name_mappings import (CIPHER, WORD_OPERATION, CIPHER_OUTPUT, CONSTANT, INTERMEDIATE_OUTPUT, LINEAR_LAYER,
                                  MIX_COLUMN, SBOX)


class SatCipherModel(SatModel):
    def __init__(self, cipher,  window_size_weight_pr_vars=-1,
                 counter='sequential', compact=False):
        super().__init__(cipher, window_size_weight_pr_vars, counter, compact)

    def build_cipher_model(self, fixed_variables=[]):
        """
        Build the sat model.

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); the variables to be fixed in standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_cipher_model import SatCipherModel
            sage: speck = SpeckBlockCipher(number_of_rounds=22)
            sage: sat = SatCipherModel(speck)
            sage: sat.build_cipher_model()
        """
        variables = []
        constraints = self.fix_variables_value_constraints(fixed_variables)
        self._variables_list = []
        self._model_constraints = constraints
        component_types = [CIPHER_OUTPUT, CONSTANT, INTERMEDIATE_OUTPUT, LINEAR_LAYER, MIX_COLUMN, SBOX, WORD_OPERATION]
        operation_types = ['AND', 'MODADD', 'MODSUB', 'NOT', 'OR', 'ROTATE', 'SHIFT', 'SHIFT_BY_VARIABLE_AMOUNT', 'XOR']

        for component in self._cipher.get_all_components():
            operation = component.description[0]
            if component.type not in component_types or (
                    WORD_OPERATION == component.type and operation not in operation_types):
                print(f'{component.id} not yet implemented')
            else:
                variables, constraints = component.sat_constraints()

            self._model_constraints.extend(constraints)
            self._variables_list.extend(variables)

    def find_missing_bits(self, fixed_values=[], solver_name='cryptominisat'):
        """
        Return the solution representing a generic flow of the cipher from plaintext and key to ciphertext.

        INPUT:

        - ``fixed_values`` -- **list** (default: `[]`); can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `cryptominisat`); the name of the solver

        .. SEEALSO::

            :ref:`sat-solvers`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=22)
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_cipher_model import SatCipherModel
            sage: sat = SatCipherModel(speck)
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: ciphertext = set_fixed_variables(
            ....:         component_id=speck.get_all_components_ids()[-1],
            ....:         constraint_type='equal',
            ....:         bit_positions=range(32),
            ....:         bit_values=integer_to_bit_list(endianness='big', list_length=32, int_value=0xaffec7ed))
            sage: sat.find_missing_bits(fixed_values=[ciphertext]) # random
            {'cipher_id': 'speck_p32_k64_o32_r22',
             'model_type': 'cipher',
             'solver_name': 'cryptominisat',
             ...
              'intermediate_output_21_11': {'value': '1411'},
              'cipher_output_21_12': {'value': 'affec7ed'}},
             'total_weight': None,
             'status': 'SATISFIABLE',
             'building_time_seconds': 0.019376516342163086}
        """
        start_building_time = time.time()
        self.build_cipher_model(fixed_variables=fixed_values)
        end_building_time = time.time()
        solution = self.solve(CIPHER, solver_name=solver_name)
        solution['building_time_seconds'] = end_building_time - start_building_time

        return solution

    def _parse_solver_output(self, variable2value):
        out_suffix = ''
        components_solutions = self._get_cipher_inputs_components_solutions(out_suffix, variable2value)
        for component in self._cipher.get_all_components():
            hex_value = self._get_component_hex_value(component, out_suffix, variable2value)
            component_solution = set_component_solution(hex_value)
            components_solutions[component.id] = component_solution

        return components_solutions, None
