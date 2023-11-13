
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


from claasp.cipher_modules.models.sat.sat_model import SatModel
from claasp.name_mappings import (CIPHER_OUTPUT, CONSTANT, INTERMEDIATE_OUTPUT, LINEAR_LAYER, MIX_COLUMN,
                                  WORD_OPERATION)


class SatDeterministicTruncatedXorDifferentialModel(SatModel):
    def __init__(self, cipher, window_size_weight_pr_vars=-1,
                 counter='sequential', compact=False):
        super().__init__(cipher, window_size_weight_pr_vars, counter, compact)

    def build_deterministic_truncated_xor_differential_trail_model(self, fixed_variables=[]):
        """
        Build the model for the search of deterministic truncated XOR DIFFERENTIAL trails.

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); the variables to be fixed in standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_deterministic_truncated_xor_differential_model import SatDeterministicTruncatedXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=22)
            sage: sat = SatDeterministicTruncatedXorDifferentialModel(speck)
            sage: sat.build_deterministic_truncated_xor_differential_trail_model()
            ...
        """
        variables = []
        constraints = self.fix_variables_value_constraints(fixed_variables)
        self._variables_list = []
        self._model_constraints = constraints
        component_types = (CIPHER_OUTPUT, CONSTANT, INTERMEDIATE_OUTPUT, LINEAR_LAYER, MIX_COLUMN, WORD_OPERATION)
        operation_types = ('AND', 'MODADD', 'NOT', 'OR', 'ROTATE', 'SHIFT', 'XOR')

        for component in self._cipher.get_all_components():
            operation = component.description[0]
            if component.type in component_types and (component.type != WORD_OPERATION or operation in operation_types):
                variables, constraints = component.sat_deterministic_truncated_xor_differential_trail_constraints()
            else:
                print(f'{component.id} not yet implemented')

            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

    def fix_variables_value_constraints(self, fixed_variables=[]):
        """
        Return constraints for fixed variables

        Return lists of variables and clauses for fixing variables in bitwise
        deterministic truncated XOR differential model.

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); variables in default format

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_deterministic_truncated_xor_differential_model import SatDeterministicTruncatedXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: sat = SatDeterministicTruncatedXorDifferentialModel(speck)
            sage: fixed_variables = [{
            ....:    'component_id': 'plaintext',
            ....:    'constraint_type': 'equal',
            ....:    'bit_positions': [0, 1, 2, 3],
            ....:    'bit_values': [1, 0, 1, 1]
            ....: }, {
            ....:    'component_id': 'ciphertext',
            ....:    'constraint_type': 'not_equal',
            ....:    'bit_positions': [0, 1, 2, 3],
            ....:    'bit_values': [2, 1, 1, 0]
            ....: }]
            sage: sat.fix_variables_value_constraints(fixed_variables)
            ['-plaintext_0_0',
             'plaintext_0_1',
             '-plaintext_1_0',
             '-plaintext_1_1',
             '-plaintext_2_0',
             'plaintext_2_1',
             '-plaintext_3_0',
             'plaintext_3_1',
             '-ciphertext_0_0 ciphertext_1_0 -ciphertext_1_1 ciphertext_2_0 -ciphertext_2_1 ciphertext_3_0 ciphertext_3_1']
        """
        constraints = []
        for variable in fixed_variables:
            component_id = variable['component_id']
            is_equal = (variable['constraint_type'] == 'equal')
            bit_positions = variable['bit_positions']
            bit_values = variable['bit_values']
            if is_equal:
                for position, value in zip(bit_positions, bit_values):
                    if value == 0:
                        constraints.extend((f'-{component_id}_{position}_0', f'-{component_id}_{position}_1'))
                    elif value == 1:
                        constraints.extend((f'-{component_id}_{position}_0', f'{component_id}_{position}_1'))
                    elif value == 2:
                        constraints.append(f'{component_id}_{position}_0')
            else:
                clause = []
                for position, value in zip(bit_positions, bit_values):
                    if value == 0:
                        clause.extend((f'{component_id}_{position}_0', f'{component_id}_{position}_1'))
                    elif value == 1:
                        clause.extend((f'{component_id}_{position}_0', f'-{component_id}_{position}_1'))
                    elif value == 2:
                        clause.append(f'-{component_id}_{position}_0')
                constraints.append(' '.join(clause))

        return constraints
