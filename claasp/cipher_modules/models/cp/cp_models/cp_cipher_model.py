
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


from claasp.cipher_modules.models.cp.cp_model import CpModel, solve_satisfy
from claasp.name_mappings import (CIPHER_OUTPUT, INTERMEDIATE_OUTPUT, MIX_COLUMN, LINEAR_LAYER, WORD_OPERATION,
                                  CONSTANT, SBOX)


class CpCipherModel(CpModel):

    def __init__(self, cipher):
        super().__init__(cipher)

    def build_cipher_model(self, fixed_variables=[], second=False):
        """
        Build the cipher model.

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing name, bit_size, value
          (as integer) for the variables that need to be fixed to a certain value:

          {

              'component_id': 'plaintext',

              'constraint_type': 'equal'/'not_equal'

              'bit_positions': [0, 1, 2, 3],

              'binary_value': '[0, 0, 0, 0]'

          }

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_cipher_model import CpCipherModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = CpCipherModel(speck)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(64), integer_to_bit_list(0, 64, 'little'))]
            sage: fixed_variables.append(set_fixed_variables('plaintext', 'equal', range(32), integer_to_bit_list(0, 32, 'little')))
            sage: cp.build_cipher_model(fixed_variables)
        """
        self.initialise_model()
        self._model_prefix.extend(self.input_constraints())
        self.sbox_mant = []
        variables = []
        self._variables_list = []
        constraints = self.fix_variables_value_constraints(fixed_variables)
        component_types = [CIPHER_OUTPUT, CONSTANT, INTERMEDIATE_OUTPUT, LINEAR_LAYER, MIX_COLUMN, SBOX, WORD_OPERATION]
        operation_types = ['AND', 'MODADD', 'MODSUB', 'NOT', 'OR', 'ROTATE', 'SHIFT', 'SHIFT_BY_VARIABLE_AMOUNT', 'XOR']
        self._model_constraints = constraints

        for component in self._cipher.get_all_components():
            operation = component.description[0]
            if component.type not in component_types or (
                    WORD_OPERATION == component.type and operation not in operation_types):
                print(f'{component.id} not yet implemented')
            else:
                if component.type != SBOX:
                    variables, constraints = component.cp_constraints()
                else:
                    variables, constraints = component.cp_constraints(self.sbox_mant)

            self._model_constraints.extend(constraints)
            self._variables_list.extend(variables)
        
        self._model_constraints.extend(self.final_constraints())
        
        if not second:
            self._model_constraints = self._model_prefix + self._variables_list + self._model_constraints

    def evaluate_model(self, fixed_values=[], solver_name='Chuffed'):
        self.build_cipher_model(fixed_variables = fixed_values)
        
        self.solve('evaluate_cipher', solver_name)
        

    def final_constraints(self):
        """
        Return a CP constraints list for the cipher outputs and solving indications for single or second step model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_models.cp_cipher_model import CpCipherModel
            sage: speck = SpeckBlockCipher()
            sage: cp = CpCipherModel(speck)
            sage: cp.final_constraints()[:-1]
            ['solve satisfy;']
        """
        cipher_inputs = self._cipher.inputs
        cp_constraints = [solve_satisfy]
        new_constraint = 'output['
        for element in cipher_inputs:
            new_constraint = f'{new_constraint}\"{element} = \"++ show({element}) ++ \"\\n\" ++'
        for component_id in self._cipher.get_all_components_ids():
            new_constraint = new_constraint + f'\"{component_id} = \"++ ' \
                                              f'show({component_id})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
        new_constraint = new_constraint[:-2] + '];'
        cp_constraints.append(new_constraint)

        return cp_constraints
        
    def input_constraints(self):
        """
        Return a list of CP constraints for the inputs of the cipher.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_models.cp_cipher_model import CpCipherModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = CpCipherModel(speck)
            sage: cp.input_constraints()
            ['array[0..31] of var 0..1: plaintext;',
              ...
             'array[0..31] of var 0..1: cipher_output_3_12;']
        """
        self.sbox_mant = []
        cp_declarations = [f'array[0..{bit_size - 1}] of var 0..1: {input_};'
                           for input_, bit_size in zip(self._cipher.inputs, self._cipher.inputs_bit_size)]
        for component in self._cipher.get_all_components():
            if CONSTANT not in component.type:
                output_id_link = component.id
                output_size = int(component.output_bit_size)
                cp_declarations.append(f'array[0..{output_size - 1}] of var 0..1: {output_id_link};')

        return cp_declarations
