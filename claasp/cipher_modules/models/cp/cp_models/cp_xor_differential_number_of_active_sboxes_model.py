
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


from copy import deepcopy

from claasp.input import Input
from claasp.component import Component
from claasp.cipher_modules.models.cp.cp_model import CpModel, solve_satisfy
from claasp.name_mappings import (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, SBOX, MIX_COLUMN, WORD_OPERATION)


def build_xor_truncated_table(numadd):
    """
    Return a model that generates the list of possible input/output couples for the given xor component.

    INPUT:

    - ``numadd``-- **integer**; the number of addenda

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
        sage: from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_number_of_active_sboxes_model import (
        ....: build_xor_truncated_table)
        sage: aes = AESBlockCipher()
        sage: build_xor_truncated_table(3)
        'array[0..4, 1..3] of int: xor_truncated_table_3 = array2d(0..4, 1..3, [0,0,0,0,1,1,1,0,1,1,1,0,1,1,1]);'
    """
    size = 2 ** numadd
    binary_list = (f'{i:0{numadd}b}' for i in range(size))
    table_items = [','.join(i) for i in binary_list if i.count('1') != 1]
    table = ','.join(table_items)
    xor_table = f'array[0..{size - numadd - 1}, 1..{numadd}] of int: ' \
                f'xor_truncated_table_{numadd} = array2d(0..{size - numadd - 1}, 1..{numadd}, ' \
                f'[{table}]);'

    return xor_table


class CpXorDifferentialNumberOfActiveSboxesModel(CpModel):

    def __init__(self, cipher):
        self._first_step = []
        self._first_step_find_all_solutions = []
        super().__init__(cipher)

    def add_additional_xor_constraints(self, nmax, repetition):
        """
        Add additional xor constraints in the first step model for reducing the number of inconsistent solutions.

        INPUT:

        - ``nmax`` -- **integer**; the minimum number of addends for which the new xor component is NOT added
        - ``repetition`` -- **integer**; the number of times the procedure for creating new xor components will
          be repeated

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_number_of_active_sboxes_model import (
            ....: CpXorDifferentialNumberOfActiveSboxesModel)
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: cp = CpXorDifferentialNumberOfActiveSboxesModel(aes)
            sage: fixed_variables = [set_fixed_variables('key', 'not_equal', range(128),
            ....: integer_to_bit_list(0, 128, 'little'))]
            sage: cp.build_xor_differential_trail_first_step_model(-1, fixed_variables)
            sage: cp.add_additional_xor_constraints(5,1)
            sage: len(cp.list_of_xor_components)
            188
        """
        n = 0
        for _ in range(repetition):
            temp_list_of_xor_components = deepcopy(self.list_of_xor_components)
            for i in range(n, len(self.list_of_xor_components)):
                component = self.list_of_xor_components[i]
                for j in range(i):
                    self.create_xor_component(component, self.list_of_xor_components[j], nmax)
            n = len(temp_list_of_xor_components)
            if self.list_of_xor_components == temp_list_of_xor_components:
                break

    def build_xor_differential_trail_first_step_model(self, weight=-1, fixed_variables=[], nmax=2, repetition=1, possible_sboxes=0):
        """
        Build the CP Model for the second step of the search of XOR differential trail of an SPN cipher.

        INPUT:

        - ``weight`` -- **integer** (default: `1`); a specific weight. If set to non-negative integer, fixes the XOR
          trail weight
        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in standard
          format components are NOT added when considering additional xor constraints
        - ``nmax`` -- **integer** (default: `2`); the minimum number of addends for which new xor
        - ``repetition`` -- **integer** (default: `1`); the number of times the procedure for creating new xor
          components will be repeated

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_number_of_active_sboxes_model import (
            ....: CpXorDifferentialNumberOfActiveSboxesModel)
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: cp = CpXorDifferentialNumberOfActiveSboxesModel(aes)
            sage: fixed_variables = [set_fixed_variables('key', 'not_equal', range(128),
            ....: integer_to_bit_list(0, 128, 'little'))]
            sage: cp.build_xor_differential_trail_first_step_model(-1, fixed_variables)
        """
        self.initialise_model()
        variables = []
        self.list_of_xor_all_inputs = []
        self.list_of_xor_components = []
        self.mix_column_mant = []
        self.sbox_mant = []
        self.input_sbox = []
        self._variables_list = []
        self.c = 0
        self.table_of_solutions_length = 0
        constraints = self.fix_variables_value_constraints(fixed_variables, 'first_step')
        self._first_step = constraints
        self._variables_list.extend(self.input_xor_differential_first_step_constraints(possible_sboxes))

        for component in self._cipher.get_all_components():
            component_types = [CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, SBOX, MIX_COLUMN, WORD_OPERATION]
            operation = component.description[0]
            operation_types = ['ROTATE', 'SHIFT', 'XOR', 'NOT']
            if component.type not in component_types or \
                    (component.type == WORD_OPERATION and operation not in operation_types):
                print(f'{component.id} not yet implemented')
            elif component.type == WORD_OPERATION and operation == 'XOR':
                variables, constraints = component.cp_transform_xor_components_for_first_step(self)
            else:
                variables, constraints = component.cp_xor_differential_propagation_first_step_constraints(self)
            self._variables_list.extend(variables)
            self._first_step.extend(constraints)

        self.add_additional_xor_constraints(nmax, repetition)
        for i, component in enumerate(self.list_of_xor_components):
            variables, constraints = self.xor_xor_differential_first_step_constraints(component)
            self._variables_list.extend(variables)
            self._first_step.append(constraints)
        self._first_step.extend(self.final_xor_differential_first_step_constraints(weight))
        self._first_step = \
            self._model_prefix + self._variables_list + self._first_step

    def create_xor_component(self, component1, component2, nmax):
        """
        Create a new xor component which is the sum of the two components in input.

        INPUT:

        - ``component1`` -- **object**; the first xor component from the Cipher
        - ``component2`` -- **object**; the second xor component from the Cipher
        - ``nmax`` -- **integer**; the minimum number of addends for which the new xor component is NOT added

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_number_of_active_sboxes_model import (
            ....: CpXorDifferentialNumberOfActiveSboxesModel)
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: cp = CpXorDifferentialNumberOfActiveSboxesModel(aes)
            sage: old_xor_components = deepcopy(cp.list_of_xor_components)
            sage: xor_component1 = aes.component_from(0, 32)
            sage: xor_component2 = aes.component_from(0, 31)
            sage: cp.create_xor_component(xor_component1, xor_component2, 25)
            sage: old_xor_components == cp.list_of_xor_components
            False
        """
        if component1 == component2:
            return

        all_inputs = self.get_xor_all_inputs(component1, component2)
        new_numb_of_inp = len(all_inputs)
        not_add = 0
        if self.list_of_xor_all_inputs:
            for set_of_xor_inputs in self.list_of_xor_all_inputs:
                if set(all_inputs) == set(set_of_xor_inputs):
                    not_add = 1
                    break
        if new_numb_of_inp < nmax and all_inputs != [] and not_add != 1:
            input_id_link, input_bit_positions = self.get_new_xor_input_links_and_positions(all_inputs, new_numb_of_inp)
            self.list_of_xor_all_inputs.append(all_inputs)
            input_len = 0
            for input_bit in input_bit_positions:
                input_len += len(input_bit)
            component_input = Input(input_len, input_id_link, input_bit_positions)
            xor_component = Component("", "word_operation", component_input, input_len, ['XOR', new_numb_of_inp])
            xor_components_dictionaries = [component.as_python_dictionary()
                                           for component in self.list_of_xor_components]
            if xor_component.as_python_dictionary() not in xor_components_dictionaries:
                self.list_of_xor_components.append(xor_component)

    def final_xor_differential_first_step_constraints(self, weight=-1):
        r"""
        Return a list of CP constraints for the outputs of the cipher and solving indications for the first step model.

        INPUT:

        - ``weight`` -- **integer** (default: `-1`); a specific weight. If set to non-negative integer, fixes the XOR
          trail weight

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_number_of_active_sboxes_model import (
            ....: CpXorDifferentialNumberOfActiveSboxesModel)
            sage: aes = AESBlockCipher()
            sage: cp = CpXorDifferentialNumberOfActiveSboxesModel(aes)
            sage: cp.final_xor_differential_first_step_constraints()
            ['constraint number_of_active_sBoxes = ;',
             'int: table_of_solutions_length = 0;',
             'solve minimize number_of_active_sBoxes;',
             'output[show(number_of_active_sBoxes) ++ "\\n" ++ " table_of_solution_length = "++ show(table_of_solutions_length)];']
        """
        inputs = '+'.join([f'{input_[0]}' for input_ in self.input_sbox])
        cp_constraints = [f'constraint number_of_active_sBoxes = {inputs};',
                          f'int: table_of_solutions_length = {self.table_of_solutions_length};']
        if weight == -1:
            cp_constraints.append('solve minimize number_of_active_sBoxes;')
        else:
            cp_constraints.append(solve_satisfy)
        new_constraint = 'output[show(number_of_active_sBoxes) ++ \"\\n\" ++ \" ' \
                         'table_of_solution_length = \"++ show(table_of_solutions_length)' \
                         + ''.join([f' ++ \"\\n\" ++ \" {input_[0]} = \"++ show({input_[0]})'
                                    for input_ in self.input_sbox]) + '];'
        cp_constraints.append(new_constraint)

        return cp_constraints

    def get_new_xor_input_links_and_positions(self, all_inputs, new_numb_of_inp):
        input_id_link = []
        input_bit_positions = [[] for _ in range(new_numb_of_inp)]
        input_index = 0
        for i in range(new_numb_of_inp):
            divide = all_inputs[i].partition('[')
            new_input_name = divide[0]
            new_input_bit_positions = divide[2][:-1]
            if new_input_name not in input_id_link:
                input_id_link.append(new_input_name)
                input_bit_positions[input_index] += [int(new_input_bit_positions) * self.word_size + j
                                                     for j in range(self.word_size)]
                input_index = input_index + 1
            else:
                for j, present_input in enumerate(input_id_link):
                    if present_input == new_input_name:
                        input_bit_positions[j] += [int(new_input_bit_positions) * self.word_size + word_size
                                                   for word_size in range(self.word_size)]
        input_bit_positions = [x for x in input_bit_positions if x != []]

        return input_id_link, input_bit_positions

    def get_xor_all_inputs(self, component1, component2):
        input_id_links_1 = component1.input_id_links
        input_bit_positions_1 = component1.input_bit_positions
        input_id_links_2 = component2.input_id_links
        input_bit_positions_2 = component2.input_bit_positions
        old_all_inputs = []
        for id_link, bit_positions in zip(input_id_links_1, input_bit_positions_1):
            old_all_inputs.extend([f'{id_link}[{bit_positions[j * self.word_size] // self.word_size}]'
                                   for j in range(len(bit_positions) // self.word_size)])
        for id_link, bit_positions in zip(input_id_links_2, input_bit_positions_2):
            old_all_inputs.extend([f'{id_link}[{bit_positions[j * self.word_size] // self.word_size}]'
                                   for j in range(len(bit_positions) // self.word_size)])
        all_inputs = []
        for old_input in old_all_inputs:
            if old_input not in all_inputs:
                all_inputs.append(old_input)
            else:
                all_inputs.remove(old_input)

        return all_inputs

    def input_xor_differential_first_step_constraints(self, possible_sboxes):
        """
        Return a list of CP constraints for the inputs of the cipher for the first step model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_number_of_active_sboxes_model import (
            ....: CpXorDifferentialNumberOfActiveSboxesModel)
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher()
            sage: cp = CpXorDifferentialNumberOfActiveSboxesModel(aes)
            sage: cp.input_xor_differential_first_step_constraints()
            ['var 1..200: number_of_active_sBoxes;',
             'array[0..15] of var 0..1: key;',
             'array[0..15] of var 0..1: plaintext;']
        """
        if possible_sboxes != 0:
            number_of_active_sBoxes_declaration = 'var {'
            for sboxes_n in possible_sboxes:
                number_of_active_sBoxes_declaration += str(sboxes_n)
                number_of_active_sBoxes_declaration += ', '
            number_of_active_sBoxes_declaration = number_of_active_sBoxes_declaration[:-2] + '}: number_of_active_sBoxes;'
            cp_declarations = [number_of_active_sBoxes_declaration]
        else:
            active_sboxes_count = 0
            for component in self._cipher.get_all_components():
                if SBOX in component.type:
                    input_bit_positions = component.input_bit_positions
                    active_sboxes_count += len(input_bit_positions)
            cp_declarations = [f'var 1..{active_sboxes_count}: number_of_active_sBoxes;']
        cp_declarations.extend([f'array[0..{bit_size // self.word_size - 1}] of var 0..1: {input_};'
                                for input_, bit_size in zip(self._cipher.inputs, self._cipher.inputs_bit_size)])

        return cp_declarations

    def xor_xor_differential_first_step_constraints(self, component):
        """
        Return a list of CP declarations and a list of CP constraints for xor component for the first step model.

        INPUT:

        - ``component`` -- **object**; the xor component in Cipher of an SPN cipher

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_number_of_active_sboxes_model import (
            ....: CpXorDifferentialNumberOfActiveSboxesModel)
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: cp = CpXorDifferentialNumberOfActiveSboxesModel(aes)
            sage: xor_component = aes.component_from(0, 32)
            sage: cp.xor_xor_differential_first_step_constraints(xor_component)
            (['array[0..1, 1..2] of int: xor_truncated_table_2 = array2d(0..1, 1..2, [0,0,1,1]);'],
              'constraint table([xor_0_31[0]]++[key[4]], xor_truncated_table_2);')
        """
        input_id_links = component.input_id_links
        input_bit_positions = component.input_bit_positions
        description = component.description
        numadd = description[1]
        all_inputs = []
        for id_link, bit_positions in zip(input_id_links, input_bit_positions):
            all_inputs.extend([f'{id_link}[{bit_positions[j * self.word_size] // self.word_size}]'
                               for j in range(len(bit_positions) // self.word_size)])
        input_len = len(all_inputs) // numadd
        cp_constraints = 'constraint table(' \
                         + '++'.join([f'[{all_inputs[input_len * j]}]' for j in range(numadd)]) \
                         + f', xor_truncated_table_{numadd});'
        xor_table = build_xor_truncated_table(numadd)
        cp_declarations = []
        if xor_table not in self._variables_list:
            cp_declarations = [xor_table]

        return cp_declarations, cp_constraints
