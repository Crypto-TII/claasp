
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
from bitstring import BitArray

from sage.matrix.constructor import matrix
from sage.modules.free_module import VectorSpace
from sage.modules.free_module_element import vector
from sage.rings.finite_rings.finite_field_constructor import FiniteField as GF

from claasp.cipher_modules.models.sat.utils import constants
from claasp.DTOs.power_of_2_word_based_dto import PowerOf2WordBasedDTO


def check_size(position_list, size):
    if size > len(position_list):
        return False

    for j in range(0, len(position_list), size):
        if position_list[j] % size == 0 and (position_list[j + size - 1] + 1) % size == 0:
            # check consecutive positions
            i = position_list[j]
            for position in position_list[j + 1:j + size]:
                i += 1
                if i != position:
                    return False
        else:
            return False

    return True


def linear_layer_to_binary_matrix(linear_layer_function, input_bit_size, output_bit_size, list_specific_inputs):
    vector_space = VectorSpace(GF(2), input_bit_size)
    p_matrix = matrix(GF(2), input_bit_size, input_bit_size)

    while p_matrix.rank() != input_bit_size:
        for i in range(p_matrix.nrows()):
            p_matrix[i] = vector_space.random_element()

    c_matrix = matrix(GF(2), input_bit_size, output_bit_size)#, input_bit_size)
    for i in range(c_matrix.nrows()):
        result = linear_layer_function(BitArray(list(p_matrix[i])), *list_specific_inputs)
        c_matrix[i] = vector(GF(2), result)

    return p_matrix.transpose().solve_left(c_matrix.transpose())


def free_input(code):
    code.append('\tdelete_bitstring(input);\n')


class Component:
    def __init__(self, component_id, component_type, component_input, output_bit_size, description):
        if not isinstance(component_input.id_links, list):
            print("type of [input_id_link] should be a list")
            return

        if not isinstance(component_input.bit_positions, list):
            print("type of [input_bit_positions] should be a list")
            return

        if not isinstance(component_input.bit_positions[0], list):
            print("element of [input_bit_positions] should be a list")
            return

        if len(component_input.id_links) != len(component_input.bit_positions):
            print("[input_id_link] and [input_bit_positions] should have the same length")
            return

        length = 0
        for i in component_input.bit_positions:
            length += len(i)
        if component_input.bit_size != length:
            print("the length of [input_bit_positions] is not equal to input_bit_size")
            return

        self._id = component_id
        self._type = component_type
        self._input = deepcopy(component_input)
        self._output_bit_size = output_bit_size
        self._description = description
        self._suffixes = ['_i', '_o']

    def _create_minizinc_1d_array_from_list(self, mzn_list):
        mzn_list_size = len(mzn_list)
        lst_temp = f'[{",".join(mzn_list)}]'

        return f'array1d(0..{mzn_list_size}-1, {lst_temp})'

    def _define_var(self, input_postfix, output_postfix, data_type):
        """
        Define Minizinc variables from component.

        INPUT:

        - ``input_postfix`` -- **strings**
        - ``output_postfix`` -- **strings**
        - ``data_type`` -- **strings**
        """
        var_definition_names = []
        component_id = self.id
        input_size = self.input_bit_size
        output_size = self.output_bit_size
        var_names_temp = []
        if self.type != "constant":
            var_names_temp += [component_id + "_" + input_postfix + str(i) for i in range(input_size)]
        var_names_temp += [component_id + "_" + output_postfix + str(i) for i in range(output_size)]
        for i in range(len(var_names_temp)):
            var_definition_names.append(f'var {data_type}: {var_names_temp[i]};')

        return var_definition_names

    def _generate_component_input_ids(self):
        input_id_link = self.id
        in_suffix = constants.INPUT_BIT_ID_SUFFIX
        input_bit_size = self.input_bit_size
        input_bit_ids = [f'{input_id_link}_{i}{in_suffix}' for i in range(input_bit_size)]

        return input_bit_size, input_bit_ids

    def _generate_input_ids(self, suffix=''):
        input_id_link = self.input_id_links
        input_bit_positions = self.input_bit_positions
        input_bit_ids = []
        for link, positions in zip(input_id_link, input_bit_positions):
            input_bit_ids.extend([f'{link}_{j}{suffix}' for j in positions])

        return self.input_bit_size, input_bit_ids

    def _generate_input_double_ids(self):
        _, in_ids_0 = self._generate_input_ids(suffix='_0')
        _, in_ids_1 = self._generate_input_ids(suffix='_1')

        return in_ids_0, in_ids_1

    def _generate_output_ids(self, suffix=''):
        output_id_link = self.id
        output_bit_size = self.output_bit_size
        output_bit_ids = [f'{output_id_link}_{j}{suffix}' for j in range(output_bit_size)]

        return output_bit_size, output_bit_ids

    def _generate_output_double_ids(self):
        out_len, out_ids_0 = self._generate_output_ids(suffix='_0')
        _, out_ids_1 = self._generate_output_ids(suffix='_1')

        return out_len, out_ids_0, out_ids_1

    def _get_independent_input_output_variables(self):
        """
        Return a list of 2 lists containing the name of each input/output bit.

        The bit in position 0 of those lists corresponds to the MSB.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=2)
            sage: component = fancy.get_component_from_id("and_0_8")
            sage: l = component._get_independent_input_output_variables()
            sage: l[0]
            ['and_0_8_0_i',
             'and_0_8_1_i',
             ...
             'and_0_8_22_i',
             'and_0_8_23_i']
            sage: l[1]
            ['and_0_8_0_o',
             'and_0_8_1_o',
             ...
             'and_0_8_10_o',
             'and_0_8_11_o']
        """
        input_vars = [f"{self.id}_{i}_i" for i in range(self.input_bit_size)]
        output_vars = [f"{self.id}_{i}_o" for i in range(self.output_bit_size)]

        return input_vars, output_vars

    def _get_input_output_variables(self):
        """
        Return a list of 2 lists containing the name of each input/output bit.

        The bit in position 0 of those lists corresponds to the MSB.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=2)
            sage: component = fancy.get_component_from_id("and_0_8")
            sage: l = component._get_input_output_variables()
            sage: l[0]
            ['xor_0_7_0',
            'xor_0_7_1',
            'xor_0_7_2',
            ...
            'key_21',
            'key_22',
            'key_23']
            sage: l[1]
            ['and_0_8_0',
            'and_0_8_1',
            'and_0_8_2',
            'and_0_8_3',
            ...
            'and_0_8_8',
            'and_0_8_9',
            'and_0_8_10',
            'and_0_8_11']
        """

        output_vars = [f"{self.id}_{i}" for i in range(self.output_bit_size)]
        input_vars = []
        for index, link in enumerate(self.input_id_links):
            input_vars.extend([f"{link}_{pos}" for pos in self.input_bit_positions[index]])

        return input_vars, output_vars

    def _get_input_output_variables_tuples(self):
        """
        Returns a tuple that encodes the truncated pattern of each bit, for the milp bitwise truncated model:
            - (0, 0) means that the pattern is 0, i.e. the bit value equals 0
            - (0, 1) means that the pattern is 1, i.e. the bit value equals 1
            - (1, 0) means that the pattern is 2, i.e. the bit value is unknown

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(fancy)
            sage: milp.init_model_in_sage_milp_class()
            sage: component = fancy.component_from(0, 6)
            sage: input_class_id, output_class_id = component._get_input_output_variables_tuples()
            sage: input_class_id
            [('sbox_0_0_0_class_bit_0', 'sbox_0_0_0_class_bit_1'),
             ('sbox_0_0_1_class_bit_0', 'sbox_0_0_1_class_bit_1'),
             ...
             ('sbox_0_5_2_class_bit_0', 'sbox_0_5_2_class_bit_1'),
             ('sbox_0_5_3_class_bit_0', 'sbox_0_5_3_class_bit_1')]
            sage: output_class_id
            [('linear_layer_0_6_0_class_bit_0', 'linear_layer_0_6_0_class_bit_1'),
             ('linear_layer_0_6_1_class_bit_0', 'linear_layer_0_6_1_class_bit_1'),
            ...
             ('linear_layer_0_6_22_class_bit_0', 'linear_layer_0_6_22_class_bit_1'),
             ('linear_layer_0_6_23_class_bit_0', 'linear_layer_0_6_23_class_bit_1')]



        """

        tuple_size = 2
        output_ids_tuple = [tuple(f"{self.id}_{i}_class_bit_{j}" for j in range(tuple_size)) for i in range(self.output_bit_size)]
        input_ids_tuple = []
        for index, link in enumerate(self.input_id_links):
            input_ids_tuple.extend([tuple(f"{link}_{pos}_class_bit_{j}" for j in range(tuple_size)) for pos in self.input_bit_positions[index]])


        return input_ids_tuple, output_ids_tuple

    def _get_wordwise_input_output_linked_class(self, model):
        """
        Returns the integer variable associated to the truncated pattern of a word, for the milp wordwise truncated model:
            - 0 means that the word equals 0
            - 1 means that the word value is fixed
            - 2 means that the word can be any value except zero
            - 3 means that the word is unkown


        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: cipher = AESBlockCipher(number_of_rounds=3)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: component = cipher.get_component_from_id("rot_0_18")
            sage: input_class_id, output_class_id = component._get_wordwise_input_output_linked_class(milp)
            sage: input_class_id
            ['sbox_0_2_word_0_class',
             'sbox_0_6_word_0_class',
             'sbox_0_10_word_0_class',
             'sbox_0_14_word_0_class']
            sage: output_class_id
            ['rot_0_18_word_0_class',
             'rot_0_18_word_1_class',
             'rot_0_18_word_2_class',
             'rot_0_18_word_3_class']
        """

        output_class_ids = [self.id + '_word_' + str(i) + '_class' for i in
                        range(self.output_bit_size // model.word_size)]
        input_class_ids = []

        for index, link in enumerate(self.input_id_links):
            for pos in self.input_bit_positions[index][::model.word_size]:
                input_class_ids.append(link + '_word_' + str(pos // model.word_size) + '_class')

        return input_class_ids, output_class_ids

    def _get_wordwise_input_output_linked_class_tuples(self, model):
        """

        Returns a tuple that encodes the truncated pattern of each word in the milp wordwise truncated model

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: cipher = AESBlockCipher(number_of_rounds=3)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: component = cipher.get_component_from_id("rot_0_18")
            sage: input_id_tuples, output_id_tuples = component._get_wordwise_input_output_linked_class_tuples(milp)
            sage: input_id_tuples
            [('sbox_0_2_word_0_class_bit_0', 'sbox_0_2_word_0_class_bit_1'),
             ('sbox_0_6_word_0_class_bit_0', 'sbox_0_6_word_0_class_bit_1'),
             ('sbox_0_10_word_0_class_bit_0', 'sbox_0_10_word_0_class_bit_1'),
             ('sbox_0_14_word_0_class_bit_0', 'sbox_0_14_word_0_class_bit_1')]
            sage: output_id_tuples
            [('rot_0_18_word_0_class_bit_0', 'rot_0_18_word_0_class_bit_1'),
             ('rot_0_18_word_1_class_bit_0', 'rot_0_18_word_1_class_bit_1'),
             ('rot_0_18_word_2_class_bit_0', 'rot_0_18_word_2_class_bit_1'),
             ('rot_0_18_word_3_class_bit_0', 'rot_0_18_word_3_class_bit_1')]

        """
        tuple_size = 2
        input_class, output_class = self._get_wordwise_input_output_linked_class(model)

        output_class_tuples = [tuple(f"{id}_bit_{i}" for i in range(tuple_size)) for id in
                              output_class]
        input_class_tuples = [tuple(f"{id}_bit_{i}" for i in range(tuple_size)) for id in
                             input_class]

        return input_class_tuples, output_class_tuples


    def _get_wordwise_input_output_full_tuples(self, model):
        """

        Returns a tuple that contains all binary variables linked to a word in the milp wordwise truncated model:
            - the tuple of binary variables that encodes the truncated pattern of each word
            - the list of n binary variables that represent the value each n-bit word

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: cipher = AESBlockCipher(number_of_rounds=3)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: component = cipher.get_component_from_id("rot_0_18")
            sage: input_id_tuples, output_id_tuples = component._get_wordwise_input_output_full_tuples(milp)
            sage: input_id_tuples[0]
            ('sbox_0_2_word_0_class_bit_0',
             'sbox_0_2_word_0_class_bit_1',
             ...
             'sbox_0_2_6',
             'sbox_0_2_7')
            sage: output_id_tuples[0]
            ('rot_0_18_word_0_class_bit_0',
             'rot_0_18_word_0_class_bit_1',
             ...
             'rot_0_18_6',
             'rot_0_18_7')


        """
        word_size = model.word_size

        input_ids, output_ids = self._get_input_output_variables()
        input_class_id_tuples, output_class_id_tuples = self._get_wordwise_input_output_linked_class_tuples(model)

        input_full_tuple = [tuple(list(input_class_id_tuples[i]) + input_ids[i * word_size: (i + 1) * word_size]) for i in
                            range(len(input_ids) // word_size)]
        output_full_tuple = [tuple(list(output_class_id_tuples[i]) + output_ids[i * word_size: (i + 1) * word_size]) for i in
                             range(len(output_ids) // word_size)]

        return input_full_tuple, output_full_tuple
    
    ####################################### BOOMERANG #############################################
    def add_prefix(self, prefix='upper_'):
        self._id = prefix + self.id
        self._input._id_links = [prefix + i for i in self.input_id_links]
        
        # new_input = []
        # for input in self.input_id_links:
        #     new_input.append(prefix + input)
        # self._input_id_links = new_input

    def remove_prefix(self, prefix='upper_'):
        self._id = self.id[len(prefix):] if self.id.startswith(prefix) else self.id
        self._input._id_links = [i[len(prefix):] if i.startswith(prefix) else i for i in self.input_id_links]
    ###################################### BOOMERANG ##############################################
    
    def as_python_dictionary(self):
        return {
            'id': self._id,
            'type': self._type,
            'input_bit_size': self.input_bit_size,
            'input_id_link': self.input_id_links,
            'input_bit_positions': self.input_bit_positions,
            'output_bit_size': self._output_bit_size,
            'description': self._description
        }

    def get_graph_representation(self):
        return {
            "id": self._id,
            "type": self._type,
            "input_bit_size": self._input.bit_size,
            "input_id_link": deepcopy(self._input.id_links),
            "input_bit_positions": deepcopy(self._input.bit_positions),
            "output_bit_size": self._output_bit_size,
            "description": self._description
        }

    def is_id_equal_to(self, component_id):
        return self._id == component_id

    def is_power_of_2_word_based(self, dto):
        available_word_sizes = [64, 32, 16, 8]
        fixed = dto.fixed
        word_size = dto.word_size

        if self._type in ('sbox', 'mix_column', 'linear_layer'):
            return PowerOf2WordBasedDTO(False, fixed)

        # Check output size
        fixed, word_size = self.check_output_size(available_word_sizes, fixed, word_size)
        if not word_size:
            return PowerOf2WordBasedDTO(False, fixed)

        # Check input positions and size
        if self._type != 'constant':
            valid_sizes = [positions for positions in self.input_bit_positions if not check_size(positions, word_size)]
            if valid_sizes or self.input_bit_size % word_size != 0:
                return PowerOf2WordBasedDTO(False, fixed)

        return PowerOf2WordBasedDTO(word_size, fixed)

    def check_output_size(self, available_word_sizes, fixed, word_size):
        if self._type in ('concatenate', 'intermediate_output', 'cipher_output'):
            word_size = self.output_size_for_concatenate(available_word_sizes, fixed, word_size)
            if word_size is None:
                return None, fixed
        else:
            if word_size is None and self._output_bit_size in available_word_sizes:
                word_size = self._output_bit_size
                fixed = True
            elif self._output_bit_size != word_size:
                return None, fixed

        return fixed, word_size

    def output_size_for_concatenate(self, available_word_sizes, fixed, word_size):
        if word_size is None:
            word_sizes = [size for size in available_word_sizes if self._output_bit_size % size != 0]
            if word_sizes:
                word_size = word_sizes[0]
        else:
            word_sizes = [size for size in available_word_sizes[available_word_sizes.index(word_size):]
                          if self._output_bit_size % size != 0]
            if (fixed and self._output_bit_size % word_size != 0) or (not fixed and not word_sizes):
                word_size = None
            elif not fixed:
                word_size = word_sizes[0]

        return word_size

    def is_forbidden(self, forbidden_types, forbidden_descriptions):
        if self._type in forbidden_types:
            return True
        if self._type == "word_operation" and self._description[0] in forbidden_descriptions:
            return True

        return False

    def print(self):
        print(f"    id =", self._id)
        print(f"    type =", self._type)
        print(f"    input_bit_size =", self.input_bit_size)
        print(f"    input_id_link =", self.input_id_links)
        print(f"    input_bit_positions =", self.input_bit_positions)
        print(f"    output_bit_size =", self._output_bit_size)
        print(f"    description =", self._description)

    def print_as_python_dictionary(self):
        print("    'id': '" + self._id + "',")
        print("    'type': '" + self._type + "',")
        print(f"    'input_bit_size': {self.input_bit_size},")
        print(f"    'input_id_link': {self.input_id_links},")
        print(f"    'input_bit_positions': {self.input_bit_positions},")
        print(f"    'output_bit_size': {self._output_bit_size},")
        print(f"    'description': {self._description},")

    def set_description(self, description):
        self._description = description

    def set_input_id_links(self, input_id_links):
        self._input.set_input_id_links(input_id_links)

    def set_input_bit_positions(self, bit_positions):
        self._input.set_input_bit_positions(bit_positions)

    def print_values(self, code):
        code.append(f'\tprintf("{self.id}_input = ");')
        code.append('\tprint_bitstring(input, 16);')
        code.append(f'\tprintf("{self.id}_output = ");')
        code.append(f'\tprint_bitstring({self.id}, 16);\n')

    def print_word_values(self, code):
        code.append(f'\tprintf("{self.id}_input = ");')
        code.append('\tprint_wordstring(input, 16);')
        code.append(f'\tprintf("{self.id}_output = ");')
        code.append(f'\tprint_wordstring({self.id}, 16);\n')

    def select_bits(self, code):
        n = len(self.input_id_links)

        code.append((f'\tinput_id = (BitString*[]) {{{", ".join(self.input_id_links)}}};\n'
                     f'\tinput_positions = (uint16_t*[]) {{'))

        for position_list in self.input_bit_positions:
            code.append(
                (f'\t\t(uint16_t[]) {{{len(position_list)}, {", ".join([str(p) for p in position_list])}}},'))

        code.append('\t};')

        code.append(f'\tinput = select_bits({n}, input_id, input_positions, {self.output_bit_size});')

    def select_words(self, code, word_size, input=True):
        word_list = []
        i = 0

        for position_list in self.input_bit_positions:
            for j in range(0, len(position_list), word_size):
                word_list.append(f'{self.input_id_links[i]} -> list[{position_list[j] // word_size}]')

            i += 1

        if input:
            code.append(f'\tinput -> list = (Word[]) {{{", ".join(word_list)}}};')
            code.append(f'\tinput -> string_size = {len(word_list)};')
        else:
            code.append(f'\tWordString* {self.id} = create_wordstring({len(word_list)}, false);')
            code.append(
                f'\tmemcpy({self.id} -> '
                f'list, (Word[]) {{{", ".join(word_list)}}}, {len(word_list)} * sizeof(Word));')

    def set_id(self, id_string):
        self._id = id_string

    @property
    def description(self):
        return self._description

    @property
    def id(self):
        return self._id

    @property
    def input_bit_size(self):
        return self._input.bit_size

    @property
    def input_id_links(self):
        return self._input.id_links

    @property
    def input_bit_positions(self):
        return self._input.bit_positions

    @property
    def output_bit_size(self):
        return self._output_bit_size

    @property
    def suffixes(self):
        return self._suffixes

    @property
    def type(self):
        return self._type
