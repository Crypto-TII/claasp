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
from claasp.name_mappings import (
    CIPHER_OUTPUT,
    INTERMEDIATE_OUTPUT,
    LINEAR_LAYER,
    MIX_COLUMN,
    SBOX,
    WORD_OPERATION,
)


def check_size(position_list, size):
    if size > len(position_list):
        return False

    for j in range(0, len(position_list), size):
        if position_list[j] % size == 0 and (position_list[j + size - 1] + 1) % size == 0:
            # check consecutive positions
            i = position_list[j]
            for position in position_list[j + 1 : j + size]:
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

    c_matrix = matrix(GF(2), input_bit_size, output_bit_size)  # , input_bit_size)
    for i in range(c_matrix.nrows()):
        result = linear_layer_function(BitArray(list(p_matrix[i])), *list_specific_inputs)
        c_matrix[i] = vector(GF(2), result)

    return p_matrix.transpose().solve_left(c_matrix.transpose())


def free_input(code):
    code.append("\tdelete_bitstring(input);\n")


class Component:
    """
    Construct a generic component.

    INPUT:

    - ``component_id`` -- **string**; unique component identifier (for example,
        ``'xor_0_0'``). Required and should not be ``None``.
    - ``component_type`` -- **string**; component category (for example,
        ``'word_operation'``). Required and should not be ``None``.
    - ``component_input`` -- **Input**; instance of :class:`claasp.input.Input`.
        Required and should not be ``None``.
        ``component_input.id_links`` must be a list.
        ``component_input.bit_positions`` must be a list of lists and should not be empty.
        ``component_input.id_links`` and ``component_input.bit_positions`` must have the same length.
    - ``output_bit_size`` -- **integer**; output width in bits. ``0`` is allowed
        when the component semantics allows it.
    - ``description`` -- **object**; component-specific metadata (typically a
        list). Required and should not be ``None``.

    EXAMPLES::

            sage: from claasp.component import Component
            sage: from claasp.input import Input
            sage: component_input = Input(4, ['input'], [[0, 1, 2, 3]])
            sage: component = Component('xor_0_0', 'word_operation', component_input, 4, ['XOR', 2])
            sage: print(component.id)
            xor_0_0
            sage: print(component.type)
            word_operation
            sage: print(component.output_bit_size)
            4
            sage: print(component.description)
            ['XOR', 2]
    """
    def __init__(
        self,
        component_id,
        component_type,
        component_input,
        output_bit_size,
        description,
    ):
        if not isinstance(component_input.id_links, list):
            raise TypeError(f"{component_id} id_links must be a list.")

        if not isinstance(component_input.bit_positions, list):
            raise TypeError(f"{component_id} bit_positions must be a list.")

        for positions in component_input.bit_positions:
            if not isinstance(positions, list):
                raise TypeError(f"Each element of {component_id} bit_positions must be a list.")

        if len(component_input.id_links) != len(component_input.bit_positions):
            raise ValueError(f"{component_id} id_links and bit_positions must have the same length.")

        length = sum(len(positions) for positions in component_input.bit_positions)
        if component_input.bit_size != length:
            raise ValueError(f"The length of {component_id} bit_positions is not equal to input_bit_size")

        self._id = component_id
        self._type = component_type
        self._input = deepcopy(component_input)
        self._output_bit_size = output_bit_size
        self._description = description
        self._suffixes = ("_i", "_o")

    def _raise_method_not_implemented_error(self, method_name):
        raise NotImplementedError(
            f"{self.__class__.__name__} (id='{self.id}', type='{self.type}') "
            f"does not implement method '{method_name}'."
        )

    def algebraic_polynomials(self, *args, **kwargs):
        self._raise_method_not_implemented_error("algebraic_polynomials")

    def cms_constraints(self, *args, **kwargs):
        self._raise_method_not_implemented_error("cms_constraints")

    def cms_xor_differential_propagation_constraints(self, *args, **kwargs):
        return self.cms_constraints(*args, **kwargs)

    def cms_xor_linear_mask_propagation_constraints(self, *args, **kwargs):
        return self.cms_constraints(*args, **kwargs)

    def cp_constraints(self, *args, **kwargs):
        self._raise_method_not_implemented_error("cp_constraints")

    def cp_continuous_differential_propagation_constraints(self, *args, **kwargs):
        self._raise_method_not_implemented_error("cp_continuous_differential_propagation_constraints")

    def cp_deterministic_truncated_xor_differential_constraints(self):
        self._raise_method_not_implemented_error("cp_deterministic_truncated_xor_differential_constraints")

    def cp_deterministic_truncated_xor_differential_trail_constraints(self):
        return self.cp_deterministic_truncated_xor_differential_constraints()

    def cp_semi_deterministic_truncated_xor_differential_constraints(self):
        return self.cp_deterministic_truncated_xor_differential_constraints()

    def cp_wordwise_deterministic_truncated_xor_differential_constraints(self, *args, **kwargs):
        self._raise_method_not_implemented_error("cp_wordwise_deterministic_truncated_xor_differential_constraints")

    def cp_xor_differential_propagation_constraints(self, *args, **kwargs):
        return self.cp_constraints(*args, **kwargs)

    def cp_xor_linear_mask_propagation_constraints(self, *args, **kwargs):
        return self.cp_constraints(*args, **kwargs)

    def get_bit_based_vectorized_python_code(self, *args, **kwargs):
        self._raise_method_not_implemented_error("get_bit_based_vectorized_python_code")

    def get_byte_based_vectorized_python_code(self, *args, **kwargs):
        self._raise_method_not_implemented_error("get_byte_based_vectorized_python_code")

    def milp_constraints(self, *args, **kwargs):
        self._raise_method_not_implemented_error("milp_constraints")

    def milp_bitwise_deterministic_truncated_xor_differential_constraints(self, *args, **kwargs):
        self._raise_method_not_implemented_error("milp_bitwise_deterministic_truncated_xor_differential_constraints")

    def milp_wordwise_deterministic_truncated_xor_differential_constraints(self, *args, **kwargs):
        self._raise_method_not_implemented_error("milp_wordwise_deterministic_truncated_xor_differential_constraints")

    def milp_xor_differential_propagation_constraints(self, *args, **kwargs):
        return self.milp_constraints(*args, **kwargs)

    def milp_xor_linear_mask_propagation_constraints(self, *args, **kwargs):
        return self.milp_constraints(*args, **kwargs)

    def minizinc_constraints(self, *args, **kwargs):
        self._raise_method_not_implemented_error("minizinc_constraints")

    def minizinc_deterministic_truncated_xor_differential_trail_constraints(self, *args, **kwargs):
        return self.minizinc_constraints(*args, **kwargs)

    def minizinc_xor_differential_propagation_constraints(self, *args, **kwargs):
        return self.minizinc_constraints(*args, **kwargs)

    def sat_constraints(self, *args, **kwargs):
        self._raise_method_not_implemented_error("sat_constraints")

    def sat_bitwise_deterministic_truncated_xor_differential_constraints(self):
        self._raise_method_not_implemented_error("sat_bitwise_deterministic_truncated_xor_differential_constraints")

    def sat_semi_deterministic_truncated_xor_differential_constraints(self):
        return self.sat_bitwise_deterministic_truncated_xor_differential_constraints()

    def sat_xor_differential_propagation_constraints(self, *args, **kwargs):
        return self.sat_constraints(*args, **kwargs)

    def sat_xor_linear_mask_propagation_constraints(self, *args, **kwargs):
        return self.sat_constraints(*args, **kwargs)

    def smt_constraints(self, *args, **kwargs):
        self._raise_method_not_implemented_error("smt_constraints")

    def smt_xor_differential_propagation_constraints(self, *args, **kwargs):
        return self.smt_constraints(*args, **kwargs)

    def smt_xor_linear_mask_propagation_constraints(self, *args, **kwargs):
        return self.smt_constraints(*args, **kwargs)

    def _create_minizinc_1d_array_from_list(self, mzn_list):
        mzn_list_size = len(mzn_list)
        lst_temp = f"[{','.join(mzn_list)}]"

        return f"array1d(0..{mzn_list_size}-1, {lst_temp})"

    def minizinc_define_var(self, input_postfix, output_postfix, data_type):
        """
        Define Minizinc variables from component.

        INPUT:

        - ``input_postfix`` -- **strings**
        - ``output_postfix`` -- **strings**
        - ``data_type`` -- **strings**

        EXAMPLES::

            sage: from claasp.component import Component
            sage: from claasp.input import Input
            sage: component_input = Input(4, ['input'], [[0, 1, 2, 3]])
            sage: component = Component('my_component_id', 'my_component_type', component_input, 4, [])
            sage: component.minizinc_define_var("in", "out", "data_type")
            ['var data_type: my_component_id_in0;', 'var data_type: my_component_id_in1;', 'var data_type: my_component_id_in2;', 'var data_type: my_component_id_in3;', 'var data_type: my_component_id_out0;', 'var data_type: my_component_id_out1;', 'var data_type: my_component_id_out2;', 'var data_type: my_component_id_out3;']
        """
        var_definition_names = []
        component_id = self.id
        input_size = self.input_bit_size
        output_size = self.output_bit_size
        var_names_temp = []
        if self.type != "constant":
            var_names_temp += [f"{component_id}_{input_postfix}{i}" for i in range(input_size)]
        var_names_temp += [f"{component_id}_{output_postfix}{i}" for i in range(output_size)]
        for i in range(len(var_names_temp)):
            var_definition_names.append(f"var {data_type}: {var_names_temp[i]};")

        return var_definition_names

    def _generate_component_input_ids(self):
        """
        Generate component-local input identifiers.

        EXAMPLES::

            sage: from claasp.component import Component
            sage: from claasp.input import Input
            sage: component_input = Input(4, ['input'], [[0, 1, 2, 3]])
            sage: component = Component('my_component_id', 'my_component_type', component_input, 4, [])
            sage: component._generate_component_input_ids()
            (4, ['my_component_id_0_i', 'my_component_id_1_i', 'my_component_id_2_i', 'my_component_id_3_i'])
        """
        input_id_link = self.id
        in_suffix = constants.INPUT_BIT_ID_SUFFIX
        input_bit_size = self.input_bit_size
        input_bit_ids = [f"{input_id_link}_{i}{in_suffix}" for i in range(input_bit_size)]

        return input_bit_size, input_bit_ids

    def _generate_input_ids(self, suffix=""):
        """
        Generate linked input identifiers.

        EXAMPLES::

            sage: from claasp.component import Component
            sage: from claasp.input import Input
            sage: component_input = Input(4, ['input'], [[0, 1, 2, 3]])
            sage: component = Component('my_component_id', 'my_component_type', component_input, 4, [])
            sage: component._generate_input_ids()
            ['input_0', 'input_1', 'input_2', 'input_3']
            sage: component._generate_input_ids(suffix="my_suffix")
            ['input_0my_suffix', 'input_1my_suffix', 'input_2my_suffix', 'input_3my_suffix']
        """
        input_id_link = self.input_id_links
        input_bit_positions = self.input_bit_positions
        input_bit_ids = []
        for link, positions in zip(input_id_link, input_bit_positions):
            input_bit_ids.extend([f"{link}_{j}{suffix}" for j in positions])

        return input_bit_ids

    def _generate_input_double_ids(self):
        """
        Generate paired linked input identifiers.

        EXAMPLES::

            sage: from claasp.component import Component
            sage: from claasp.input import Input
            sage: component_input = Input(4, ['input'], [[0, 1, 2, 3]])
            sage: component = Component('my_component_id', 'my_component_type', component_input, 4, [])
            sage: component._generate_input_double_ids()
            (['input_0_0', 'input_1_0', 'input_2_0', 'input_3_0'], ['input_0_1', 'input_1_1', 'input_2_1', 'input_3_1'])
        """
        in_ids_0 = self._generate_input_ids(suffix="_0")
        in_ids_1 = self._generate_input_ids(suffix="_1")

        return in_ids_0, in_ids_1

    def _generate_output_ids(self, suffix=""):
        """
        Generate output identifiers.

        EXAMPLES::

            sage: from claasp.component import Component
            sage: from claasp.input import Input
            sage: component_input = Input(4, ['input'], [[0, 1, 2, 3]])
            sage: component = Component('my_component_id', 'my_component_type', component_input, 4, [])
            sage: component._generate_output_ids()
            (4, ['my_component_id_0', 'my_component_id_1', 'my_component_id_2', 'my_component_id_3'])
        """
        output_id_link = self.id
        output_bit_size = self.output_bit_size
        output_bit_ids = [f"{output_id_link}_{j}{suffix}" for j in range(output_bit_size)]

        return output_bit_size, output_bit_ids

    def _generate_output_double_ids(self):
        """
        Generate paired output identifiers.

        EXAMPLES::

            sage: from claasp.component import Component
            sage: from claasp.input import Input
            sage: component_input = Input(4, ['input'], [[0, 1, 2, 3]])
            sage: component = Component('my_component_id', 'my_component_type', component_input, 4, [])
            sage: component._generate_output_double_ids()
            (4, ['my_component_id_0_0', 'my_component_id_1_0', 'my_component_id_2_0', 'my_component_id_3_0'], ['my_component_id_0_1', 'my_component_id_1_1', 'my_component_id_2_1', 'my_component_id_3_1'])
        """
        out_len, out_ids_0 = self._generate_output_ids(suffix="_0")
        _, out_ids_1 = self._generate_output_ids(suffix="_1")

        return out_len, out_ids_0, out_ids_1

    def _get_independent_input_output_variables(self):
        """
        Return a list of 2 lists containing the name of each input/output bit.

        The bit in position 0 of those lists corresponds to the MSB.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.component import Component
            sage: from claasp.input import Input
            sage: component_input = Input(4, ['input'], [[0, 1, 2, 3]])
            sage: component = Component('my_component_id', 'my_component_type', component_input, 4, [])
            sage: l = component._get_independent_input_output_variables()
            sage: l
            (['my_component_id_0_i', 'my_component_id_1_i', 'my_component_id_2_i', 'my_component_id_3_i'], ['my_component_id_0_o', 'my_component_id_1_o', 'my_component_id_2_o', 'my_component_id_3_o'])
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

            sage: from claasp.component import Component
            sage: from claasp.input import Input
            sage: component_input = Input(4, ['input'], [[0, 1, 2, 3]])
            sage: component = Component('my_component_id', 'my_component_type', component_input, 4, [])
            sage: l = component._get_input_output_variables()
            sage: l[0]
            ['input_0', 'input_1', 'input_2', 'input_3']
            sage: l[1]
            ['my_component_id_0', 'my_component_id_1', 'my_component_id_2', 'my_component_id_3']
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

            sage: from claasp.component import Component
            sage: from claasp.input import Input
            sage: component_input = Input(4, ['input'], [[0, 1, 2, 3]])
            sage: component = Component('my_component_id', 'my_component_type', component_input, 4, [])
            sage: input_class_id, output_class_id = component._get_input_output_variables_tuples()
            sage: input_class_id
            [('input_0_class_bit_0', 'input_0_class_bit_1'), ('input_1_class_bit_0', 'input_1_class_bit_1'), ('input_2_class_bit_0', 'input_2_class_bit_1'), ('input_3_class_bit_0', 'input_3_class_bit_1')]
            sage: output_class_id
            [('my_component_id_0_class_bit_0', 'my_component_id_0_class_bit_1'), ('my_component_id_1_class_bit_0', 'my_component_id_1_class_bit_1'), ('my_component_id_2_class_bit_0', 'my_component_id_2_class_bit_1'), ('my_component_id_3_class_bit_0', 'my_component_id_3_class_bit_1')]



        """

        tuple_size = 2
        output_ids_tuple = [
            tuple(f"{self.id}_{i}_class_bit_{j}" for j in range(tuple_size)) for i in range(self.output_bit_size)
        ]
        input_ids_tuple = []
        for index, link in enumerate(self.input_id_links):
            input_ids_tuple.extend(
                [
                    tuple(f"{link}_{pos}_class_bit_{j}" for j in range(tuple_size))
                    for pos in self.input_bit_positions[index]
                ]
            )

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

            sage: from claasp.component import Component
            sage: from claasp.input import Input
            sage: from types import SimpleNamespace
            sage: component_input = Input(4, ['input'], [[0, 1, 2, 3]])
            sage: component = Component('my_component_id', 'my_component_type', component_input, 4, [])
            sage: milp = SimpleNamespace(word_size=8)
            sage: input_class_id, output_class_id = component._get_wordwise_input_output_linked_class(milp)
            sage: input_class_id
            ['input_word_0_class']
            sage: output_class_id
            []
        """

        output_class_ids = [f"{self.id}_word_{i}_class" for i in range(self.output_bit_size // model.word_size)]
        input_class_ids = []

        for index, link in enumerate(self.input_id_links):
            for pos in self.input_bit_positions[index][:: model.word_size]:
                input_class_ids.append(f"{link}_word_{pos // model.word_size}_class")

        return input_class_ids, output_class_ids

    def _get_wordwise_input_output_linked_class_tuples(self, model):
        """

        Returns a tuple that encodes the truncated pattern of each word in the milp wordwise truncated model

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.component import Component
            sage: from claasp.input import Input
            sage: from types import SimpleNamespace
            sage: component_input = Input(4, ['input'], [[0, 1, 2, 3]])
            sage: component = Component('my_component_id', 'my_component_type', component_input, 4, [])
            sage: milp = SimpleNamespace(word_size=8)
            sage: input_id_tuples, output_id_tuples = component._get_wordwise_input_output_linked_class_tuples(milp)
            sage: input_id_tuples
            [('input_word_0_class_bit_0', 'input_word_0_class_bit_1')]
            sage: output_id_tuples
            []

        """
        tuple_size = 2
        input_class, output_class = self._get_wordwise_input_output_linked_class(model)

        output_class_tuples = [tuple(f"{id}_bit_{i}" for i in range(tuple_size)) for id in output_class]
        input_class_tuples = [tuple(f"{id}_bit_{i}" for i in range(tuple_size)) for id in input_class]

        return input_class_tuples, output_class_tuples

    def _get_wordwise_input_output_full_tuples(self, model):
        """

        Returns a tuple that contains all binary variables linked to a word in the milp wordwise truncated model:
            - the tuple of binary variables that encodes the truncated pattern of each word
            - the list of n binary variables that represent the value each n-bit word

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.component import Component
            sage: from claasp.input import Input
            sage: from types import SimpleNamespace
            sage: component_input = Input(4, ['input'], [[0, 1, 2, 3]])
            sage: component = Component('my_component_id', 'my_component_type', component_input, 4, [])
            sage: milp = SimpleNamespace(word_size=8)
            sage: input_id_tuples, output_id_tuples = component._get_wordwise_input_output_full_tuples(milp)
            sage: input_id_tuples
            []
            sage: output_id_tuples
            []


        """
        word_size = model.word_size

        input_ids, output_ids = self._get_input_output_variables()
        input_class_id_tuples, output_class_id_tuples = self._get_wordwise_input_output_linked_class_tuples(model)

        input_full_tuple = [
            tuple(list(input_class_id_tuples[i]) + input_ids[i * word_size : (i + 1) * word_size])
            for i in range(len(input_ids) // word_size)
        ]
        output_full_tuple = [
            tuple(list(output_class_id_tuples[i]) + output_ids[i * word_size : (i + 1) * word_size])
            for i in range(len(output_ids) // word_size)
        ]

        return input_full_tuple, output_full_tuple

    def as_python_dictionary(self):
        """
        Return the component as a Python dictionary.

        EXAMPLES::

            sage: from claasp.component import Component
            sage: from claasp.input import Input
            sage: component_input = Input(4, ['input'], [[0, 1, 2, 3]])
            sage: component = Component('my_component_id', 'my_component_type', component_input, 4, [])
            sage: d = component.as_python_dictionary()
            sage: d['id'], d['type'], d['input_bit_size'], d['output_bit_size']
            ('my_component_id', 'my_component_type', 4, 4)
            sage: d['input_id_link'], d['input_bit_positions'], d['description']
            (['input'], [[0, 1, 2, 3]], [])
        """
        return {
            "id": self._id,
            "type": self._type,
            "input_bit_size": self._input.bit_size,
            "input_id_link": deepcopy(self._input.id_links),
            "input_bit_positions": deepcopy(self._input.bit_positions),
            "output_bit_size": self._output_bit_size,
            "description": self._description,
        }

    def is_id_equal_to(self, component_id):
        """
        Check whether the component id equals ``component_id``.

        EXAMPLES::

            sage: from claasp.component import Component
            sage: from claasp.input import Input
            sage: component_input = Input(4, ['input'], [[0, 1, 2, 3]])
            sage: component = Component('my_component_id', 'my_component_type', component_input, 4, [])
            sage: component.is_id_equal_to('my_id')
            False
            sage: component.is_id_equal_to('my_component_id')
            True
        """
        return self._id == component_id

    def is_power_of_2_word_based(self, dto):
        available_word_sizes = (64, 32, 16, 8)
        fixed = dto.fixed
        word_size = dto.word_size

        if self._type in (SBOX, MIX_COLUMN, LINEAR_LAYER):
            return PowerOf2WordBasedDTO(False, fixed)

        # Check output size
        fixed, word_size = self.check_output_size(available_word_sizes, fixed, word_size)
        if not word_size:
            return PowerOf2WordBasedDTO(False, fixed)

        # Check input positions and size
        if self._type != "constant":
            valid_sizes = [positions for positions in self.input_bit_positions if not check_size(positions, word_size)]
            if valid_sizes or self.input_bit_size % word_size != 0:
                return PowerOf2WordBasedDTO(False, fixed)

        return PowerOf2WordBasedDTO(word_size, fixed)

    def check_output_size(self, available_word_sizes, fixed, word_size):
        if self._type in (INTERMEDIATE_OUTPUT, CIPHER_OUTPUT):
            if word_size is None:
                return None, fixed
        else:
            if word_size is None and self._output_bit_size in available_word_sizes:
                word_size = self._output_bit_size
                fixed = True
            elif self._output_bit_size != word_size:
                return None, fixed

        return fixed, word_size

    def is_forbidden(self, forbidden_types, forbidden_descriptions):
        if self._type in forbidden_types:
            return True
        if self._type == WORD_OPERATION and self._description[0] in forbidden_descriptions:
            return True

        return False

    def print(self):
        print(f"    id = {self._id}")
        print(f"    type = {self._type}")
        print(f"    input_bit_size = {self.input_bit_size}")
        print(f"    input_id_link = {self.input_id_links}")
        print(f"    input_bit_positions = {self.input_bit_positions}")
        print(f"    output_bit_size = {self._output_bit_size}")
        print(f"    description = {self._description}")

    def print_values(self, code):
        code.append(f'\tprintf("{self.id}_input = ");')
        code.append("\tprint_bitstring(input, 16);")
        code.append(f'\tprintf("{self.id}_output = ");')
        code.append(f"\tprint_bitstring({self.id}, 16);\n")

    def print_word_values(self, code):
        code.append(f'\tprintf("{self.id}_input = ");')
        code.append("\tprint_wordstring(input, 16);")
        code.append(f'\tprintf("{self.id}_output = ");')
        code.append(f"\tprint_wordstring({self.id}, 16);\n")

    def select_bits(self, code):
        code.append(
            (f"\tinput_id = (BitString*[]) {{{', '.join(self.input_id_links)}}};\n\tinput_positions = (uint16_t*[]) {{")
        )

        for position_list in self.input_bit_positions:
            code.append((f"\t\t(uint16_t[]) {{{len(position_list)}, {', '.join(map(str, position_list))}}},"))

        code.append("\t};")
        n = len(self.input_id_links)
        code.append(f"\tinput = select_bits({n}, input_id, input_positions, {self.output_bit_size});")

    def select_words(self, code, word_size, input=True):
        word_list = []
        i = 0

        for position_list in self.input_bit_positions:
            for j in range(0, len(position_list), word_size):
                word_list.append(f"{self.input_id_links[i]} -> list[{position_list[j] // word_size}]")

            i += 1

        if input:
            code.append(f"\tinput -> list = (Word[]) {{{', '.join(word_list)}}};")
            code.append(f"\tinput -> string_size = {len(word_list)};")
        else:
            code.append(f"\tWordString* {self.id} = create_wordstring({len(word_list)}, false);")
            code.append(
                f"\tmemcpy({self.id} -> list, (Word[]) {{{', '.join(word_list)}}}, {len(word_list)} * sizeof(Word));"
            )

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, description):
        self._description = description

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, id_string):
        self._id = id_string

    @property
    def input_bit_size(self):
        return self._input.bit_size

    @property
    def input_id_links(self):
        return self._input.id_links

    @input_id_links.setter
    def input_id_links(self, input_id_links):
        self._input.id_links = input_id_links

    @property
    def input_bit_positions(self):
        return self._input.bit_positions

    @input_bit_positions.setter
    def input_bit_positions(self, bit_positions):
        self._input.bit_positions = bit_positions

    @property
    def output_bit_size(self):
        return self._output_bit_size

    @property
    def suffixes(self):
        return self._suffixes

    @property
    def type(self):
        return self._type
