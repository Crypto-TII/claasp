
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


"""
SMT model of Cipher.

.. _smt-solvers:

SMT standard of Cipher
------------------------------------

The target of this class is to build, solve and retrieve the solution of an SMT
CNF representing some attacks on ciphers, e.g. the generic cipher inversion or
the search for XOR differential trails (for SAT CNFs see the correspondent
class :py:class:`Sat Model <cipher_modules.models.sat.sat_model>`). SMT-LIB is the chosen
standard.

An SMT solver is called by a subprocess, therefore note also that you will not
be able to solve the models in the SMT-LIB files until you have installed one
SMT solver at least. In methods, solvers are chosen by ``solver_name``
variable. Solvers and their corresponding values for ``solver_name`` variable
are:

    =========================================== =================
    SMT solver                                  value
    =========================================== =================
    `Z3 <https://github.com/Z3Prover/z3>`_      ``'z3'``
    `Yices-smt2 <https://yices.csl.sri.com/>`_  ``'yices-smt2'``
    `MathSAT <https://mathsat.fbk.eu/>`_        ``'mathsat'``
    =========================================== =================

The default choice is z3.
"""
import math
import re
import subprocess

from claasp.name_mappings import (SBOX, CIPHER, XOR_LINEAR)
from claasp.cipher_modules.models.smt.utils import constants, utils
from claasp.cipher_modules.models.utils import set_component_value_weight_sign, convert_solver_solution_to_dictionary


def get_component_value(component, suffix, output_bit_size, var_dict):
    value = 0
    for i in range(output_bit_size):
        value <<= 1
        if f'{component.id}_{i}{suffix}' in var_dict:
            value ^= var_dict[f'{component.id}_{i}{suffix}']
    return value


def mathsat_parser(output_to_parse):
    tmp_dict = {}
    time, memory = time_memory_extractor('time-seconds', 'memory-mb', output_to_parse)
    for line in output_to_parse[1:]:
        if line.strip().startswith('(define-fun'):
            solution = line.strip()[1:-1].split(' ')
            var_name = solution[1]
            var_value = '1' if solution[-1] == 'true' else '0'
            tmp_dict[var_name] = var_value

    return time, memory, tmp_dict


def yices_parser(output_to_parse):
    tmp_dict = {}
    time, memory = time_memory_extractor('total-run-time', 'mem-usage', output_to_parse)
    for line in output_to_parse[1:]:
        if line.startswith('(='):
            solution = line[1:-1].split(' ')
            var_name = solution[1]
            var_value = '1' if solution[-1] == 'true' else '0'
            tmp_dict[var_name] = var_value

    return time, memory, tmp_dict


def z3_parser(output_to_parse):
    tmp_dict = {}
    time, memory = time_memory_extractor('time', 'memory', output_to_parse)
    for index in range(0, len(output_to_parse), 2):
        if output_to_parse[index] == ')':
            break
        var_name = output_to_parse[index].split()[1]
        var_value = '1' if output_to_parse[index + 1].strip()[:-1] == 'true' else '0'
        tmp_dict[var_name] = var_value

    return time, memory, tmp_dict


def time_memory_extractor(time_keyword, memory_keyword, output_to_parse):
    time_lines = list(filter(lambda x: time_keyword in x, output_to_parse))
    memory_lines = list(filter(lambda x: memory_keyword in x, output_to_parse))
    time = float(time_lines[0].split()[1]) if ')' not in time_lines[0].split()[1] else \
        float(time_lines[0].split()[1][:-1])
    memory = float(memory_lines[0].split()[1])

    return time, memory


class SmtModel:
    def __init__(self, cipher, counter='sequential'):
        self._cipher = cipher
        self._variables_list = []
        self._model_constraints = []
        self._declarations = []
        self._sample_clauses = []
        self._sboxes_ddt_templates = {}
        self._sboxes_lat_templates = {}

        # set the counter to fix the weight
        if counter == 'sequential':
            self._counter = self._sequential_counter
        else:
            self._counter = self._parallel_counter

    def _declarations_builder(self):
        self._declarations = [f'(declare-const {variable} Bool)'
                              for variable in self._variables_list]

    def _generate_component_input_ids(self, component):
        input_id_link = component.id
        in_suffix = constants.INPUT_BIT_ID_SUFFIX
        input_bit_size = component.input_bit_size
        input_bit_ids = [f'{input_id_link}_{i}{in_suffix}' for i in range(input_bit_size)]

        return input_bit_size, input_bit_ids

    def _generate_input_ids(self, component, suffix=''):
        input_id_link = component.input_id_links
        input_bit_positions = component.input_bit_positions
        input_bit_ids = []
        for link, positions in zip(input_id_link, input_bit_positions):
            input_bit_ids.extend([f'{link}_{j}{suffix}' for j in positions])

        return component.input_bit_size, input_bit_ids

    def _generate_output_ids(self, component, suffix=''):
        output_id_link = component.id
        output_bit_size = component.output_bit_size
        output_bit_ids = [f'{output_id_link}_{j}{suffix}' for j in range(output_bit_size)]

        return output_bit_size, output_bit_ids

    def _parallel_counter(self, hw_list, weight):
        """
        No references.

        Extend the list of variables representing the weight until the cardinality is the lowest possible power of 2.

        Then, create constraints representing parallel addition of them.

        The ID of the word representing the result will be always <r_0_0>, i.e.
        the bits are <r_0_0_0>, <r_0_0_1>, <r_0_0_2>, ...
        """
        # adding dummy variables and building the first part (i.e. summing couple of bits)
        variables = []
        constraints = []
        num_of_orders = math.ceil(math.log2(len(hw_list)))
        dummy_list = [f'dummy_hw_{i}' for i in range(len(hw_list), 2 ** num_of_orders)]
        variables.extend(dummy_list)
        hw_list.extend(dummy_list)
        constraints.extend(utils.smt_assert(utils.smt_not(dummy)) for dummy in dummy_list)
        for i in range(0, 2 ** num_of_orders, 2):
            variables.append(f'r_{num_of_orders - 1}_{i // 2}_0')
            variables.append(f'r_{num_of_orders - 1}_{i // 2}_1')
            carry = utils.smt_and((f'{hw_list[i]}', f'{hw_list[i + 1]}'))
            equation = utils.smt_equivalent((f'r_{num_of_orders - 1}_{i // 2}_0', carry))
            constraints.append(utils.smt_assert(equation))
            result = utils.smt_xor((f'{hw_list[i]}', f'{hw_list[i + 1]}'))
            equation = utils.smt_equivalent((f'r_{num_of_orders - 1}_{i // 2}_1', result))
            constraints.append(utils.smt_assert(equation))

        # recursively adding couple words
        series = num_of_orders - 2
        for i in range(2, num_of_orders + 1):
            for j in range(0, 2 ** num_of_orders, 2 ** i):
                # carries computed as usual (remember the library convention: MSB indexed by 0)
                for k in range(0, i - 1):
                    variables.append(f'c_{series}_{j // (2 ** i)}_{k}')
                    carry = utils.smt_carry(f'r_{series + 1}_{j // (2 ** (i - 1))}_{k}',
                                            f'r_{series + 1}_{j // (2 ** (i - 1)) + 1}_{k}',
                                            f'c_{series}_{j // (2 ** i)}_{k + 1}')
                    equation = utils.smt_equivalent((f'c_{series}_{j // (2 ** i)}_{k}', carry))
                    constraints.append(utils.smt_assert(equation))
                # the carry for the tens is the first not null
                variables.append(f'c_{series}_{j // (2 ** i)}_{i - 1}')
                carry = utils.smt_and((f'r_{series + 1}_{j // (2 ** (i - 1))}_{i - 1}',
                                       f'r_{series + 1}_{j // (2 ** (i - 1)) + 1}_{i - 1}'))
                equation = utils.smt_equivalent((f'c_{series}_{j // (2 ** i)}_{i - 1}', carry))
                constraints.append(utils.smt_assert(equation))
                # first bit of the result (MSB) is simply the carry of the previous MSBs
                variables.append(f'r_{series}_{j // (2 ** i)}_0')
                equation = utils.smt_equivalent((f'r_{series}_{j // (2 ** i)}_0',
                                                 f'c_{series}_{j // (2 ** i)}_0'))
                constraints.append(utils.smt_assert(equation))
                # remaining bits of the result except the last one are as usual
                for k in range(1, i):
                    variables.append(f'r_{series}_{j // (2 ** i)}_{k}')
                    result = utils.smt_xor((f'r_{series + 1}_{j // (2 ** (i - 1))}_{k - 1}',
                                            f'r_{series + 1}_{j // (2 ** (i - 1)) + 1}_{k - 1}',
                                            f'c_{series}_{j // (2 ** i)}_{k}'))
                    equation = utils.smt_equivalent((f'r_{series}_{j // (2 ** i)}_{k}', result))
                    constraints.append(utils.smt_assert(equation))
                # last bit of the result (LSB)
                variables.append(f'r_{series}_{j // (2 ** i)}_{i}')
                result = utils.smt_xor((f'r_{series + 1}_{j // (2 ** (i - 1))}_{i - 1}',
                                        f'r_{series + 1}_{j // (2 ** (i - 1)) + 1}_{i - 1}'))
                equation = utils.smt_equivalent((f'r_{series}_{j // (2 ** i)}_{i}', result))
                constraints.append(utils.smt_assert(equation))
            series -= 1

        # the bit length of hamming weight, needed to fix weight when building the model
        bit_length_of_hw = num_of_orders + 1
        constraints.extend(utils.smt_assert(f'r_0_0_{i}') if weight >> (bit_length_of_hw - 1 - i) & 1
                           else utils.smt_assert(utils.smt_not(f'r_0_0_{i}'))
                           for i in range(bit_length_of_hw))

        return variables, constraints, bit_length_of_hw

    def _sequential_counter_algorithm(self, hw_list, weight, dummy_id, greater_or_equal=False):
        n = len(hw_list)
        if greater_or_equal:
            weight = n - weight
            hw_list = [utils.smt_not(id_) for id_ in hw_list]
        dummy_variables = [[f'{dummy_id}_{i}_{j}' for j in range(weight)] for i in range(n - 1)]
        constraints = [utils.smt_assert(utils.smt_implies(hw_list[0], dummy_variables[0][0]))]
        for j in range(1, weight):
            constraints.append(utils.smt_assert(utils.smt_not(dummy_variables[0][j])))
        for i in range(1, n - 1):
            constraints.append(utils.smt_assert(utils.smt_implies(hw_list[i],
                                                                  dummy_variables[i][0])))
            constraints.append(utils.smt_assert(utils.smt_implies(dummy_variables[i - 1][0],
                                                                  dummy_variables[i][0])))
            for j in range(1, weight):
                antecedent = utils.smt_and((hw_list[i], dummy_variables[i - 1][j - 1]))
                constraints.append(utils.smt_assert(utils.smt_implies(antecedent,
                                                                      dummy_variables[i][j])))
                constraints.append(utils.smt_assert(utils.smt_implies(dummy_variables[i - 1][j],
                                                                      dummy_variables[i][j])))
            opposite_dummy = utils.smt_not(dummy_variables[i - 1][weight - 1])
            constraints.append(utils.smt_assert(utils.smt_implies(hw_list[i], opposite_dummy)))
        opposite_dummy = utils.smt_not(dummy_variables[n - 2][weight - 1])
        constraints.append(utils.smt_assert(utils.smt_implies(hw_list[n - 1], opposite_dummy)))
        dummy_variables = [d for dummy_list in dummy_variables for d in dummy_list]

        return dummy_variables, constraints

    def _sequential_counter(self, hw_list, weight):
        return self._sequential_counter_algorithm(hw_list, weight, 'dummy_hw_0')

    def _sequential_counter_greater_or_equal(self, weight, dummy_id):
        hw_list = [variable_id for variable_id in self._variables_list if variable_id.startswith('hw_')]
        variables, constraints = self._sequential_counter_algorithm(hw_list, weight, dummy_id,
                                                                    greater_or_equal=True)
        number_of_declarations = len(self._variables_list)
        formulae = self._model_constraints[
                   len(constants.MODEL_PREFIX)+number_of_declarations:-len(constants.MODEL_SUFFIX)]
        self._variables_list.extend(variables)
        self._declarations_builder()
        formulae.extend(constraints)
        self._model_constraints = constants.MODEL_PREFIX + self._declarations + formulae + constants.MODEL_SUFFIX

    def cipher_input_variables(self):
        """
        Return the list of input variables.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.cipher_modules.models.smt.smt_model import SmtModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: smt = SmtModel(speck)
            sage: smt.cipher_input_variables()
            ['plaintext_0',
             'plaintext_1',
             ...
             'key_62',
             'key_63']
        """
        cipher_input_bit_ids = [f'{input_id}_{j}'
                                for input_id, size in zip(self._cipher.inputs, self._cipher.inputs_bit_size)
                                for j in range(size)]

        return cipher_input_bit_ids

    def fix_variables_value_constraints(self, fixed_variables=[]):
        """
        Return a list of SMT-LIB asserts for fixing variables in CIPHER and XOR DIFFERENTIAL model.

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); variables in default format

        EXAMPLES::

            sage: from claasp.cipher_modules.models.smt.smt_model import SmtModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: smt = SmtModel(speck)
            sage: smt.fix_variables_value_constraints([set_fixed_variables('plaintext', 'equal', range(4), integer_to_bit_list(5, 4, 'big'))])
            ['(assert (not plaintext_0))',
             '(assert plaintext_1)',
             '(assert (not plaintext_2))',
             '(assert plaintext_3)']
            sage: smt.fix_variables_value_constraints([set_fixed_variables('plaintext', 'not_equal', range(4), integer_to_bit_list(5, 4, 'big'))])
            ['(assert (or plaintext_0 (not plaintext_1) plaintext_2 (not plaintext_3)))']
        """
        constraints = []
        for component in fixed_variables:
            component_id = component['component_id']
            bit_positions = component['bit_positions']
            bit_values = component['bit_values']

            if component['constraint_type'] not in ['equal', 'not_equal']:
                raise ValueError('constraint type not defined or misspelled.')

            if component['constraint_type'] == 'equal':
                self.update_constraints_for_equal_type(bit_positions, bit_values, component_id, constraints)
            elif component['constraint_type'] == 'not_equal':
                self.update_constraints_for_not_equal_type(bit_positions, bit_values, component_id, constraints)

        return constraints

    def get_cipher_components_for_components_values(self, model_type, out_suffix, var_dict):
        total_weight = 0
        components_values = {}
        in_suffix = constants.INPUT_BIT_ID_SUFFIX
        for component in self._cipher.get_all_components():
            output_bit_size = component.output_bit_size
            output_value = get_component_value(component, out_suffix, output_bit_size, var_dict)
            width = output_bit_size // 4 + (output_bit_size % 4 != 0)
            hex_value = f'{output_value:0{width}x}'
            weight = 0
            if model_type != CIPHER and (('MODADD' in component.description) or ('AND' in component.description) or
                                         ('OR' in component.description) or (SBOX in component.type)):
                weight = sum([var_dict[f'hw_{component.id}_{i}{out_suffix}'] for i in range(output_bit_size)])
            component_value = set_component_value_weight_sign(hex_value, weight)
            components_values[f'{component.id}{out_suffix}'] = component_value
            total_weight += weight
            if model_type == XOR_LINEAR:
                input_value = get_component_value(component, in_suffix, output_bit_size, var_dict)
                hex_digits = output_bit_size // 4 + (output_bit_size % 4 != 0)
                hex_value = f'{input_value:0{hex_digits}x}'
                component_value = set_component_value_weight_sign(hex_value, 0)
                components_values[f'{component.id}{in_suffix}'] = component_value

        return components_values, total_weight

    def get_cipher_input_for_components_values(self, out_suffix, var_dict):
        components_values = {}
        for cipher_input, bit_size in zip(self._cipher.inputs, self._cipher.inputs_bit_size):
            value = 0
            for i in range(bit_size):
                value <<= 1
                if f'{cipher_input}_{i}{out_suffix}' in var_dict:
                    value ^= var_dict[f'{cipher_input}_{i}{out_suffix}']
            width = bit_size // 4 + (bit_size % 4 != 0)
            hex_value = f'{value:0{width}x}'
            components_values[cipher_input] = set_component_value_weight_sign(hex_value)

        return components_values

    def get_xor_probability_constraints(self, bit_ids, template):
        constraints = []
        for clause in template:
            literals = []
            for value in clause:
                literal = bit_ids[value[1]]
                if value[0]:
                    literal = utils.smt_not(literal)
                literals.append(literal)
            constraints.append(utils.smt_assert(utils.smt_or(literals)))

        return constraints

    def _parse_solver_output(self, model_type, solver_output, solver_name):
        # parsing the solver output
        var_dict = {}
        if solver_name == 'z3':
            var_dict = utils.z3_parser(solver_output)
        elif solver_name == 'yices-smt2':
            var_dict = utils.yices_parser(solver_output)
        elif solver_name == 'mathsat':
            var_dict = utils.mathsat_parser(solver_output)

        # if sat, compute components' value and weight
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX if model_type == XOR_LINEAR else ''

        components_values = self.get_cipher_input_for_components_values(out_suffix, var_dict)

        cipher_components_components_values, total_weight = self.get_cipher_components_for_components_values(model_type,
                                                                                                             out_suffix,
                                                                                                             var_dict)
        components_values.update(cipher_components_components_values)

        return components_values, total_weight

    def update_constraints_for_equal_type(self, bit_positions, bit_values, component_id, constraints, out_suffix=""):
        for i, position in enumerate(bit_positions):
            if bit_values[i]:
                constraint = f'{component_id}_{position}{out_suffix}'
            else:
                constraint = utils.smt_not(f'{component_id}_{position}{out_suffix}')
            constraints.append(utils.smt_assert(constraint))

    def update_constraints_for_not_equal_type(self, bit_positions, bit_values,
                                              component_id, constraints, out_suffix=""):
        literals = []
        for i, position in enumerate(bit_positions):
            if bit_values[i]:
                literals.append(utils.smt_not(f'{component_id}_{position}{out_suffix}'))
            else:
                literals.append(f'{component_id}_{position}{out_suffix}')
        constraints.append(utils.smt_assert(utils.smt_or(literals)))

    def solve(self, model_type, solver_name='z3'):
        """
        Return the solution of the model using the ``solver_name`` SMT solver.

        INPUT:

        - ``model_type`` -- **string**; the model for which we want a solution. Available values are:

          * ``'cipher'``
          * ``'xor_differential'``
          * ``'xor_linear'``
        - ``solver_name`` -- **string** (default: `z3`); the name of the solver

        .. SEEALSO::

            :ref:`smt-solvers`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_model import SmtModel
            sage: speck = SpeckBlockCipher(number_of_rounds=4)
            sage: smt = SmtModel(speck)
            sage: smt.solve('xor_differential') # random
            {'cipher_id': 'speck_p32_k64_o32_r4',
             'model_type': 'xor_differential',
             'solver_name': 'z3',
             'solving_time_seconds': 0.0,
             'memory_megabytes': 0.09,
             'components_values': {},
             'total_weight': None}
        """
        def _get_data(data_string, lines):
            data_line = [line for line in lines if data_string in line][0]
            data = float(re.findall(r'\d+\.?\d*', data_line)[0])
            return data

        solver_specs = constants.SMT_SOLVERS[solver_name]
        command = solver_specs['command'][:]
        smt_input = '\n'.join(self._model_constraints) + '\n'
        solver_process = subprocess.run(command, input=smt_input, capture_output=True, text=True)
        solver_output = solver_process.stdout.splitlines()
        solve_time = _get_data(solver_specs['time'], solver_output)
        memory = _get_data(solver_specs['memory'], solver_output)
        if solver_output[0] == 'sat':
            component2value, total_weight = self._parse_solver_output(model_type, solver_output,
                                                                      solver_name)
            total_weight = float(total_weight)
            status = 'SATISFIABLE'
        else:
            component2value, total_weight = {}, None
            status = 'UNSATISFIABLE'

        solution = convert_solver_solution_to_dictionary(self.cipher_id, model_type, solver_name, solve_time,
                                                         memory, component2value, total_weight)
        solution['status'] = status

        return solution

    def weight_constraints(self, weight):
        """
        Return a variable list and SMT-LIB list asserts representing the fixing of the total weight to the input value.

        INPUT:

        - ``weight`` -- **integer**; represents the total weight of the trail
        """
        hw_list = [variable_id for variable_id in self._variables_list if variable_id.startswith('hw_')]
        if weight == 0:
            return [], [utils.smt_assert(utils.smt_not(variable)) for variable in hw_list]

        return self._counter(hw_list, weight)

    @property
    def cipher_id(self):
        return self._cipher.id

    @property
    def model_constraints(self):
        """
        Return the model specified by ``model_type``.

        If the key refers to one of the available solver, Otherwise will raise a KeyError exception.

        INPUT:

        - ``model_type`` -- **string**; the model to retrieve

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_model import SmtModel
            sage: speck = SpeckBlockCipher(number_of_rounds=4)
            sage: smt = SmtModel(speck)
            sage: smt.model_constraints()
            Traceback (most recent call last):
            ...
            ValueError: No model generated
        """
        if not self._model_constraints:
            raise ValueError('No model generated')
        return self._model_constraints

    @property
    def sboxes_ddt_templates(self):
        return self._sboxes_ddt_templates

    @property
    def sboxes_lat_templates(self):
        return self._sboxes_lat_templates
