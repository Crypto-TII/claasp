
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
SAT model of Cipher.

.. _sat-standard:

SAT standard of Cipher
------------------------------------

The target of this class is to build, solve and retrieve the solution of a SAT
CNF representing some attacks on ciphers, e.g. the generic cipher inversion or
the search for XOR differential trails (for SMT CNFs see the correspondent
module). The internal format for SAT CNF clauses follows 3 rules:

    * every variable is a string with no spaces nor dashes;
    * if a literal is a negation of a variable, a dash is prepended to the variable;
    * the separator for literals is a space.

This module only handles the internal format. The translation in DIMACS
standard is performed whenever a solution method is called (e.g. ``solve``,
``find_lowest_weight_xor_differential_trail``, ...).

.. _sat-solvers:

SAT Solvers
-----------

This module is able to use different SAT solvers. They can be divided in two
categories: external and internal. All over the module, ``solver_name``
variable can be replaced with a value in the following.

External SAT solvers need to be installed in the system as they are called
using a subprocess. They and corresponding values for ``solver_name`` variable
are:

    ============================================================== ======================
    SAT solver                                                     value
    ============================================================== ======================
    `CaDiCal <https://github.com/arminbiere/cadical>`_             ``'cadical'``
    `CryptoMiniSat <https://github.com/msoos/cryptominisat>`_      ``'cryptominisat'``
    `Glucose <https://www.labri.fr/perso/lsimon/glucose/>`_        ``'glucose'``
    `Glucose-syrup <https://www.labri.fr/perso/lsimon/glucose/>`_  ``'glucose-syrup'``
    `Kissat <https://github.com/arminbiere/kissat>`_               ``'kissat'``
    `MathSAT <https://mathsat.fbk.eu/>`_                           ``'mathsat'``
    `Minisat <https://github.com/niklasso/minisat>`_               ``'minisat'``
    `Yices-sat <https://yices.csl.sri.com/>`_                      ``'yices-sat'``
    ============================================================== ======================

Internal SAT solvers should be installed by default. To call them, use the
following values:

    * ``'cryptominisat_sage'``
    * ``'glucose_sage'``
    * ``'glucose-syrup_sage'``
    * ``'LP_sage'``
    * ``'picosat_sage'``

For any further information on internal SAT solvers, visit `Abstract SAT solver
<https://doc.sagemath.org/html/en/reference/sat/sage/sat/solvers/satsolver.html>`_.

**REMARK**: in order to be compliant with the library, the Most Significant Bit
(MSB) is indexed by 0. Be careful whenever inspecting the code or, as well, a
CNF.
"""
import copy
import math
import time
import tracemalloc
import uuid

from sage.sat.solvers.satsolver import SAT

from claasp.cipher_modules.models.sat.utils import constants, utils
from claasp.cipher_modules.models.utils import set_component_value_weight_sign, convert_solver_solution_to_dictionary
from claasp.name_mappings import (SBOX, CIPHER, XOR_LINEAR)


class SatModel:
    def __init__(self, cipher, window_size=-1,
                 window_size_weight_pr_vars=-1,
                 counter='sequential',
                 compact=False):
        """
        Initialise the sat model.

        INPUT:

        - ``cipher`` -- **Cipher object**; an instance of the cipher.
        - ``window_size`` -- **integer** (default: `-1`)
        - ``window_size_weight_pr_vars`` -- **integer** (default: `-1`)
        - ``counter`` -- **string** (default: `sequential`)
        - ``compact`` -- **boolean** (default: False); set to True for using a simplified cipher (it will remove
          rotations and permutations)
        """
        # remove rotations and permutations (if any)
        internal_graph = copy.deepcopy(cipher)
        if compact:
            new_rounds = utils.remove_rotations(internal_graph.rounds_as_list)
            new_rounds = utils.remove_permutations(new_rounds)
            internal_graph['cipher_rounds'] = new_rounds

        # set the counter to fix the weight
        if counter == 'sequential':
            self._counter = self._sequential_counter
        else:
            self._counter = self._parallel_counter

        self._cipher = internal_graph
        self._variables_list = []
        self._model_constraints = []
        self._sboxes_ddt_templates = {}
        self._sboxes_lat_templates = {}
        self._window_size = window_size
        self.window_size_weight_pr_vars = window_size_weight_pr_vars

    def _add_clauses_to_solver(self, numerical_cnf, solver):
        """
        Add clauses to the (internal) SAT solver.

        It has been separated from the :py:meth:`~SatModel._solve_with_sage_sat_solver`
        because it needs to be overwritten in every model.
        """
        for clause in numerical_cnf:
            solver.add_clause([int(literal) for literal in clause.split()])

    def _get_components_values(self, out_suffix, output_values_dict):
        components_values = {}
        for cipher_input, bit_size in zip(self._cipher.inputs, self._cipher.inputs_bit_size):
            value = 0
            for i in range(bit_size):
                value <<= 1
                if f'{cipher_input}_{i}{out_suffix}' in output_values_dict:
                    value ^= output_values_dict[f'{cipher_input}_{i}{out_suffix}']
            hex_digits = bit_size // 4 + (bit_size % 4 != 0)
            hex_value = f'{value:0{hex_digits}x}'
            component = set_component_value_weight_sign(hex_value)
            components_values[cipher_input] = component

        return components_values

    def _get_solver_solution_parsed(self, dimacs_dict, output_values):
        output_values_dict = {}
        for i, key in enumerate(dimacs_dict):
            output_values_dict[key] = 0 if output_values[i][0] == '-' else 1

        return output_values_dict

    def _parallel_counter(self, hw_list, weight):
        """
        No references.

        Extend the list of variables representing the weight until the cardinality is the lowest possible power of 2.
        Then, create constraints representing parallel addition of them. The ID of the word representing the result
        will be always <r_0_0>, i.e. the bits are <r_0_0_0>, <r_0_0_1>, <r_0_0_2>, ...
        """
        # adding dummy variables and building the first part (i.e. summing couple of bits)
        variables = []
        constraints = []
        num_of_orders = math.ceil(math.log2(len(hw_list)))
        dummy_list = [f'dummy_hw_{i}' for i in range(len(hw_list), 2 ** num_of_orders)]
        variables.extend(dummy_list)
        hw_list.extend(dummy_list)
        constraints.extend(f'-{d}' for d in dummy_list)
        for i in range(0, 2 ** num_of_orders, 2):
            variables.append(f'r_{num_of_orders - 1}_{i // 2}_0')
            variables.append(f'r_{num_of_orders - 1}_{i // 2}_1')
            constraints.extend(utils.cnf_and(f'r_{num_of_orders - 1}_{i // 2}_0',
                                             (f'{hw_list[i]}', f'{hw_list[i + 1]}')))
            constraints.extend(utils.cnf_xor(f'r_{num_of_orders - 1}_{i // 2}_1',
                                             [f'{hw_list[i]}', f'{hw_list[i + 1]}']))
        # recursively summing couple words
        series = num_of_orders - 2
        for i in range(2, num_of_orders + 1):
            for j in range(0, 2 ** num_of_orders, 2 ** i):
                # carries computed as usual (remember the library convention: MSB indexed by 0)
                for k in range(0, i - 1):
                    variables.append(f'c_{series}_{j // (2 ** i)}_{k}')
                    constraints.extend(utils.cnf_carry(f'c_{series}_{j // (2 ** i)}_{k}',
                                                       f'r_{series + 1}_{j // (2 ** (i - 1))}_{k}',
                                                       f'r_{series + 1}_{j // (2 ** (i - 1)) + 1}_{k}',
                                                       f'c_{series}_{j // (2 ** i)}_{k + 1}'))
                # the carry for the tens is the first not null
                variables.append(f'c_{series}_{j // (2 ** i)}_{i - 1}')
                constraints.extend(utils.cnf_and(f'c_{series}_{j // (2 ** i)}_{i - 1}',
                                                 [f'r_{series + 1}_{j // (2 ** (i - 1))}_{i - 1}',
                                                  f'r_{series + 1}_{j // (2 ** (i - 1)) + 1}_{i - 1}']))
                # first bit of the result (MSB) is simply the carry of the previous MSBs
                variables.append(f'r_{series}_{j // (2 ** i)}_0')
                constraints.extend(utils.cnf_equivalent([f'r_{series}_{j // (2 ** i)}_0',
                                                         f'c_{series}_{j // (2 ** i)}_0']))
                # remaining bits of the result except the last one are as usual
                for k in range(1, i):
                    variables.append(f'r_{series}_{j // (2 ** i)}_{k}')
                    constraints.extend(utils.cnf_xor(f'r_{series}_{j // (2 ** i)}_{k}',
                                                     [f'r_{series + 1}_{j // (2 ** (i - 1))}_{k - 1}',
                                                      f'r_{series + 1}_{j // (2 ** (i - 1)) + 1}_{k - 1}',
                                                      f'c_{series}_{j // (2 ** i)}_{k}']))
                # last bit of the result (LSB)
                variables.append(f'r_{series}_{j // (2 ** i)}_{i}')
                constraints.extend(utils.cnf_xor(f'r_{series}_{j // (2 ** i)}_{i}',
                                                 [f'r_{series + 1}_{j // (2 ** (i - 1))}_{i - 1}',
                                                  f'r_{series + 1}_{j // (2 ** (i - 1)) + 1}_{i - 1}']))
            series -= 1
        # bit length of hamming weight, needed to fix weight when building the model
        bit_length_of_hw = num_of_orders + 1
        minus_signs = ['-' * (int(bit) ^ 1) for bit in f'{weight:0{bit_length_of_hw}b}']
        constraints.extend([f'{minus_signs[i]}r_0_0_{i}' for i in range(bit_length_of_hw)])

        return variables, constraints

    def _sequential_counter_algorithm(self, hw_list, weight, dummy_id, greater_or_equal=False):
        n = len(hw_list)
        if greater_or_equal:
            weight = n - weight
            minus = ''
        else:
            minus = '-'
        dummy_variables = [[f'{dummy_id}_{i}_{j}' for j in range(weight)] for i in range(n - 1)]
        constraints = [f'{minus}{hw_list[0]} {dummy_variables[0][0]}']
        constraints.extend([f'-{dummy_variables[0][j]}' for j in range(1, weight)])
        for i in range(1, n - 1):
            constraints.append(f'{minus}{hw_list[i]} {dummy_variables[i][0]}')
            constraints.append(f'-{dummy_variables[i - 1][0]} {dummy_variables[i][0]}')
            constraints.extend([f'{minus}{hw_list[i]} -{dummy_variables[i - 1][j - 1]} {dummy_variables[i][j]}'
                                for j in range(1, weight)])
            constraints.extend([f'-{dummy_variables[i - 1][j]} {dummy_variables[i][j]}'
                                for j in range(1, weight)])
            constraints.append(f'{minus}{hw_list[i]} -{dummy_variables[i - 1][weight - 1]}')
        constraints.append(f'{minus}{hw_list[n - 1]} -{dummy_variables[n - 2][weight - 1]}')
        dummy_variables = [d for dummy_list in dummy_variables for d in dummy_list]

        return dummy_variables, constraints

    def _sequential_counter(self, hw_list, weight):
        return self._sequential_counter_algorithm(hw_list, weight, 'dummy_hw_0')

    def _sequential_counter_greater_or_equal(self, weight, dummy_id):
        hw_list = [variable_id for variable_id in self._variables_list if variable_id.startswith('hw_')]
        variables, constraints = self._sequential_counter_algorithm(hw_list, weight, dummy_id,
                                                                    greater_or_equal=True)
        self._variables_list.extend(variables)
        self._model_constraints.extend(constraints)

    def _solve_with_external_sat_solver(self, model_type, solver_name, options, host=None, env_vars_string=""):
        if host and (solver_name not in constants.SAT_SOLVERS_DIMACS_COMPLIANT):
            raise ValueError('{solver_name} not supported.')

        # creating the dimacs
        variable2number, numerical_cnf = utils.create_numerical_cnf(self._model_constraints)
        dimacs = utils.numerical_cnf_to_dimacs(len(variable2number), numerical_cnf)

        # running the SAT solver
        file_id = f'{uuid.uuid4()}'
        if host is not None:
            status, sat_time, sat_memory, values = utils.run_sat_solver(solver_name, options,
                                                                        dimacs, host, env_vars_string)
        else:
            if solver_name in constants.SAT_SOLVERS_DIMACS_COMPLIANT:
                status, sat_time, sat_memory, values = utils.run_sat_solver(solver_name, options,
                                                                            dimacs)
            elif solver_name == 'minisat':
                input_file = f'{self.cipher_id}_{file_id}_sat_input.cnf'
                output_file = f'{self.cipher_id}_{file_id}_sat_output.cnf'
                status, sat_time, sat_memory, values = utils.run_minisat(options, dimacs,
                                                                         input_file, output_file)
            elif solver_name == 'yices-sat':
                input_file = f'{self.cipher_id}_{file_id}_sat_input.cnf'
                status, sat_time, sat_memory, values = utils.run_yices(options, dimacs, input_file)

        # parsing the solution
        if status == 'SATISFIABLE':
            component2value, total_weight = self._parse_solver_output(model_type, values,
                                                                      variable2number)
            total_weight = float(total_weight)
        else:
            component2value, total_weight = {}, None
        solution = convert_solver_solution_to_dictionary(self.cipher_id, model_type, solver_name, sat_time,
                                                         sat_memory, component2value, total_weight)
        solution['status'] = status

        return solution

    def _solve_with_sage_sat_solver(self, model_type, solver_name):
        variable2number, numerical_cnf = utils.create_numerical_cnf(self._model_constraints)
        solver = SAT(solver=solver_name)
        self._add_clauses_to_solver(numerical_cnf, solver)
        start_time = time.time()
        tracemalloc.start()
        output_values = solver()
        sat_memory = tracemalloc.get_traced_memory()[1] / 10 ** 6
        tracemalloc.stop()
        sat_time = time.time() - start_time
        if output_values:
            output_values = [f'{v-1}' for v in output_values[1:]]
            component2value, total_weight = self._parse_solver_output(model_type, output_values,
                                                                      variable2number)
            total_weight = float(total_weight)
            status = 'SATISFIABLE'
        else:
            component2value, total_weight = {}, None
            status = 'UNSATISFIABLE'
        solution = convert_solver_solution_to_dictionary(self.cipher_id, model_type, solver_name, sat_time,
                                                         sat_memory, component2value, total_weight)
        solution['status'] = status

        return solution

    def fix_variables_value_constraints(self, fixed_variables=[]):
        """
        Return lists of variables and clauses for fixing variables in CIPHER model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); variables in default format

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.sat.sat_model import SatModel
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: sat = SatModel(speck)
            sage: fixed_variables = [{
            ....:    'component_id': 'plaintext',
            ....:    'constraint_type': 'equal',
            ....:    'bit_positions': [0, 1, 2, 3],
            ....:    'bit_values': [1, 0, 1, 1]
            ....: }, {
            ....:    'component_id': 'ciphertext',
            ....:    'constraint_type': 'not_equal',
            ....:    'bit_positions': [0, 1, 2, 3],
            ....:    'bit_values': [1, 1, 1, 0]
            ....: }]
            sage: sat.fix_variables_value_constraints(fixed_variables)
            ['plaintext_0',
             '-plaintext_1',
             'plaintext_2',
             'plaintext_3',
             '-ciphertext_0 -ciphertext_1 -ciphertext_2 ciphertext_3']
        """
        constraints = []
        for variable in fixed_variables:
            component_id = variable['component_id']
            is_equal = (variable['constraint_type'] == 'equal')
            bit_positions = variable['bit_positions']
            bit_values = variable['bit_values']
            variables_ids = []
            for position, value in zip(bit_positions, bit_values):
                is_negative = '-' * (value ^ is_equal)
                variables_ids.append(f'{is_negative}{component_id}_{position}')
            if is_equal:
                constraints.extend(variables_ids)
            else:
                constraints.append(' '.join(variables_ids))

        return constraints

    def _parse_solver_output(self, model_type, output_values, dimacs_dict):
        out_suffix = ''
        in_suffix = ''
        if model_type == XOR_LINEAR:
            out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
            in_suffix = constants.INPUT_BIT_ID_SUFFIX

        output_values_dict = self._get_solver_solution_parsed(dimacs_dict, output_values)

        # building cipher components
        components_values = self._get_components_values(out_suffix, output_values_dict)
        total_weight = 0
        for component in self._cipher.get_all_components():
            output_bit_size = component.output_bit_size
            output_value = self.get_component_value(component, out_suffix, output_bit_size,
                                                    output_values_dict)
            hex_digits = output_bit_size // 4 + (output_bit_size % 4 != 0)
            hex_value = f'{output_value:0{hex_digits}x}'
            weight = self.calculate_component_weight(component, model_type, out_suffix,
                                                     output_bit_size, output_values_dict)
            component_value = set_component_value_weight_sign(hex_value, weight)
            components_values[f'{component.id}{out_suffix}'] = component_value
            total_weight += weight
            if model_type == XOR_LINEAR:
                input_value = self.get_component_value(component, in_suffix, output_bit_size,
                                                       output_values_dict)
                hex_digits = output_bit_size // 4 + (output_bit_size % 4 != 0)
                hex_value = f'{input_value:0{hex_digits}x}'
                component_value = set_component_value_weight_sign(hex_value, 0)
                components_values[f'{component.id}{in_suffix}'] = component_value

        return components_values, total_weight

    def get_component_value(self, component, out_suffix, output_bit_size, output_values_dict):
        value = 0
        for i in range(output_bit_size):
            value <<= 1
            if f'{component.id}_{i}{out_suffix}' in output_values_dict:
                value ^= output_values_dict[f'{component.id}_{i}{out_suffix}']
        return value

    def calculate_component_weight(self, component, model_type, out_suffix, output_bit_size, output_values_dict):
        weight = 0
        if model_type != CIPHER and ('MODADD' in component.description or
                                     'AND' in component.description or
                                     'OR' in component.description or
                                     SBOX in component.type):
            weight = sum([output_values_dict[f'hw_{component.id}_{i}{out_suffix}']
                          for i in range(output_bit_size)])
        return weight

    def solve(self, model_type, solver_name='cryptominisat', options=None):
        """
        Return the solution of the model using the ``solver_name`` SAT solver.

        .. NOTE::

            Two types of solvers can be chosen: external or internal. In the following list of inputs, allowed SAT
            solvers are listed. Those ending with ``_sage`` will not create a subprocess nor additional files and will
            work completely embedded in Sage. Remaining solvers are allowed, but they need to be installed in the
            system.

        INPUT:

        - ``model_type`` -- **string**; the model for which we want a solution. Available values are:

          * ``'cipher'``
          * ``'xor_differential'``
          * ``'xor_linear'``
        - ``solver_name`` -- **string** (default: `cryptominisat`); the name of the solver

        .. SEEALSO::

            :ref:`sat-solvers`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.sat.sat_models.sat_cipher_model import SatCipherModel
            sage: from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
            sage: tea = TeaBlockCipher(number_of_rounds=32)
            sage: sat = SatCipherModel(tea)
            sage: sat.build_cipher_model()
            sage: sat.solve('cipher') # random
            {'cipher_id': 'tea_p64_k128_o64_r32',
             'model_type': 'tea_p64_k128_o64_r32',
             'solver_name': 'cryptominisat',
             ...
              'intermediate_output_31_15': {'value': '8ca8d5de0906f08e', 'weight': 0, 'sign': 1},
              'cipher_output_31_16': {'value': '8ca8d5de0906f08e', 'weight': 0, 'sign': 1}},
             'total_weight': 0,
             'status': 'SATISFIABLE'}}
        """
        if options is None:
            options = []
        if solver_name.endswith('_sage'):
            if options:
                raise ValueError('Options not allowed for SageMath solvers.')
            solution = self._solve_with_sage_sat_solver(model_type, solver_name[:-5])
        else:
            solution = self._solve_with_external_sat_solver(model_type, solver_name, options)

        return solution

    def weight_constraints(self, weight):
        """
        Return lists of variables and constraints that fix the total weight of the trail to a specific value.

        INPUT:

        - ``weight`` -- **integer**; the total weight of the trail

        EXAMPLES::

            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: sat = SatXorDifferentialModel(speck)
            sage: sat.build_xor_differential_trail_model()
            sage: sat.weight_constraints(7)
            (['dummy_hw_0_0_0',
              'dummy_hw_0_0_1',
              'dummy_hw_0_0_2',
              ...
              '-dummy_hw_0_77_6 dummy_hw_0_78_6',
              '-hw_modadd_2_7_14 -dummy_hw_0_77_6',
              '-hw_modadd_2_7_15 -dummy_hw_0_78_6'])
        """
        hw_list = [variable_id for variable_id in self._variables_list if variable_id.startswith('hw_')]
        if weight == 0:
            return [], [f'-{variable}' for variable in hw_list]

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
            sage: from claasp.cipher_modules.models.sat.sat_model import SatModel
            sage: speck = SpeckBlockCipher(number_of_rounds=4)
            sage: sat = SatModel(speck)
            sage: sat.model_constraints('xor_differential')
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

    @property
    def window_size(self):
        return self._window_size
