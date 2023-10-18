
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

from minizinc import Status

from claasp.cipher_modules.models.minizinc.minizinc_model import MinizincModel
from claasp.name_mappings import CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, WORD_OPERATION


class MinizincXorDifferentialModel(MinizincModel):

    def __init__(self, cipher, window_size_list=None, probability_weight_per_round=None, sat_or_milp='sat'):
        super().__init__(cipher, window_size_list, probability_weight_per_round, sat_or_milp)

    @staticmethod
    def _create_minizinc_1d_array_from_list(mzn_list):
        mzn_list_size = len(mzn_list)
        lst_temp = f'[{",".join(mzn_list)}]'

        return f'array1d(0..{mzn_list_size}-1, {lst_temp})'

    @staticmethod
    def _get_total_weight(result):
        if result.status in [Status.SATISFIED, Status.ALL_SOLUTIONS, Status.OPTIMAL_SOLUTION]:
            if result.status == Status.OPTIMAL_SOLUTION:
                return result.objective
            elif result.status in [Status.SATISFIED]:
                if isinstance(result.solution, list):
                    return "list_of_solutions"
                else:
                    return result.solution.objective
            elif result.status in [Status.ALL_SOLUTIONS]:
                return []
        else:
            return None

    def _parse_solution(self, result, solution, list_of_vars, statistics='None'):
        def get_hex_string_from_bool_dict(data, bool_dict, probability_vars_weights_):
            temp_result = {}
            for sublist in data:
                reversed_list = sublist[::-1]
                bool_list = [bool_dict[item] for item in reversed_list]
                int_value = sum([2 ** i if bit else 0 for i, bit in enumerate(bool_list)])
                component_id = "_".join(sublist[0].split("_")[:-1])
                weight = 0
                if component_id.startswith('modadd') or component_id.startswith('modsub'):
                    weight = probability_vars_weights_[f'p_{component_id}_0']['weight']
                temp_result[component_id] = {'value': hex(int_value)[2:], 'weight': weight, 'sign': 1}

            return temp_result

        parsed_solution = {'total_weight': None, 'component_values': {}}
        if result.status in [Status.SATISFIED, Status.ALL_SOLUTIONS, Status.OPTIMAL_SOLUTION]:
            dict_of_solutions = solution.__dict__
            probability_vars_weights = self.parse_probability_vars(result, solution)
            solution_total_weight = sum(item['weight'] for item in probability_vars_weights.values())
            parsed_solution['total_weight'] = solution_total_weight
            parsed_solution['component_values'] = get_hex_string_from_bool_dict(
                list_of_vars, dict_of_solutions, probability_vars_weights
            )

        parsed_solution['status'] = str(result.status)

        if statistics:
            parsed_solution['statistics'] = result.statistics
        return parsed_solution

    def _parse_result(self, result, solver_name, total_weight, model_type):
        def _entry_matches(entry, prefix):
            valid_starts = [f"var bool: {prefix}", f"var 0..1: {prefix}"]
            return any(entry.startswith(vs) for vs in valid_starts)

        def group_strings_by_pattern(data: list) -> list:
            prefixes = set([entry.split("_y")[0].split(": ")[1] for entry in data if "_y" in entry])
            temp_result = []
            for prefix in prefixes:
                sublist = [entry.split(": ")[1][:-1] for entry in data if _entry_matches(entry, prefix)]
                if sublist:
                    temp_result.append(sublist)
            return temp_result

        list_of_vars = group_strings_by_pattern(self._variables_list)
        common_parsed_data = {
            'id': self.cipher_id,
            'model_type': model_type,
            'solver_name': solver_name
        }

        if total_weight == "list_of_solutions":
            solutions = []
            for solution in result.solution:
                parsed_solution = self._parse_solution(result, solution, list_of_vars)
                solutions.append({**parsed_solution, **common_parsed_data})
            return solutions
        else:
            parsed_result = self._parse_solution(result, result.solution, list_of_vars, result.statistics)
            return {**parsed_result, **common_parsed_data}

    def build_xor_differential_trail_model(self, weight=-1, fixed_variables=[]):
        """
        Build the model for the search of xor differential trails.

        INPUT:

        - ``weight`` -- **integer** (default: `-1`); If set to non-negative integer, fixes the xor trail search to a specific
          weight
        - ``fixed_variables`` -- **list** (default: `[]`); variables that need to be fixed to a certain value
          dictionaries contain name, bit_size and value (as integer)
          | [
          |     {
          |         'component_id': 'plaintext',
          |         'constraint_type': 'equal'/'not_equal'
          |         'bit_positions': [0, 1, 2, 3],
          |         'binary_value': [0, 0, 0, 0]
          |     }
          | ]

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_xor_differential_model import MinizincXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=22)
            sage: minizinc = MinizincXorDifferentialModel(speck)
            sage: minizinc.build_xor_differential_trail_model()
        """
        variables = []
        self._variables_list = []
        constraints = self.fix_variables_value_constraints(fixed_variables)
        component_types = [CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, WORD_OPERATION]
        operation_types = ['MODADD', 'MODSUB', 'ROTATE', 'SHIFT', 'SHIFT_BY_VARIABLE_AMOUNT', 'XOR']
        self._model_constraints = constraints

        for component in self._cipher.get_all_components():
            operation = component.description[0]
            if component.type not in component_types or (
                    WORD_OPERATION == component.type and operation not in operation_types):
                print(f'{component.id} not yet implemented')
            else:
                variables, constraints = component.minizinc_xor_differential_propagation_constraints(self)

            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

        if weight != -1:
            variables, constraints = self.weight_constraints(weight)
            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

        self.init_constraints()

    def build_all_xor_differential_trails_with_fixed_weight(self, fixed_weight, fixed_variables):
        """
        Build a MiniZinc MILP model setting as objective the lowest weight for the xor differential trail.

        INPUT:

        - ``fixed_weight`` -- **integer**; the probability weight for the entire model
        - ``fixed_variables`` -- **list**; the variables to be fixed in the model

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_xor_differential_model import MinizincXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=5, block_bit_size=32, key_bit_size=64)
            sage: minizinc = MinizincXorDifferentialModel(speck)
            sage: bit_positions = [i for i in range(speck.output_bit_size)]
            sage: bit_positions_key = list(range(64))
            sage: fixed_variables = [{ 'component_id': 'plaintext',
            ....:     'constraint_type': 'sum',
            ....:     'bit_positions': bit_positions,
            ....:     'operator': '>',
            ....:     'value': '0' }]
            sage: fixed_variables.append({ 'component_id': 'key',
            ....:     'constraint_type': 'sum',
            ....:     'bit_positions': bit_positions_key,
            ....:     'operator': '=',
            ....:     'value': '0' })
            sage: minizinc.build_lowest_weight_xor_differential_trail_model(fixed_variables)
            sage: result = minizinc.solve('Xor')
            sage: result.statistics['nSolutions'] > 1
            True
        """
        self.init_constraints()
        self.build_xor_differential_trail_model(-1, fixed_variables)
        self._model_constraints.extend(self.weight_constraints(weight=fixed_weight, operator="="))
        self._model_constraints.extend(self.satisfy_generator())

    def build_lowest_weight_xor_differential_trail_model(self, fixed_variables, max_weight=None, min_weight=None):
        """
        Build a MiniZinc MILP model setting as objective the lowest weight for the xor differential trail.

        INPUT:

        - ``fixed_variables`` -- **list**; the variables to be fixed in the model
        - ``max_weight`` -- **integer** (default: `None`)
        - ``min_weight`` -- **integer** (default: `None`)

        EXAMPLES::

            sage: from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_xor_differential_model import MinizincXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=5, block_bit_size=32, key_bit_size=64)
            sage: minizinc = MinizincXorDifferentialModel(speck)
            sage: bit_positions = [i for i in range(speck.output_bit_size)]
            sage: bit_positions_key = list(range(64))
            sage: fixed_variables = [{ 'component_id': 'plaintext',
            ....:     'constraint_type': 'sum',
            ....:     'bit_positions': bit_positions,
            ....:     'operator': '>',
            ....:     'value': '0' }]
            sage: fixed_variables.append({ 'component_id': 'key',
            ....:     'constraint_type': 'sum',
            ....:     'bit_positions': bit_positions_key,
            ....:     'operator': '=',
            ....:     'value': '0' })
            sage: minizinc.build_lowest_weight_xor_differential_trail_model(fixed_variables)
            sage: result = minizinc.solve('Xor')
            sage: result.statistics['nSolutions'] > 1
            True
        """
        self.build_xor_differential_trail_model(-1, fixed_variables)
        self._model_constraints.extend(self.objective_generator())
        self._model_constraints.extend(
            self.weight_constraints(max_weight=max_weight, weight=min_weight, operator=">="))

    def build_lowest_xor_differential_trails_with_at_most_weight(self, fixed_weight, fixed_variables):
        """
        Build a MiniZinc MILP model setting as objective the lowest weight fot he xor differential trail.

        INPUT:

        - ``fixed_weight`` -- **integer**; the upper bound for the weight
        - ``fixed_variables`` -- **list**; the variables to be fixed in the model

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_xor_differential_model import MinizincXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=5, block_bit_size=32, key_bit_size=64)
            sage: minizinc = MinizincXorDifferentialModel(speck)
            sage: bit_positions = [i for i in range(speck.output_bit_size)]
            sage: bit_positions_key = list(range(64))
            sage: fixed_variables = [{ 'component_id': 'plaintext',
            ....:     'constraint_type': 'sum',
            ....:     'bit_positions': bit_positions,
            ....:     'operator': '>',
            ....:     'value': '0' }]
            sage: fixed_variables.append({ 'component_id': 'key',
            ....:     'constraint_type': 'sum',
            ....:     'bit_positions': bit_positions_key,
            ....:     'operator': '=',
            ....:     'value': '0' })
            sage: minizinc.build_lowest_xor_differential_trails_with_at_most_weight(
            ....:     100, fixed_variables
            ....: )
            sage: result = minizinc.solve('Xor')
            sage: result.statistics['nSolutions'] > 1
            True
        """
        self.init_constraints()
        self.build_xor_differential_trail_model(-1, fixed_variables)
        self._model_constraints.extend(self.weight_constraints(fixed_weight, "<="))
        self._model_constraints.extend(self.objective_generator())

    def connect_rounds(self):
        """
        Return a list of constraints that link the bits from each component.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_xor_differential_model import MinizincXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=22)
            sage: minizinc = MinizincXorDifferentialModel(speck)
            sage: minizinc.connect_rounds()[:24][0]
            'constraint rot_0_0_x0 = plaintext_y0;'
        """
        connect_rounds_constraints = []

        for cipher_round in self._cipher.rounds_as_list:
            for component in cipher_round.components:
                if component.type == "constant":
                    continue

                ninputs = component.input_bit_size
                input_vars = [f'{component.id}_{self.input_postfix}{i}' for i in range(ninputs)]
                input_links = component.input_id_links
                input_positions = component.input_bit_positions
                prev_input_vars = []

                for k in range(len(input_links)):
                    prev_input_vars += [input_links[k] + "_" + self.output_postfix + str(i) for i in input_positions[k]]

                connect_rounds_constraints += [f'constraint {x} = {y};' for (x, y) in zip(input_vars, prev_input_vars)]

        return connect_rounds_constraints

    def find_all_xor_differential_trails_with_fixed_weight(self, fixed_weight, fixed_values=[], solver_name=None):
        """
        Return all the XOR differential trails with weight equal to ``fixed_weight``.

        The value returned is a list of solutions in standard format.

        INPUT:

        - ``fixed_weight`` -- **integer**; upper limit probability weight
        - ``fixed_values`` -- **list** (default: `[]`); dictioanries contain variables values whose output need to be
          fixed
        - ``solver_name`` -- **string** (default: `None`); the name of the solver (if needed)

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_xor_differential_model import MinizincXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=5, block_bit_size=32, key_bit_size=64)
            sage: minizinc = MinizincXorDifferentialModel(speck)
            sage: bit_positions = [i for i in range(speck.output_bit_size)]
            sage: bit_positions_key = list(range(64))
            sage: fixed_variables = [{ 'component_id': 'plaintext',
            ....:     'constraint_type': 'sum',
            ....:     'bit_positions': bit_positions,
            ....:     'operator': '>',
            ....:     'value': '0' }]
            sage: fixed_variables.append({ 'component_id': 'key',
            ....:     'constraint_type': 'sum',
            ....:     'bit_positions': bit_positions_key,
            ....:     'operator': '=',
            ....:     'value': '0' })
            sage: result = minizinc.find_all_xor_differential_trails_with_fixed_weight(
            ....: 5, solver_name='Xor', fixed_values=fixed_variables
            ....: )
            sage: print(result['total_weight'])
            None
        """
        self.build_xor_differential_trail_model(-1, fixed_values)
        self._model_constraints.extend(self.weight_constraints(fixed_weight, "="))
        result = self.solve(solver_name=solver_name, all_solutions_=True)
        total_weight = MinizincXorDifferentialModel._get_total_weight(result)
        parsed_result = self._parse_result(result, solver_name, total_weight, 'xor_differential')

        return parsed_result

    def find_all_xor_differential_trails_with_weight_at_most(self, min_weight, max_weight=64,
                                                             fixed_values=[], solver_name=None):
        """
        Return all XOR differential trails with weight greater than ``min_weight`` and lower/equal to ``max_weight``.

        The value returned is a list of solutions in standard format.

        INPUT:

        - ``min_weight`` -- **integer**;  the lower bound for the weight
        - ``max_weight`` -- **integer** (default: `64`); the upper bound for the weight
        - ``fixed_values`` -- **list** (default: `[]`); dictionaries contain variables values whose output need to be
          fixed
        - ``solver_name`` -- **string** (default: `None`); the name of the solver (if needed)

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_xor_differential_model import MinizincXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=4, block_bit_size=32, key_bit_size=64)
            sage: minizinc = MinizincXorDifferentialModel(speck)
            sage: bit_positions = list(range(32))
            sage: bit_positions_key = list(range(64))
            sage: fixed_variables = [{ 'component_id': 'plaintext',
            ....:     'constraint_type': 'sum',
            ....:     'bit_positions': bit_positions,
            ....:     'operator': '>',
            ....:     'value': '0' }]
            sage: fixed_variables.append({ 'component_id': 'key',
            ....:     'constraint_type': 'sum',
            ....:     'bit_positions': bit_positions_key,
            ....:     'operator': '=',
            ....:     'value': '0' })
            sage: result = minizinc.find_all_xor_differential_trails_with_weight_at_most(
            ....:     1, solver_name='Xor', fixed_values=fixed_variables
            ....: )
            sage: result[0]['total_weight'] > 1
            True
        """
        self.build_xor_differential_trail_model(-1, fixed_values)
        self._model_constraints.extend(
            self.weight_constraints(min_weight, ">", max_weight))
        result = self.solve(solver_name=solver_name, all_solutions_=True)
        total_weight = MinizincXorDifferentialModel._get_total_weight(result)
        parsed_result = self._parse_result(result, solver_name, total_weight, 'xor_differential')

        return parsed_result

    def find_min_of_max_xor_differential_between_permutation_and_key_schedule(
            self, fixed_values=[], solver_name=None
    ):
        self.constraint_permutation_and_key_schedule_separately_by_input_sizes()
        self.build_xor_differential_trail_model(-1, fixed_values)
        self._model_constraints.extend(self.objective_generator(strategy='min_max_key_schedule_permutation'))
        self._model_constraints.extend(self.weight_constraints())

        result = self.solve(solver_name=solver_name)
        total_weight = self._get_total_weight(result)
        parsed_result = self._parse_result(result, solver_name, total_weight, 'xor_differential')
        parsed_result['objective_strategy'] = 'min_max_key_schedule_permutation'

        return parsed_result

    def find_lowest_weight_xor_differential_trail(self, fixed_values=[], solver_name=None):
        """
        Find the lowest weight solution in a MiniZinc MILP model.

        INPUT:

        - ``fixed_values`` -- **list** (default: `[]`); disctionaries contains variables values whose output need to be
          fixed
        - ``solver_name`` -- **string** (default: `None`); the name of the solver (if needed)

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_xor_differential_model import MinizincXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=5, block_bit_size=32, key_bit_size=64)
            sage: minizinc = MinizincXorDifferentialModel(speck)
            sage: bit_positions = list(range(32))
            sage: bit_positions_key = list(range(64))
            sage: fixed_variables = [{ 'component_id': 'plaintext',
            ....:     'constraint_type': 'sum',
            ....:     'bit_positions': bit_positions,
            ....:     'operator': '>',
            ....:     'value': '0' }]
            sage: fixed_variables.append({ 'component_id': 'key',
            ....:     'constraint_type': 'sum',
            ....:     'bit_positions': bit_positions_key,
            ....:     'operator': '=',
            ....:     'value': '0' })
            sage: result = minizinc.find_lowest_weight_xor_differential_trail(
            ....:     solver_name='Xor', fixed_values=fixed_variables
            ....: )
            sage: result["total_weight"]
            9

            sage: minizinc = MinizincXorDifferentialModel(speck, [0, 0, 0, 0, 0])
            sage: result = minizinc.find_lowest_weight_xor_differential_trail(solver_name='Xor', fixed_values=fixed_variables)
            sage: result["total_weight"]
            9
        """
        self.build_xor_differential_trail_model(-1, fixed_values)
        self._model_constraints.extend(self.objective_generator())
        self._model_constraints.extend(self.weight_constraints())
        result = self.solve(solver_name=solver_name)
        total_weight = MinizincXorDifferentialModel._get_total_weight(result)
        parsed_result = self._parse_result(result, solver_name, total_weight, 'xor_differential')

        return parsed_result

    def init_constraints(self):
        output_string_for_cipher_inputs = []
        for i in range(len(self._cipher.inputs)):
            var_names_inputs = [self._cipher.inputs[i] + "_" + self.output_postfix + str(j)
                                for j in range(self._cipher.inputs_bit_size[i])]
            output_string_for_cipher_input = \
                "output [\"cipher_input:" + self._cipher.inputs[i] + "\" ++ show(" + \
                MinizincXorDifferentialModel._create_minizinc_1d_array_from_list(var_names_inputs) + ")++\"\\n\"];\n"
            output_string_for_cipher_inputs.append(output_string_for_cipher_input)

            for ii in range(len(var_names_inputs)):
                self._variables_list.extend([f'var {self.data_type}: {var_names_inputs[ii]};'])

        self._model_constraints.extend(self.connect_rounds())
        if self.sat_or_milp == "sat":
            from claasp.cipher_modules.models.sat.utils.mzn_predicates import get_word_operations
        else:
            from claasp.cipher_modules.models.milp.utils.mzn_predicates import get_word_operations

        self._model_constraints.extend([get_word_operations()])
        self._model_constraints.extend([
            f'output [ \"{self.cipher_id}, and window_size={self.window_size_list}\" ++ \"\\n\"];'])
        self._model_constraints.extend(output_string_for_cipher_inputs)

    def get_probability_vars_from_permutation(self):
        cipher_copy = deepcopy(self.cipher)
        cipher_permutation = cipher_copy.remove_key_schedule()
        permutation_components = cipher_permutation.get_all_components()
        probability_vars_from_permutation = []
        for permutation_component in permutation_components:
            if permutation_component.id.startswith('modadd') or permutation_component.id.startswith('modsub'):
                for probability_var in self.probability_vars:
                    if probability_var.startswith(f'p_{permutation_component.id}'):
                        probability_vars_from_permutation.append(probability_var)
        return probability_vars_from_permutation

    def get_probability_vars_from_key_schedule(self):
        key_schedule_ids = self.cipher.get_key_schedule_component_ids()
        key_schedule_prob_var_ids = []
        for key_schedule_id in key_schedule_ids:
            if key_schedule_id.startswith('modadd') or key_schedule_id.startswith('modsub'):
                for probability_var in self.probability_vars:
                    if probability_var.startswith(f'p_{key_schedule_id}'):
                        key_schedule_prob_var_ids.append(probability_var)

        return key_schedule_prob_var_ids

    def constraint_permutation_and_key_schedule_separately_by_input_sizes(self):
        key_schedule_probability_vars = list(set(self.get_probability_vars_from_key_schedule()))
        permutation_probability_vars = list(set(self.get_probability_vars_from_permutation()))
        modadd_key_schedule_concatenation_vars = "++".join(key_schedule_probability_vars)
        modadd_permutation_probability_vars = "++".join(permutation_probability_vars)
        key_index = self.cipher.inputs.index('key')
        plaintext_index = self.cipher.inputs.index('plaintext')
        key_input_bit_size = self.cipher.inputs_bit_size[key_index]
        plaintext_input_bit_size = self.cipher.inputs_bit_size[plaintext_index]

        self._model_constraints.append(f'sum({modadd_key_schedule_concatenation_vars}) <= {key_input_bit_size};')
        self._model_constraints.append(f'sum({modadd_permutation_probability_vars}) <= {plaintext_input_bit_size};')

    def objective_generator(self, strategy='min_all_probabilities'):
        if strategy == 'min_all_probabilities':
            objective_string = []
            modular_addition_concatenation = "++".join(self.probability_vars)
            objective_string.append(f'solve:: int_search({modular_addition_concatenation},'
                                    f' smallest, indomain_min, complete)')
            objective_string.append(f'minimize sum({modular_addition_concatenation});')
            self.mzn_output_directives.append(f'output ["Total_Probability: "++show(sum('
                                              f'{modular_addition_concatenation}))];')
        elif strategy == 'min_max_key_schedule_permutation':
            objective_string = []
            modular_addition_concatenation = "++".join(self.probability_vars)
            key_schedule_probability_vars = list(set(self.get_probability_vars_from_key_schedule()))
            permutation_probability_vars = list(set(self.get_probability_vars_from_permutation()))

            modadd_key_schedule_concatenation_vars = "++".join(key_schedule_probability_vars)
            modadd_permutation_probability_vars = "++".join(permutation_probability_vars)
            objective_string.append(f'solve:: int_search({modular_addition_concatenation},'
                                    f' smallest, indomain_min, complete)')

            objective_string.append(f'minimize max(sum({modadd_key_schedule_concatenation_vars}), sum({modadd_permutation_probability_vars}));')
        else:
            raise NotImplementedError("Strategy {strategy} no implemented")

        return objective_string

    def parse_probability_vars(self, result, solution):
        parsed_result = {}
        if result.status not in [Status.UNKNOWN, Status.UNSATISFIABLE, Status.ERROR]:

            for probability_var in self.probability_vars:
                lst_value = solution.__dict__[probability_var]
                parsed_result[probability_var] = {
                    'value': str(hex(int("".join(str(0) if str(x) in ["false", "0"] else str(1) for x in lst_value),
                                         2))),
                    'weight': sum(lst_value)
                }

        return parsed_result

    def satisfy_generator(self):
        objective_string = []
        modular_addition_concatenation = "++".join(self.probability_vars)
        objective_string.append(f'solve:: int_search({modular_addition_concatenation},'
                                f' smallest, indomain_min, complete)')
        objective_string.append(f'satisfy;')
        self.mzn_output_directives.append(f'output ["Total_Probability: "++show(sum('
                                          f'{modular_addition_concatenation}))];')

        return objective_string

    def weight_constraints(self, weight=None, operator="=", max_weight=None):
        """
        Return listS of variables and constraints that fix the total weight of the trail to a specific value.

        INPUT:

        - ``weight`` -- **integer** (default: `None`); the total weight of the trail
        - ``operator`` -- **str** (default: `=`)
        - ``max_weight`` -- **integer** (default: `None`)

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_xor_differential_model import MinizincXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: minizinc = MinizincXorDifferentialModel(speck)
            sage: minizinc.build_xor_differential_trail_model()
            sage: minizinc.weight_constraints(7)
            ['constraint sum(p_modadd_0_1_0++p_modadd_1_2_0++p_modadd_1_7_0++p_modadd_2_2_0++p_modadd_2_7_0) = 7;']
        """
        objective_string = []
        modular_addition_concatenation = "++".join(self.probability_vars)

        if weight is not None:
            objective_string.append(f'constraint sum({modular_addition_concatenation}) {operator} {weight};')
        if max_weight is not None:
            objective_string.append(f'constraint sum({modular_addition_concatenation}) < {max_weight};')

        if self.probability_weight_per_round:
            for index, mzn_probability_modadd_vars in enumerate(self.probability_modadd_vars_per_round):
                weights_per_round = self.probability_weight_per_round[index]
                min_weight_per_round = weights_per_round['min_bound']
                max_weight_per_round = weights_per_round['max_bound']
                mzn_probability_vars_per_round = "++".join(mzn_probability_modadd_vars)
                objective_string.append(f'constraint sum({mzn_probability_vars_per_round}) <= {max_weight_per_round};')
                objective_string.append(f'constraint sum({mzn_probability_vars_per_round}) >= {min_weight_per_round};')

        self.mzn_output_directives.append(f'output ["\\n"++"Probability: "++show(sum('
                                          f'{modular_addition_concatenation}))++"\\n"];')

        return objective_string

    def set_max_number_of_nonlinear_carries(self, max_number_of_nonlinear_carries):
        carries_vars = self.carries_vars
        concatenated_str = "array[1.."
        sizes_sum = sum(var['mzn_carry_array_size'] for var in carries_vars)
        concatenated_str += str(sizes_sum) + "] of var bool: concatenated_carries = "
        concatenated_str += " ++ ".join(var['mzn_carry_array_name'] for var in carries_vars) + ";\n"
        aux_x_definition_str = f'array[1..{sizes_sum}] of var bool: x_carries;\n'
        cluster_constraint = (f'constraint forall(i in 1..{sizes_sum}) ('
                              f'x_carries[i]<->(concatenated_carries[i] /\\ (i == 1 \\/ not concatenated_carries[i-1]))'
                              f');\n')

        self._variables_list.append(concatenated_str)
        self._variables_list.append(aux_x_definition_str)
        self._model_constraints.append(cluster_constraint)
        self._model_constraints.append(f'constraint sum(i in 1..{sizes_sum})' 
                                       f'(bool2int(x_carries[i])) <= {max_number_of_nonlinear_carries};\n')

    def set_max_number_of_carries_on_arx_cipher(self, max_number_of_carries):
        concatenated_str = " ++ ".join(var['mzn_carry_array_name'] for var in self.carries_vars)
        self._model_constraints.append(f'constraint sum({concatenated_str}) <= {max_number_of_carries};\n')

