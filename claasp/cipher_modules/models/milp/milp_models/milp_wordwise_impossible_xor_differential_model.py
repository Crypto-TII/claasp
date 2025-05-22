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

from claasp.cipher_modules.inverse_cipher import get_key_schedule_component_ids
from claasp.cipher_modules.models.milp.solvers import SOLVER_DEFAULT
from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
from claasp.cipher_modules.models.milp.utils.milp_name_mappings import MILP_WORDWISE_IMPOSSIBLE_AUTO, \
    MILP_WORDWISE_IMPOSSIBLE, MILP_BACKWARD_SUFFIX, MILP_BUILDING_MESSAGE
from claasp.name_mappings import CIPHER_OUTPUT, INPUT_KEY
from claasp.cipher_modules.models.milp.utils import utils as milp_utils, milp_truncated_utils


class MilpWordwiseImpossibleXorDifferentialModel(MilpWordwiseDeterministicTruncatedXorDifferentialModel):

    def __init__(self, cipher, n_window_heuristic=None, verbose=False):
        super().__init__(cipher, n_window_heuristic, verbose)
        self._forward_cipher = None
        self._backward_cipher = None
        self._incompatible_components = None

    def build_wordwise_impossible_xor_differential_trail_model(self, fixed_bits=[], fixed_words=[]):
        """
        Build the model for the search of wordwise impossible XOR differential trails.

        INPUTS:

        - ``fixed_bits`` -- *list of dict*, the bit variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)
        - ``fixed_words`` -- *list of dict*, the word variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_impossible_xor_differential_model import MilpWordwiseImpossibleXorDifferentialModel
            sage: milp = MilpWordwiseImpossibleXorDifferentialModel(aes)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp._forward_cipher = aes.get_partial_cipher(0, 0, keep_key_schedule=True)
            sage: backward_cipher = milp._cipher.cipher_partial_inverse(1, 1, keep_key_schedule=False)
            sage: milp._backward_cipher = backward_cipher.add_suffix_to_components("_backward", [backward_cipher.get_all_components_ids()[-1]])
            sage: milp.build_wordwise_impossible_xor_differential_trail_model() # doctest: +SKIP
            ...
        """
        cipher_list = [self._forward_cipher, self._backward_cipher]
        return self.build_wordwise_deterministic_truncated_xor_differential_trail_model(fixed_bits, fixed_words, cipher_list)

    def add_constraints_to_build_in_sage_milp_class(self, middle_round=None, fixed_bits=[], fixed_words=[]):
        """
        Take the constraints contained in self._model_constraints and add them to the build-in sage class.

        INPUT:

        - ``model_type`` -- **string**; the model to solve
        - ``middle_round`` -- **integer**; the round number for which the incompatibility occurs
        - ``fixed_bits`` -- *list of dict*, the bit variables to be fixed in standard format
        - ``fixed_words`` -- *list of dict*, the word variables to be fixed in standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_impossible_xor_differential_model import MilpWordwiseImpossibleXorDifferentialModel
            sage: milp = MilpWordwiseImpossibleXorDifferentialModel(aes)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp.add_constraints_to_build_in_sage_milp_class(1, get_single_key_scenario_format_for_fixed_values(aes)) # doctest: +SKIP

        """
        self._verbose_print(MILP_BUILDING_MESSAGE)

        mip = self._model
        x = self._binary_variable
        x_class = self._trunc_wordvar
        p = self._integer_variable

        if middle_round is None:
            middle_round = self._cipher.number_of_rounds // 2

        assert middle_round < self._cipher.number_of_rounds

        self._forward_cipher = self._cipher.get_partial_cipher(0, middle_round - 1, keep_key_schedule=True)
        backward_cipher = self._cipher.cipher_partial_inverse(middle_round, self._cipher.number_of_rounds - 1, keep_key_schedule=False)
        self._backward_cipher = backward_cipher.add_suffix_to_components(MILP_BACKWARD_SUFFIX, [backward_cipher.get_all_components_ids()[-1]])

        self.build_wordwise_impossible_xor_differential_trail_model(fixed_bits, fixed_words)
        for index, constraint in enumerate(self._model_constraints):
            mip.add_constraint(constraint)

        # finding incompatibility
        constraints = []
        forward_output = [c for c in self._forward_cipher.get_all_components() if c.type == CIPHER_OUTPUT][0]
        output_size = forward_output.output_bit_size // self.word_size

        _, output_ids = forward_output._get_wordwise_input_output_linked_class(self)

        forward_vars = [x_class[id] for id in output_ids]
        backward_vars = [x_class["_".join(id.split("_")[:-3] + ["backward"] + id.split("_")[-3:])] for id in output_ids]

        inconsistent_vars = [x[f"{forward_output.id}_inconsistent_{_}"] for _ in range(output_size)]

        constraints.extend([sum(inconsistent_vars) == 1])
        for inconsistent_index in range(output_size):
            incompatibility_constraints = [forward_vars[inconsistent_index] + backward_vars[inconsistent_index] <= 2]
            dummy = x[f'dummy_incompatibility_{x[forward_vars[inconsistent_index]]}_or_{x[backward_vars[inconsistent_index]]}_is_0']
            incompatibility_constraints += [forward_vars[inconsistent_index] <= self._model.get_max(x_class) * (1 - dummy)]
            incompatibility_constraints += [backward_vars[inconsistent_index] <= self._model.get_max(x_class) * dummy]
            constraints.extend(milp_utils.milp_if_then(inconsistent_vars[inconsistent_index], incompatibility_constraints, self._model.get_max(x_class) * 2))

        # output is fixed
        cipher_output = [c for c in self._cipher.get_all_components() if c.type == CIPHER_OUTPUT][0]
        _, cipher_output_ids = cipher_output._get_wordwise_input_output_linked_class(self)
        constraints.extend([x_class[id] <= 2 for id in cipher_output_ids] + [sum([x_class[id] for id in cipher_output_ids]) >= 1])

        for constraint in constraints:
            mip.add_constraint(constraint)

        # unknown patterns are tuples of the form (1,x) (i.e pattern = 2 or 3)
        _, forward_output_id_tuple = forward_output._get_wordwise_input_output_linked_class_tuples(self)
        mip.add_constraint(
        p["number_of_unknown_patterns"] == sum(x[output_msb] for output_msb in [id[0] for id in forward_output_id_tuple]))


    def add_constraints_to_build_in_sage_milp_class_with_chosen_incompatible_components(self, component_id_list=None, fixed_bits=[], fixed_words=[]):
        """
        Take the constraints contained in self._model_constraints and add them to the build-in sage class.

        INPUT:

        - ``model_type`` -- **string**; the model to solve
        - ``component_id_list`` -- **list** (default: `None`); list of component IDs where incompatibility occurs
        - ``fixed_bits`` -- *list of dict*, the bit variables to be fixed in standard format
        - ``fixed_words`` -- *list of dict*, the word variables to be fixed in standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_impossible_xor_differential_model import MilpWordwiseImpossibleXorDifferentialModel
            sage: milp = MilpWordwiseImpossibleXorDifferentialModel(aes)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp.add_constraints_to_build_in_sage_milp_class_with_chosen_incompatible_components(["intermediate_output_0_37"], get_single_key_scenario_format_for_fixed_values(aes)) # doctest: +SKIP

        """
        self._verbose_print(MILP_BUILDING_MESSAGE)

        mip = self._model
        x = self._binary_variable
        x_class = self._trunc_wordvar
        p = self._integer_variable

        if component_id_list == None:
            return self.add_constraints_to_build_in_sage_milp_class(fixed_bits=fixed_bits, fixed_words=fixed_words)

        assert set(component_id_list) <= set(self._cipher.get_all_components_ids()) - set(get_key_schedule_component_ids(self._cipher))

        middle_round_numbers = [self._cipher.get_round_from_component_id(id) for id in component_id_list]

        assert len(set(middle_round_numbers)) == 1

        middle_round_number = middle_round_numbers[0]

        if len(component_id_list) == 1 and self._cipher.get_component_from_id(component_id_list[0]).description == [
            'round_output']:
            return self.add_constraints_to_build_in_sage_milp_class(middle_round_number + 1, fixed_bits, fixed_words)

        self._forward_cipher = self._cipher.get_partial_cipher(0, middle_round_number, keep_key_schedule=True)
        backward_cipher = self._cipher.cipher_partial_inverse(middle_round_number, self._cipher.number_of_rounds - 1, keep_key_schedule=False)

        self._incompatible_components = component_id_list
        backward_last_round_components = set(backward_cipher._rounds.round_at(self._cipher.number_of_rounds - 1 - middle_round_number).get_components_ids() + [backward_cipher.get_all_components_ids()[-1]])
        input_id_links_of_chosen_components = [_ for c in
                                               [backward_cipher.get_component_from_id(id) for id in component_id_list]
                                               for _ in c.input_id_links]
        round_input_id_links_of_chosen_components = [backward_cipher.get_round_from_component_id(id) for id in
                                                     input_id_links_of_chosen_components]
        links_round = [_ for r in round_input_id_links_of_chosen_components for _ in
                       backward_cipher._rounds.round_at(r).get_components_ids()]
        self._backward_cipher = backward_cipher.add_suffix_to_components(MILP_BACKWARD_SUFFIX,
                                                                         backward_last_round_components | set(
                                                                             links_round))


        self.build_wordwise_impossible_xor_differential_trail_model(fixed_bits, fixed_words)

        # finding incompatibility
        incompatibility_constraints = []

        for id in component_id_list:
            forward_component = self._cipher.get_component_from_id(id)
            output_size = forward_component.output_bit_size // self.word_size
            _, output_ids = forward_component._get_wordwise_input_output_linked_class(self)
            forward_vars = [x_class[id] for id in output_ids]

            backward_component = self._backward_cipher.get_component_from_id(id + f"{MILP_BACKWARD_SUFFIX}")
            input_ids, _ = backward_component._get_wordwise_input_output_linked_class(self)
            backward_vars = [x_class[id] for id in input_ids if INPUT_KEY not in id]
            inconsistent_vars = [x[f"{forward_component.id}_inconsistent_{_}"] for _ in range(output_size)]

            # for multiple input components such as the XOR, ensures compatibility occurs on the correct branch
            for index, input_id in enumerate(["_".join(i.split("_")[:-1]) if MILP_BACKWARD_SUFFIX in i else i for i in
                                              backward_component.input_id_links]):
                if INPUT_KEY not in input_id and self._cipher.get_component_from_id(input_id).input_id_links == [id]:
                    backward_vars = [x_class[f'{input_id}_{pos}'] for pos in
                                     backward_component.input_bit_positions[index]]

            incompatibility_constraints.extend([sum(inconsistent_vars) == 1])
            for inconsistent_index in range(output_size):
                incompatibility_constraint = [forward_vars[inconsistent_index] + backward_vars[inconsistent_index] <= 2]
                incompatibility_constraints.extend(milp_utils.milp_if_then(inconsistent_vars[inconsistent_index], incompatibility_constraint, self._model.get_max(x_class) * 2))

        # output is fixed
        cipher_output = [c for c in self._cipher.get_all_components() if c.type == CIPHER_OUTPUT][0]
        _, cipher_output_ids = cipher_output._get_wordwise_input_output_linked_class(self)
        incompatibility_constraints.extend([x_class[id] <= 1 for id in cipher_output_ids] + [sum([x_class[id] for id in cipher_output_ids]) >= 1])

        # unknown patterns are tuples of the form (1,x) (i.e pattern = 2 or 3)
        _, forward_output_id_tuple = forward_component._get_wordwise_input_output_linked_class_tuples(self)
        optimization_constraint = [p["number_of_unknown_patterns"] == sum(x[output_msb] for output_msb in [id[0] for id in forward_output_id_tuple])]

        for constraint in self._model_constraints + incompatibility_constraints + optimization_constraint:
            mip.add_constraint(constraint)
    def add_constraints_to_build_fully_automatic_model_in_sage_milp_class(self, fixed_bits=[], fixed_words=[], include_all_components=False):
        """
        Take the constraints contained in self._model_constraints and add them to the build-in sage class.

        INPUT:

        - ``model_type`` -- **string**; the model to solve
        - ``fixed_bits`` -- *list of dict*, the bit variables to be fixed in standard format
        - ``fixed_words`` -- *list of dict*, the word variables to be fixed in standard format
        - ``include_all_components`` -- **boolean** (default: `False`); when set to `True`, every component output can be a source
          of incompatibility; otherwise, only round outputs are considered

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_impossible_xor_differential_model import MilpWordwiseImpossibleXorDifferentialModel
            sage: milp = MilpWordwiseImpossibleXorDifferentialModel(aes)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp.add_constraints_to_build_fully_automatic_model_in_sage_milp_class(get_single_key_scenario_format_for_fixed_values(aes)) # doctest: +SKIP

        """
        self._verbose_print(MILP_BUILDING_MESSAGE)

        mip = self._model
        x = self._binary_variable
        x_class = self._trunc_wordvar
        p = self._integer_variable

        self._forward_cipher = self._cipher
        self._backward_cipher = self._cipher.cipher_inverse().add_suffix_to_components(MILP_BACKWARD_SUFFIX)

        self.build_wordwise_impossible_xor_differential_trail_model(fixed_bits, fixed_words)
        for index, constraint in enumerate(self._model_constraints):
            mip.add_constraint(constraint)

        # finding incompatibility
        constraints = milp_truncated_utils.generate_all_incompatibility_constraints_for_fully_automatic_model(self, MILP_WORDWISE_IMPOSSIBLE_AUTO, x, x_class, include_all_components)

        # decryption input is fixed and non-zero
        constraints.extend(
            [x_class[id] <= 1 for id in self._backward_cipher.inputs] + [sum([x_class[id] for id in self._backward_cipher.inputs]) >= 1])

        for constraint in constraints:
            mip.add_constraint(constraint)

        # unknown patterns are tuples of the form (1,x) (i.e pattern = 2 or 3)
        forward_output = [c for c in self._forward_cipher.get_all_components() if c.type == CIPHER_OUTPUT][0]
        _, forward_output_id_tuple = forward_output._get_wordwise_input_output_linked_class_tuples(self)
        mip.add_constraint(
        p["number_of_unknown_patterns"] == sum(x[output_msb] for output_msb in [id[0] for id in forward_output_id_tuple]))


    def find_one_wordwise_impossible_xor_differential_trail(self, middle_round=None, fixed_bits=[], fixed_words=[], solver_name=SOLVER_DEFAULT, external_solver_name=None):
        """
        Returns one wordwise impossible XOR differential trail.

        INPUTS:

        - ``solver_name`` -- *str*, the solver to call
        - ``middle_round`` -- **integer**; the round number for which the incompatibility occurs
        - ``fixed_bits`` -- *list of dict*, the bit variables to be fixed in standard format
        - ``fixed_words`` -- *list of dict*, the word variables to be fixed in standard format
        - ``external_solver_name`` -- **string** (default: None); if specified, the library will write the internal Sagemath MILP model as a .lp file and solve it outside of Sagemath, using the external solver.

        EXAMPLE::

            sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_impossible_xor_differential_model import MilpWordwiseImpossibleXorDifferentialModel
            sage: milp = MilpWordwiseImpossibleXorDifferentialModel(aes)
            sage: trail = milp.find_one_wordwise_impossible_xor_differential_trail(1, get_single_key_scenario_format_for_fixed_values(aes)) # doctest: +SKIP

        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        self._verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_in_sage_milp_class(middle_round, fixed_bits, fixed_words)
        end = time.time()
        building_time = end - start
        solution = self.solve(MILP_WORDWISE_IMPOSSIBLE, solver_name, external_solver_name)
        solution['building_time'] = building_time

        return solution

    def find_one_wordwise_impossible_xor_differential_trail_with_chosen_components(self, component_id_list, fixed_bits=[], fixed_words=[], solver_name=SOLVER_DEFAULT, external_solver_name=None):
        """
        Returns one wordwise impossible XOR differential trail.

        INPUTS:

        - ``solver_name`` -- *str*, the solver to call
        - ``component_id_list`` -- **str**; the list of component ids for which the incompatibility occurs
        - ``fixed_bits`` -- *list of dict*, the bit variables to be fixed in standard format
        - ``fixed_words`` -- *list of dict*, the word variables to be fixed in standard format
        - ``external_solver_name`` -- **string** (default: None); if specified, the library will write the internal Sagemath MILP model as a .lp file and solve it outside of Sagemath, using the external solver.

        EXAMPLE::

            sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_impossible_xor_differential_model import MilpWordwiseImpossibleXorDifferentialModel
            sage: milp = MilpWordwiseImpossibleXorDifferentialModel(aes)
            sage: trail = milp.find_one_wordwise_impossible_xor_differential_trail_with_chosen_components(['mix_column_0_21'], get_single_key_scenario_format_for_fixed_values(aes)) # doctest: +SKIP

        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        self._verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_in_sage_milp_class_with_chosen_incompatible_components(component_id_list,
                                                                                             fixed_bits, fixed_words)
        end = time.time()
        building_time = end - start
        solution = self.solve(MILP_WORDWISE_IMPOSSIBLE, solver_name, external_solver_name)
        solution['building_time'] = building_time

        return solution

    def find_one_wordwise_impossible_xor_differential_trail_with_fully_automatic_model(self, fixed_bits=[], fixed_words=[], include_all_components=False, solver_name=SOLVER_DEFAULT, external_solver_name=None):
        """
        Returns one wordwise impossible XOR differential trail.

        INPUTS:

        - ``solver_name`` -- *str*, the solver to call
        - ``fixed_bits`` -- *list of dict*, the bit variables to be fixed in standard format
        - ``fixed_words`` -- *list of dict*, the word variables to be fixed in standard format
        - ``include_all_components`` -- **boolean** (default: `False`); when set to `True`, every component output can be a source
          of incompatibility; otherwise, only round outputs are considered
        - ``external_solver_name`` -- **string** (default: None); if specified, the library will write the internal Sagemath MILP model as a .lp file and solve it outside of Sagemath, using the external solver.

        EXAMPLE::

            sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_impossible_xor_differential_model import MilpWordwiseImpossibleXorDifferentialModel
            sage: milp = MilpWordwiseImpossibleXorDifferentialModel(aes)
            sage: trail = milp.find_one_wordwise_impossible_xor_differential_trail_with_fully_automatic_model(get_single_key_scenario_format_for_fixed_values(aes)) # doctest: +SKIP

        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        self._verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_fully_automatic_model_in_sage_milp_class(fixed_bits, fixed_words, include_all_components=include_all_components)
        end = time.time()
        building_time = end - start
        solution = self.solve(MILP_WORDWISE_IMPOSSIBLE_AUTO, solver_name, external_solver_name)
        solution['building_time'] = building_time

        return solution

    def _get_component_values(self, objective_variables, components_variables):
        return  milp_utils._get_component_values_for_impossible_models(self, objective_variables, components_variables)

    def _parse_solver_output(self):
        mip = self._model
        if self._forward_cipher == self._cipher:
            components_variables = mip.get_values(self._trunc_wordvar)
            objective_variables = mip.get_values(self._binary_variable)
            inconsistent_component_var = \
                [i for i in objective_variables.keys() if objective_variables[i] > 0 and "inconsistent" in i][0]
            objective_value = "_".join(inconsistent_component_var.split("_")[:-3])
        else:
            components_variables = mip.get_values(self._trunc_wordvar)
            objective_variables = mip.get_values(self._integer_variable)
            objective_value = objective_variables["number_of_unknown_patterns"]
        components_values = self._get_component_values(objective_variables, components_variables)

        return objective_value, components_values

    def _get_component_value_weight(self, component_id, components_variables):

        wordsize = self._word_size
        if component_id in self._cipher.inputs:
            output_size = self._cipher.inputs_bit_size[self._cipher.inputs.index(component_id)] // wordsize
        elif self._forward_cipher != self._cipher and component_id.endswith(
                MILP_BACKWARD_SUFFIX):
            component = self._backward_cipher.get_component_from_id(component_id)
            output_size = component.output_bit_size // wordsize
        elif self._forward_cipher == self._cipher and component_id.endswith(
                MILP_BACKWARD_SUFFIX):
            if component_id in self._backward_cipher.inputs:
                output_size = self._backward_cipher.inputs_bit_size[
                                  self._backward_cipher.inputs.index(component_id)] // wordsize
            else:
                component = self._backward_cipher.get_component_from_id(component_id)
                output_size = component.output_bit_size // wordsize
        else:
            component = self._cipher.get_component_from_id(component_id)
            output_size = component.output_bit_size // wordsize
        suffix_dict = {"_class": output_size}
        final_output = self._get_final_output(component_id, components_variables, suffix_dict)
        if len(final_output) == 1:
            final_output = final_output[0]

        return final_output
