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
from claasp.cipher_modules.models.milp.utils.config import SOLVER_DEFAULT
from claasp.cipher_modules.models.milp.milp_model import verbose_print
from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
from claasp.cipher_modules.models.milp.utils.generate_inequalities_for_wordwise_truncated_xor_with_n_input_bits import \
    update_dictionary_that_contains_wordwise_truncated_input_inequalities, \
    output_dictionary_that_contains_wordwise_truncated_input_inequalities
from claasp.cipher_modules.models.milp.utils.milp_name_mappings import MILP_WORDWISE_IMPOSSIBLE_AUTO, \
    MILP_WORDWISE_IMPOSSIBLE, MILP_BACKWARD_SUFFIX
from claasp.cipher_modules.models.milp.utils.utils import espresso_pos_to_constraints
from claasp.name_mappings import CIPHER_OUTPUT
from claasp.cipher_modules.models.milp.utils import utils as milp_utils


class MilpWordwiseImpossibleXorDifferentialModel(MilpWordwiseDeterministicTruncatedXorDifferentialModel):

    def __init__(self, cipher, n_window_heuristic=None):
        super().__init__(cipher, n_window_heuristic)
        self._forward_cipher = None
        self._backward_cipher = None
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
            sage: milp.build_wordwise_impossible_xor_differential_trail_model()
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
            sage: milp.add_constraints_to_build_in_sage_milp_class(1, get_single_key_scenario_format_for_fixed_values(aes))

        """
        verbose_print("Building model in progress ...")

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
            incompatibility_constraint = [forward_vars[inconsistent_index] + backward_vars[inconsistent_index] <= 2]
            constraints.extend(milp_utils.milp_if_then(inconsistent_vars[inconsistent_index], incompatibility_constraint, self._model.get_max(x_class) * 2))

        # output is fixed
        cipher_output = [c for c in self._cipher.get_all_components() if c.type == CIPHER_OUTPUT][0]
        _, cipher_output_ids = cipher_output._get_wordwise_input_output_linked_class(self)
        constraints.extend([x_class[id] <= 1 for id in cipher_output_ids] + [sum([x_class[id] for id in cipher_output_ids]) >= 1])

        for constraint in constraints:
            mip.add_constraint(constraint)

        # unknown patterns are tuples of the form (1,x) (i.e pattern = 2 or 3)
        _, forward_output_id_tuple = forward_output._get_wordwise_input_output_linked_class_tuples(self)
        mip.add_constraint(
        p["number_of_unknown_patterns"] == sum(x[output_msb] for output_msb in [id[0] for id in forward_output_id_tuple]))


    def add_constraints_to_build_fully_automatic_model_in_sage_milp_class(self, fixed_bits=[], fixed_words=[]):
        """
        Take the constraints contained in self._model_constraints and add them to the build-in sage class.

        INPUT:

        - ``model_type`` -- **string**; the model to solve
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
            sage: milp.add_constraints_to_build_fully_automatic_model_in_sage_milp_class(get_single_key_scenario_format_for_fixed_values(aes))

        """
        verbose_print("Building model in progress ...")

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
        constraints = []
        forward_output = [c for c in self._forward_cipher.get_all_components() if c.type == CIPHER_OUTPUT][0]
        all_inconsistent_vars = []
        backward_round_outputs = [c for c in self._backward_cipher.get_all_components() if
                                  c.description == ['round_output'] and set(c.input_id_links) != {
                                      forward_output.id + MILP_BACKWARD_SUFFIX}]

        for backward_round_output in backward_round_outputs:
            output_size = backward_round_output.output_bit_size // self.word_size
            _, output_ids = backward_round_output._get_wordwise_input_output_linked_class(self)

            backward_vars = [x_class[id] for id in output_ids]
            forward_vars = [x_class["_".join(id.split("_")[:-4] + id.split("_")[-3:])] for id in output_ids]
            inconsistent_vars = [x[f"{backward_round_output.id}_inconsistent_{_}"] for _ in range(output_size)]
            all_inconsistent_vars += inconsistent_vars

            for inconsistent_index in range(output_size):
                incompatibility_constraint = [forward_vars[inconsistent_index] + backward_vars[inconsistent_index] <= 2]
                constraints.extend(milp_utils.milp_if_then(inconsistent_vars[inconsistent_index], incompatibility_constraint, self._model.get_max(x_class) * 2))

        # decryption input is fixed and non-zero
        constraints.extend(
            [x_class[id] <= 1 for id in self._backward_cipher.inputs] + [sum([x_class[id] for id in self._backward_cipher.inputs]) >= 1])

        constraints.extend([sum(all_inconsistent_vars) == 1])

        for constraint in constraints:
            mip.add_constraint(constraint)

        # unknown patterns are tuples of the form (1,x) (i.e pattern = 2 or 3)
        _, forward_output_id_tuple = forward_output._get_wordwise_input_output_linked_class_tuples(self)
        mip.add_constraint(
        p["number_of_unknown_patterns"] == sum(x[output_msb] for output_msb in [id[0] for id in forward_output_id_tuple]))


    def find_one_wordwise_impossible_xor_differential_trail(self, middle_round=None, fixed_bits=[], fixed_words=[], solver_name=SOLVER_DEFAULT):
        """
        Returns one wordwise impossible XOR differential trail.

        INPUTS:

        - ``solver_name`` -- *str*, the solver to call
        - ``middle_round`` -- **integer**; the round number for which the incompatibility occurs
        - ``fixed_bits`` -- *list of dict*, the bit variables to be fixed in standard format
        - ``fixed_words`` -- *list of dict*, the word variables to be fixed in standard format

        EXAMPLE::

            sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_impossible_xor_differential_model import MilpWordwiseImpossibleXorDifferentialModel
            sage: milp = MilpWordwiseImpossibleXorDifferentialModel(aes)
            sage: trail = milp.find_one_wordwise_impossible_xor_differential_trail(1, get_single_key_scenario_format_for_fixed_values(aes))

        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_in_sage_milp_class(middle_round, fixed_bits, fixed_words)
        end = time.time()
        building_time = end - start
        solution = self.solve(MILP_WORDWISE_IMPOSSIBLE, solver_name)
        solution['building_time'] = building_time

        return solution

    def find_one_wordwise_impossible_xor_differential_trail_with_fully_automatic_model(self, fixed_bits=[], fixed_words=[], solver_name=SOLVER_DEFAULT):
        """
        Returns one wordwise impossible XOR differential trail.

        INPUTS:

        - ``solver_name`` -- *str*, the solver to call
        - ``fixed_bits`` -- *list of dict*, the bit variables to be fixed in standard format
        - ``fixed_words`` -- *list of dict*, the word variables to be fixed in standard format

        EXAMPLE::

            sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_impossible_xor_differential_model import MilpWordwiseImpossibleXorDifferentialModel
            sage: milp = MilpWordwiseImpossibleXorDifferentialModel(aes)
            sage: trail = milp.find_one_wordwise_impossible_xor_differential_trail_with_fully_automatic_model(get_single_key_scenario_format_for_fixed_values(aes))

        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_fully_automatic_model_in_sage_milp_class(fixed_bits, fixed_words)
        end = time.time()
        building_time = end - start
        solution = self.solve(MILP_WORDWISE_IMPOSSIBLE_AUTO, solver_name)
        solution['building_time'] = building_time

        return solution