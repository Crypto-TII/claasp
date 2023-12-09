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
from claasp.cipher_modules.models.milp.utils.config import SOLVER_DEFAULT
from claasp.cipher_modules.models.milp.milp_model import verbose_print
from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import \
    MilpBitwiseDeterministicTruncatedXorDifferentialModel
from claasp.cipher_modules.models.milp.utils.milp_name_mappings import MILP_BITWISE_IMPOSSIBLE, \
    MILP_BITWISE_IMPOSSIBLE_AUTO, MILP_BACKWARD_SUFFIX, MILP_BUILDING_MESSAGE
from claasp.name_mappings import CIPHER_OUTPUT, INPUT_KEY
from claasp.cipher_modules.models.milp.utils import utils as milp_utils


class MilpBitwiseImpossibleXorDifferentialModel(MilpBitwiseDeterministicTruncatedXorDifferentialModel):

    def __init__(self, cipher, n_window_heuristic=None):
        super().__init__(cipher, n_window_heuristic)
        self._forward_cipher = None
        self._backward_cipher = None
        self._incompatible_components = None
    def build_bitwise_impossible_xor_differential_trail_model(self, fixed_variables=[]):
        """
        Build the model for the search of bitwise impossible XOR differential trails.

        INPUTS:

        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in
          standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_impossible_xor_differential_model import MilpBitwiseImpossibleXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=2)
            sage: milp = MilpBitwiseImpossibleXorDifferentialModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp._forward_cipher = speck.get_partial_cipher(0, 1, keep_key_schedule=True)
            sage: backward_cipher = milp._cipher.cipher_partial_inverse(1, 1, keep_key_schedule=False)
            sage: milp._backward_cipher = backward_cipher.add_suffix_to_components("_backward", [backward_cipher.get_all_components_ids()[-1]])
            sage: milp.build_bitwise_impossible_xor_differential_trail_model()
            ...
        """

        component_list = self._forward_cipher.get_all_components() + self._backward_cipher.get_all_components()
        return self.build_bitwise_deterministic_truncated_xor_differential_trail_model(fixed_variables, component_list)

    def add_constraints_to_build_in_sage_milp_class(self, middle_round=None, fixed_variables=[]):
        """
        Take the constraints contained in self._model_constraints and add them to the build-in sage class.

        INPUT:

        - ``model_type`` -- **string**; the model to solve
        - ``middle_round`` -- **integer**; the round number for which the incompatibility occurs
        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in
          standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_impossible_xor_differential_model import MilpBitwiseImpossibleXorDifferentialModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpBitwiseImpossibleXorDifferentialModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp.add_constraints_to_build_in_sage_milp_class(1)

        """
        verbose_print(MILP_BUILDING_MESSAGE)
        mip = self._model
        x = self._binary_variable
        x_class = self._trunc_binvar
        p = self._integer_variable

        if middle_round is None:
            middle_round = self._cipher.number_of_rounds // 2
        assert middle_round < self._cipher.number_of_rounds

        self._forward_cipher = self._cipher.get_partial_cipher(0, middle_round - 1, keep_key_schedule=True)
        backward_cipher = self._cipher.cipher_partial_inverse(middle_round, self._cipher.number_of_rounds - 1,
                                                              keep_key_schedule=False)
        self._backward_cipher = backward_cipher.add_suffix_to_components(MILP_BACKWARD_SUFFIX,
                                                                         [backward_cipher.get_all_components_ids()[-1]])

        self.build_bitwise_impossible_xor_differential_trail_model(fixed_variables)
        for index, constraint in enumerate(self._model_constraints):
            mip.add_constraint(constraint)

        # finding incompatibility
        constraints = []
        forward_output = [c for c in self._forward_cipher.get_all_components() if c.type == CIPHER_OUTPUT][0]
        output_bit_size = forward_output.output_bit_size
        _, output_ids = forward_output._get_input_output_variables()

        forward_vars = [x_class[id] for id in output_ids]
        backward_vars = [x_class["_".join(id.split("_")[:-1] + ["backward"] + [id.split("_")[-1]])] for id in
                         output_ids]
        inconsistent_vars = [x[f"{forward_output.id}_inconsistent_{_}"] for _ in range(output_bit_size)]

        constraints.extend([sum(inconsistent_vars) == 1])
        for inconsistent_index in range(output_bit_size):
            incompatibility_constraint = [forward_vars[inconsistent_index] + backward_vars[inconsistent_index] == 1]
            constraints.extend(
                milp_utils.milp_if_then(inconsistent_vars[inconsistent_index], incompatibility_constraint,
                                        self._model.get_max(x_class) * 2))
        for constraint in constraints:
            mip.add_constraint(constraint)

        _, forward_output_id_tuples = forward_output._get_input_output_variables_tuples()
        mip.add_constraint(p["number_of_unknown_patterns"] == sum(
            x[output_msb] for output_msb in [id[0] for id in forward_output_id_tuples]))

    def add_constraints_to_build_in_sage_milp_class_with_chosen_incompatible_components(self, component_id_list=None,
                                                                          fixed_variables=[]):
        """
        Take the constraints contained in self._model_constraints and add them to the build-in sage class.

        INPUT:

        - ``model_type`` -- **string**; the model to solve
        - ``component_id_list`` -- **list** (default: `None`); list of component IDs where incompatibility occurs
        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in
          standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_impossible_xor_differential_model import MilpBitwiseImpossibleXorDifferentialModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpBitwiseImpossibleXorDifferentialModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp.add_constraints_to_build_in_sage_milp_class_with_chosen_incompatible_components(["rot_1_6"])

        """

        verbose_print(MILP_BUILDING_MESSAGE)
        mip = self._model
        x = self._binary_variable
        x_class = self._trunc_binvar
        p = self._integer_variable

        if component_id_list == None:
            return self.add_constraints_to_build_in_sage_milp_class(fixed_variables=fixed_variables)
        assert set(component_id_list) <= set(self._cipher.get_all_components_ids()) - set(get_key_schedule_component_ids(self._cipher))

        middle_round_numbers = [self._cipher.get_round_from_component_id(id) for id in component_id_list]

        assert len(set(middle_round_numbers)) == 1

        middle_round_number = middle_round_numbers[0]

        if len(component_id_list) == 1 and self._cipher.get_component_from_id(component_id_list[0]).description == ['round_output']:
            return self.add_constraints_to_build_in_sage_milp_class(middle_round_number + 1, fixed_variables)

        self._forward_cipher = self._cipher.get_partial_cipher(0, middle_round_number, keep_key_schedule=True)
        backward_cipher = self._cipher.cipher_partial_inverse(middle_round_number, self._cipher.number_of_rounds - 1,
                                                              keep_key_schedule=False)

        self._incompatible_components = component_id_list

        backward_last_round_components = set(backward_cipher._rounds.round_at(self._cipher.number_of_rounds - 1 - middle_round_number).get_components_ids() + [backward_cipher.get_all_components_ids()[-1]])
        input_id_links_of_chosen_components = [_ for c in [backward_cipher.get_component_from_id(id) for id in component_id_list] for _ in c.input_id_links]
        round_input_id_links_of_chosen_components = [backward_cipher.get_round_from_component_id(id) for id in input_id_links_of_chosen_components]
        links_round = [_ for r in round_input_id_links_of_chosen_components for _ in backward_cipher._rounds.round_at(r).get_components_ids()]
        self._backward_cipher = backward_cipher.add_suffix_to_components(MILP_BACKWARD_SUFFIX, backward_last_round_components | set(links_round))
        self.build_bitwise_impossible_xor_differential_trail_model(fixed_variables)


        for index, constraint in enumerate(self._model_constraints):
            mip.add_constraint(constraint)

        # finding incompatibility
        constraints = []

        for id in component_id_list:
            forward_component = self._cipher.get_component_from_id(id)
            output_bit_size = forward_component.output_bit_size
            _, output_ids = forward_component._get_input_output_variables()
            forward_vars = [x_class[id] for id in output_ids]

            backward_component = self._backward_cipher.get_component_from_id(id + f"{MILP_BACKWARD_SUFFIX}")
            input_ids, _ = backward_component._get_input_output_variables()
            backward_vars = [x_class[id] for id in input_ids if INPUT_KEY not in id]
            inconsistent_vars = [x[f"{forward_component.id}_inconsistent_{_}"] for _ in range(output_bit_size)]

            # for multiple input components such as the XOR, ensures compatibility occurs on the correct branch
            for index, input_id in enumerate(["_".join(i.split("_")[:-1]) if MILP_BACKWARD_SUFFIX in i else i for i in backward_component.input_id_links]):
                if INPUT_KEY not in input_id and self._cipher.get_component_from_id(input_id).input_id_links == [id]:
                    backward_vars = [x_class[f'{input_id}_{pos}'] for pos in backward_component.input_bit_positions[index]]

            constraints.extend([sum(inconsistent_vars) == 1])
            for inconsistent_index in range(output_bit_size):
                incompatibility_constraint = [forward_vars[inconsistent_index] + backward_vars[inconsistent_index] == 1]
                constraints.extend(
                    milp_utils.milp_if_then(inconsistent_vars[inconsistent_index], incompatibility_constraint,
                                            self._model.get_max(x_class) * 2))

        for constraint in constraints:
            mip.add_constraint(constraint)

        _, forward_output_id_tuples = forward_component._get_input_output_variables_tuples()
        mip.add_constraint(p["number_of_unknown_patterns"] == sum(
            x[output_msb] for output_msb in [id[0] for id in forward_output_id_tuples]))

    def add_constraints_to_build_fully_automatic_model_in_sage_milp_class(self, fixed_variables=[], include_all_components=False):

        """
        Take the constraints contained in self._model_constraints and add them to the build-in sage class.

        INPUT:

        - ``model_type`` -- **string**; the model to solve
        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in
          standard format
        - ``include_all_components`` -- **boolean** (default: `False`); when set to `True`, every component output can be a source
          of incompatibility; otherwise, only round outputs are considered

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_impossible_xor_differential_model import MilpBitwiseImpossibleXorDifferentialModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpBitwiseImpossibleXorDifferentialModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp.add_constraints_to_build_fully_automatic_model_in_sage_milp_class()

        """
        verbose_print(MILP_BUILDING_MESSAGE)

        mip = self._model
        x = self._binary_variable
        x_class = self._trunc_binvar
        p = self._integer_variable

        self._forward_cipher = self._cipher
        self._backward_cipher = self._cipher.cipher_inverse().add_suffix_to_components(MILP_BACKWARD_SUFFIX)

        self.build_bitwise_impossible_xor_differential_trail_model(fixed_variables)
        for index, constraint in enumerate(self._model_constraints):
            mip.add_constraint(constraint)

        # finding incompatibility
        constraints = []
        forward_output = [c for c in self._forward_cipher.get_all_components() if c.type == CIPHER_OUTPUT][0]
        all_inconsistent_vars = []
        backward_components = [c for c in self._backward_cipher.get_all_components() if
                                   c.description == ['round_output'] and set(c.input_id_links) != {
                                       forward_output.id + MILP_BACKWARD_SUFFIX}]

        key_flow = set(get_key_schedule_component_ids(self._cipher)) - {INPUT_KEY}
        backward_key_flow = [f'{id}{MILP_BACKWARD_SUFFIX}' for id in key_flow]

        if include_all_components:
            backward_components = set(self._backward_cipher.get_all_components()) - set(self._backward_cipher.get_component_from_id(key_flow_id) for key_flow_id in backward_key_flow)

        for backward_component in backward_components:
            output_bit_size = backward_component.output_bit_size
            input_ids, output_ids = backward_component._get_input_output_variables()

            if include_all_components:
                # for multiple input components such as the XOR, ensures compatibility occurs on the correct branch
                inputs_to_be_kept = []
                for index, input_id in enumerate(["_".join(i.split("_")[:-1]) for i in set(backward_component.input_id_links)]):
                    if f'{INPUT_KEY}' not in input_id and [link+MILP_BACKWARD_SUFFIX for link in self._cipher.get_component_from_id(input_id).input_id_links] == [backward_component.id]:
                        inputs_to_be_kept.extend([_ for _ in input_ids if input_id in _])
                backward_vars = [x_class[id] for id in (inputs_to_be_kept or input_ids) if INPUT_KEY not in id]
            else:
                backward_vars = [x_class[id] for id in output_ids]
            forward_vars = [x_class["_".join(id.split("_")[:-2] + [id.split("_")[-1]])] for id in output_ids]
            inconsistent_vars = [x[f"{backward_component.id}_inconsistent_{_}"] for _ in range(output_bit_size)]
            all_inconsistent_vars += inconsistent_vars

            for inconsistent_index in range(output_bit_size):
                incompatibility_constraint = [forward_vars[inconsistent_index] + backward_vars[inconsistent_index] == 1]
                constraints.extend(
                    milp_utils.milp_if_then(inconsistent_vars[inconsistent_index], incompatibility_constraint,
                                            self._model.get_max(x_class) * 2))

        constraints.extend([sum(all_inconsistent_vars) == 1])

        for constraint in constraints:
            mip.add_constraint(constraint)

        _, forward_output_id_tuples = forward_output._get_input_output_variables_tuples()
        mip.add_constraint(p["number_of_unknown_patterns"] == sum(
            x[output_msb] for output_msb in [id[0] for id in forward_output_id_tuples]))

    def find_one_bitwise_impossible_xor_differential_trail(self, middle_round, fixed_values=[],
                                                           solver_name=SOLVER_DEFAULT, external_solver_name=None):
        """
        Returns one bitwise impossible XOR differential trail.

        INPUTS:

        - ``solver_name`` -- *str*, the solver to call
        - ``middle_round`` -- **integer**; the round number for which the incompatibility occurs
        - ``fixed_values`` -- *list of dict*, the variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)
        - ``external_solver_name`` -- **string** (default: None); if specified, the library will write the internal Sagemath MILP model as a .lp file and solve it outside of Sagemath, using the external solver.

        EXAMPLES::

            # table 9 from https://eprint.iacr.org/2014/761.pdf
            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: simon = SimonBlockCipher(block_bit_size=32, number_of_rounds=11)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_impossible_xor_differential_model import MilpBitwiseImpossibleXorDifferentialModel
            sage: milp = MilpBitwiseImpossibleXorDifferentialModel(simon)
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32), bit_values=[0]*31 + [1])
            sage: key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0]*64)
            sage: ciphertext = set_fixed_variables(component_id='cipher_output_10_13', constraint_type='equal', bit_positions=range(32), bit_values=[0]*6 + [2,0,2] + [0]*23)
            sage: trail = milp.find_one_bitwise_impossible_xor_differential_trail(6, fixed_values=[plaintext, key, ciphertext])

            # table 10 from https://eprint.iacr.org/2014/761.pdf
            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: simon = SimonBlockCipher(block_bit_size=48, key_bit_size=72, number_of_rounds=12)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_impossible_xor_differential_model import MilpBitwiseImpossibleXorDifferentialModel
            sage: milp = MilpBitwiseImpossibleXorDifferentialModel(simon)
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(48), bit_values=[0]*47 + [1])
            sage: key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(72), bit_values=[0]*72)
            sage: ciphertext = set_fixed_variables(component_id='cipher_output_11_12', constraint_type='equal', bit_positions=range(48), bit_values=[1]+[0]*16 + [2,0,0,0,2,2,2] + [0]*24)
            sage: trail = milp.find_one_bitwise_impossible_xor_differential_trail(7, fixed_values=[plaintext, key, ciphertext])

            # https://eprint.iacr.org/2016/490.pdf
            # requires to comment the constraints that sum(inconsistent_vars) == 1 as we are considering half rounds not full rounds
            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.permutations.ascon_sbox_sigma_permutation import AsconSboxSigmaPermutation
            sage: ascon = AsconSboxSigmaPermutation(number_of_rounds=5)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_impossible_xor_differential_model import MilpBitwiseImpossibleXorDifferentialModel
            sage: milp = MilpBitwiseImpossibleXorDifferentialModel(ascon)
            sage: milp.init_model_in_sage_milp_class()
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(320), bit_values=[1] + [0]*191 + [1] + [0]*63 + [1] + [0]*63 )
            sage: P1 = set_fixed_variables(component_id='intermediate_output_0_71', constraint_type='equal', bit_positions=range(320), bit_values= [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            sage: P2 = set_fixed_variables(component_id='intermediate_output_1_71', constraint_type='equal', bit_positions=range(320), bit_values= [2, 2, 0, 2, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 2, 2, 0, 2, 2, 0, 0, 0, 0, 2, 0, 0, 2, 2, 0, 0, 0, 0, 2, 0, 2, 0, 2, 2, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 0, 0, 2, 2, 0, 2, 0, 0, 2, 2, 0, 0, 2, 0, 0, 0, 2, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 2, 0, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 2, 0, 0, 2, 2, 0, 2, 2, 2, 2, 0, 0, 2, 2, 0, 0, 2, 2, 2, 0, 0, 0, 2, 2, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 2, 2, 0, 0, 0, 0, 2, 2, 0, 0, 2, 2, 0, 0, 2, 0, 2, 2, 2, 0, 2, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 2, 0, 0, 0, 2, 0, 0, 2, 0, 0, 2, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 0, 0])
            sage: P3 = set_fixed_variables(component_id='intermediate_output_2_71', constraint_type='equal', bit_positions=range(320), bit_values= [2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 0, 2, 2, 2, 2, 0, 2, 0, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 0, 2, 2, 2, 2, 0, 0, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 0, 2, 2, 2, 2, 0, 2, 0, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2])
            sage: P5 = set_fixed_variables(component_id='cipher_output_4_71', constraint_type='equal', bit_positions=range(320), bit_values= [0]*192 + [1] + [0]* 127)
            sage: trail = milp.find_one_bitwise_impossible_xor_differential_trail(4, fixed_values=[plaintext, P1, P2, P3, P5])


        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_in_sage_milp_class(middle_round, fixed_values)
        end = time.time()
        building_time = end - start
        solution = self.solve(MILP_BITWISE_IMPOSSIBLE, solver_name, external_solver_name)
        solution['building_time'] = building_time

        return solution

    def find_one_bitwise_impossible_xor_differential_trail_with_chosen_incompatible_components(self, component_id_list, fixed_values=[],
                                                                                solver_name=SOLVER_DEFAULT, external_solver_name=None):
        """
        Returns one bitwise impossible XOR differential trail.

        INPUTS:

        - ``solver_name`` -- *str*, the solver to call
        - ``component_id_list`` -- **str**; the list of component ids for which the incompatibility occurs
        - ``fixed_values`` -- *list of dict*, the variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)
        - ``external_solver_name`` -- **string** (default: None); if specified, the library will write the internal Sagemath MILP model as a .lp file and solve it outside of Sagemath, using the external solver.

        EXAMPLES::

            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: simon = SimonBlockCipher(block_bit_size=32, number_of_rounds=11)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_impossible_xor_differential_model import MilpBitwiseImpossibleXorDifferentialModel
            sage: milp = MilpBitwiseImpossibleXorDifferentialModel(simon)
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32), bit_values=[0]*31 + [1])
            sage: key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0]*64)
            sage: ciphertext = set_fixed_variables(component_id='cipher_output_10_13', constraint_type='equal', bit_positions=range(32), bit_values=[0]*6 + [2,0,2] + [0]*23)
            sage: trail = milp.find_one_bitwise_impossible_xor_differential_trail_with_chosen_incompatible_components(['intermediate_output_5_12'], fixed_values=[plaintext, key, ciphertext])


            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.permutations.ascon_sbox_sigma_permutation import AsconSboxSigmaPermutation
            sage: ascon = AsconSboxSigmaPermutation(number_of_rounds=5)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_impossible_xor_differential_model import MilpBitwiseImpossibleXorDifferentialModel
            sage: milp = MilpBitwiseImpossibleXorDifferentialModel(ascon)
            sage: milp.init_model_in_sage_milp_class()
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(320), bit_values=[1] + [0]*191 + [1] + [0]*63 + [1] + [0]*63 )
            sage: P1 = set_fixed_variables(component_id='intermediate_output_0_71', constraint_type='equal', bit_positions=range(320), bit_values= [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            sage: P2 = set_fixed_variables(component_id='intermediate_output_1_71', constraint_type='equal', bit_positions=range(320), bit_values= [2, 2, 0, 2, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 2, 2, 0, 2, 2, 0, 0, 0, 0, 2, 0, 0, 2, 2, 0, 0, 0, 0, 2, 0, 2, 0, 2, 2, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 0, 0, 2, 2, 0, 2, 0, 0, 2, 2, 0, 0, 2, 0, 0, 0, 2, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 2, 0, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 2, 0, 0, 2, 2, 0, 2, 2, 2, 2, 0, 0, 2, 2, 0, 0, 2, 2, 2, 0, 0, 0, 2, 2, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 2, 2, 0, 0, 0, 0, 2, 2, 0, 0, 2, 2, 0, 0, 2, 0, 2, 2, 2, 0, 2, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 2, 0, 0, 0, 2, 0, 0, 2, 0, 0, 2, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 0, 0])
            sage: P3 = set_fixed_variables(component_id='intermediate_output_2_71', constraint_type='equal', bit_positions=range(320), bit_values= [2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 0, 2, 2, 2, 2, 0, 2, 0, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 0, 2, 2, 2, 2, 0, 0, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 0, 2, 2, 2, 2, 0, 2, 0, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2])
            sage: P5 = set_fixed_variables(component_id='cipher_output_4_71', constraint_type='equal', bit_positions=range(320), bit_values= [0]*192 + [1] + [0]* 127)
            sage: trail = milp.find_one_bitwise_impossible_xor_differential_trail_with_chosen_incompatible_components(["sbox_3_56"], fixed_values=[plaintext, P1, P2, P3, P5])


        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_in_sage_milp_class_with_chosen_incompatible_components(component_id_list, fixed_values)
        end = time.time()
        building_time = end - start
        solution = self.solve(MILP_BITWISE_IMPOSSIBLE, solver_name, external_solver_name)
        solution['building_time'] = building_time

        return solution

    def find_one_bitwise_impossible_xor_differential_trail_with_fully_automatic_model(self, fixed_values=[], include_all_components=False,
                                                                                      solver_name=SOLVER_DEFAULT, external_solver_name=None):
        """
        Returns one bitwise impossible XOR differential trail.

        INPUTS:

        - ``solver_name`` -- *str*, the solver to call
        - ``middle_round`` -- **integer**; the round number for which the incompatibility occurs
        - ``fixed_values`` -- *list of dict*, the variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)
        - ``include_all_components`` -- **boolean** (default: `False`); when set to `True`, every component output can be a source
          of incompatibility; otherwise, only round outputs are considered
        - ``external_solver_name`` -- **string** (default: None); if specified, the library will write the internal Sagemath MILP model as a .lp file and solve it outside of Sagemath, using the external solver.

        EXAMPLES::

            # table 9 from https://eprint.iacr.org/2014/761.pdf
            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: simon = SimonBlockCipher(block_bit_size=32, number_of_rounds=11)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_impossible_xor_differential_model import MilpBitwiseImpossibleXorDifferentialModel
            sage: milp = MilpBitwiseImpossibleXorDifferentialModel(simon)
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32), bit_values=[0]*31 + [1])
            sage: key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0]*64)
            sage: key_backward = set_fixed_variables(component_id='key_backward', constraint_type='equal', bit_positions=range(64), bit_values=[0]*64)
            sage: ciphertext_backward = set_fixed_variables(component_id='cipher_output_10_13_backward', constraint_type='equal', bit_positions=range(32), bit_values=[0]*6 + [2,0,2] + [0]*23)
            sage: trail = milp.find_one_bitwise_impossible_xor_differential_trail_with_fully_automatic_model(fixed_values=[plaintext, key, key_backward, ciphertext_backward])


            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.permutations.ascon_sbox_sigma_permutation import AsconSboxSigmaPermutation
            sage: ascon = AsconSboxSigmaPermutation(number_of_rounds=5)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_impossible_xor_differential_model import MilpBitwiseImpossibleXorDifferentialModel
            sage: milp = MilpBitwiseImpossibleXorDifferentialModel(ascon)
            sage: milp.init_model_in_sage_milp_class()
            sage: P = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(320), bit_values= [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] )
            sage: trail = milp.find_one_bitwise_impossible_xor_differential_trail_with_fully_automatic_model(fixed_values=[P])

        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_fully_automatic_model_in_sage_milp_class(fixed_variables=fixed_values, include_all_components=include_all_components)
        end = time.time()
        building_time = end - start
        solution = self.solve(MILP_BITWISE_IMPOSSIBLE_AUTO, solver_name, external_solver_name)
        solution['building_time'] = building_time

        return solution

    def _get_component_values(self, objective_variables, components_variables):
        return  milp_utils._get_component_values_for_impossible_models(self, objective_variables, components_variables)

    def _parse_solver_output(self):
        mip = self._model
        components_variables = mip.get_values(self._trunc_binvar)
        if self._forward_cipher == self._cipher:
            objective_variables = mip.get_values(self._binary_variable)
            inconsistent_component_var = \
            [i for i in objective_variables.keys() if objective_variables[i] > 0 and "inconsistent" in i][0]
            objective_value = "_".join(inconsistent_component_var.split("_")[:-3])
        else:
            objective_variables = mip.get_values(self._integer_variable)
            objective_value = objective_variables["number_of_unknown_patterns"]
        components_values = self._get_component_values(objective_variables, components_variables)
        return objective_value, components_values

    def _get_component_value_weight(self, component_id, components_variables):

        if component_id in self._cipher.inputs:
            output_size = self._cipher.inputs_bit_size[self._cipher.inputs.index(component_id)]
        elif self._forward_cipher != self._cipher and component_id.endswith(MILP_BACKWARD_SUFFIX):
            component = self._backward_cipher.get_component_from_id(component_id)
            output_size = component.output_bit_size
        elif self._forward_cipher == self._cipher and component_id.endswith(MILP_BACKWARD_SUFFIX):
            if component_id in self._backward_cipher.inputs:
                output_size = self._backward_cipher.inputs_bit_size[self._backward_cipher.inputs.index(component_id)]
            else:
                component = self._backward_cipher.get_component_from_id(component_id)
                output_size = component.output_bit_size
        else:
            component = self._cipher.get_component_from_id(component_id)
            output_size = component.output_bit_size
        suffix_dict = {"": output_size}
        final_output = self._get_final_output(component_id, components_variables, suffix_dict)
        if len(final_output) == 1:
            final_output = final_output[0]

        return final_output