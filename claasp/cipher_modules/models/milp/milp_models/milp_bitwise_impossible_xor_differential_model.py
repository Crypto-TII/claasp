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
from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
from claasp.cipher_modules.models.milp.utils.milp_name_mappings import MILP_BITWISE_IMPOSSIBLE, \
    MILP_BITWISE_IMPOSSIBLE_AUTO, MILP_BACKWARD_SUFFIX
from claasp.cipher_modules.models.utils import set_component_solution
from claasp.name_mappings import CIPHER_OUTPUT
from claasp.cipher_modules.models.milp.utils import utils as milp_utils


class MilpBitwiseImpossibleXorDifferentialModel(MilpBitwiseDeterministicTruncatedXorDifferentialModel):

    def __init__(self, cipher, n_window_heuristic=None):
        super().__init__(cipher, n_window_heuristic)
        self._forward_cipher = None
        self._backward_cipher = None
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
        verbose_print("Building model in progress ...")
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
        backward_vars = [x_class["_".join(id.split("_")[:-1] + ["backward"] + [id.split("_")[-1]])] for id in output_ids]
        inconsistent_vars = [x[f"{forward_output.id}_inconsistent_{_}"] for _ in range(output_bit_size)]

        # constraints.extend([sum(backward_vars) >= 2])
        constraints.extend([sum(inconsistent_vars) == 1])
        for inconsistent_index in range(output_bit_size):
            incompatibility_constraint = [forward_vars[inconsistent_index] + backward_vars[inconsistent_index] == 1]
            constraints.extend(milp_utils.milp_if_then(inconsistent_vars[inconsistent_index], incompatibility_constraint, self._model.get_max(x_class) * 2))
        for constraint in constraints:
            mip.add_constraint(constraint)

        _, forward_output_id_tuples = forward_output._get_input_output_variables_tuples()
        mip.add_constraint(p["number_of_unknown_patterns"] == sum(x[output_msb] for output_msb in [id[0] for id in forward_output_id_tuples]))

    def add_constraints_to_build_fully_automatic_model_in_sage_milp_class(self, fixed_variables=[]):

        """
        Take the constraints contained in self._model_constraints and add them to the build-in sage class.

        INPUT:

        - ``model_type`` -- **string**; the model to solve
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
            sage: milp.aadd_constraints_to_build_fully_automatic_model_in_sage_milp_class()

        """
        verbose_print("Building model in progress ...")

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
        backward_round_outputs = [c for c in self._backward_cipher.get_all_components() if c.description == ['round_output'] and set(c.input_id_links) != {forward_output.id + MILP_BACKWARD_SUFFIX}]

        for backward_round_output in backward_round_outputs:
            output_bit_size = backward_round_output.output_bit_size
            _, output_ids = backward_round_output._get_input_output_variables()

            backward_vars = [x_class[id] for id in output_ids]
            forward_vars = [x_class["_".join(id.split("_")[:-2] + [id.split("_")[-1]])] for id in output_ids]
            inconsistent_vars = [x[f"{backward_round_output.id}_inconsistent_{_}"] for _ in range(output_bit_size)]
            all_inconsistent_vars += inconsistent_vars

            for inconsistent_index in range(output_bit_size):
                incompatibility_constraint = [forward_vars[inconsistent_index] + backward_vars[inconsistent_index] == 1]
                constraints.extend(milp_utils.milp_if_then(inconsistent_vars[inconsistent_index], incompatibility_constraint, self._model.get_max(x_class) * 2))

        constraints.extend([sum(all_inconsistent_vars) == 1])

        for constraint in constraints:
            mip.add_constraint(constraint)

        _, forward_output_id_tuples = forward_output._get_input_output_variables_tuples()
        mip.add_constraint(p["number_of_unknown_patterns"] == sum(
            x[output_msb] for output_msb in [id[0] for id in forward_output_id_tuples]))

    def find_one_bitwise_impossible_xor_differential_trail(self,  middle_round, fixed_values=[], solver_name=SOLVER_DEFAULT):
        """
        Returns one bitwise impossible XOR differential trail.

        INPUTS:

        - ``solver_name`` -- *str*, the solver to call
        - ``middle_round`` -- **integer**; the round number for which the incompatibility occurs
        - ``fixed_values`` -- *list of dict*, the variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)

        EXAMPLE::

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

            # not ok
            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: simon = SimonBlockCipher(block_bit_size=32, number_of_rounds=11)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_impossible_xor_differential_model import MilpBitwiseImpossibleXorDifferentialModel
            sage: milp = MilpBitwiseImpossibleXorDifferentialModel(simon)
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32), bit_values=[0]*17 + [1] + [0]*13 + [1])
            sage: key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0]*64)
            sage: ciphertext = set_fixed_variables(component_id='cipher_output_10_13', constraint_type='equal', bit_positions=range(32), bit_values=[0]*17 + [1] + [0]*6 + [1] + [0]*6 + [1])
            sage: trail = milp.find_one_bitwise_impossible_xor_differential_trail(6, fixed_values=[plaintext, key, ciphertext])


            # not ok
            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: simon = SimonBlockCipher(block_bit_size=48, key_bit_size=72, number_of_rounds=12)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_impossible_xor_differential_model import MilpBitwiseImpossibleXorDifferentialModel
            sage: milp = MilpBitwiseImpossibleXorDifferentialModel(simon)
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(48), bit_values=[0]*41 + [1] + [0]*6)
            sage: key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(72), bit_values=[0]*72)
            sage: ciphertext = set_fixed_variables(component_id='cipher_output_11_12', constraint_type='equal', bit_positions=range(48), bit_values=[0]*17 + [1] + [0]*15 + [1,0,1,0,0,0,1,1,1,1] + [0]*5)
            sage: trail = milp.find_one_bitwise_impossible_xor_differential_trail(7, fixed_values=[plaintext, key, ciphertext])



            # alledgedly incorrect
            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.permutations.ascon_sbox_sigma_permutation import AsconSboxSigmaPermutation
            sage: ascon = AsconSboxSigmaPermutation(number_of_rounds=1)
            sage: ascon_inv = ascon.cipher_inverse()
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(ascon_inv)
            sage: milp.init_model_in_sage_milp_class()
            sage: P4 = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(320), bit_values= [0, 2, 2, 0, 2, 0, 2, 2, 0, 2, 0, 0, 2, 0, 0, 0, 0, 2, 2, 0, 0, 2, 2, 2, 2, 0, 2, 2, 2, 2, 0, 2, 2, 2, 0, 2, 2, 2, 0, 0, 2, 0, 2, 0, 2, 0, 0, 2, 2, 2, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 2, 0, 2, 0, 2, 2, 0, 2, 0, 2, 2, 0, 2, 0, 0, 2, 0, 0, 0, 0, 2, 2, 0, 0, 2, 2, 2, 2, 0, 2, 2, 2, 2, 0, 2, 2, 2, 0, 2, 2, 2, 0, 0, 2, 0, 2, 0, 2, 0, 0, 2, 2, 2, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 2, 0, 2, 0, 2, 2, 0, 2, 0, 2, 2, 0, 2, 0, 0, 2, 0, 0, 0, 0, 2, 2, 0, 0, 2, 2, 2, 2, 0, 2, 2, 2, 2, 0, 2, 2, 2, 0, 2, 2, 2, 0, 0, 2, 0, 2, 0, 2, 0, 0, 2, 2, 2, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 2, 0, 2, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 2, 2, 0, 2, 0, 2, 2, 0, 2, 0, 0, 2, 0, 0, 0, 0, 2, 2, 0, 0, 2, 2, 2, 2, 0, 2, 2, 2, 2, 0, 2, 2, 2, 0, 2, 2, 2, 0, 0, 2, 0, 2, 0, 2, 0, 0, 2, 2, 2, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 2, 0, 2])
            sage: P5 = set_fixed_variables(component_id='cipher_output_0_71', constraint_type='equal', bit_positions=range(320), bit_values= [0]*192 + [1] + [0]* 127)
            sage: trail = milp.find_one_bitwise_deterministic_truncated_xor_differential_trail(fixed_values=[P4, P5])

            # alledgedly correct
            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.permutations.ascon_sbox_sigma_permutation import AsconSboxSigmaPermutation
            sage: ascon = AsconSboxSigmaPermutation(number_of_rounds=1)
            sage: ascon_inv = ascon.cipher_inverse()
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(ascon_inv)
            sage: milp.init_model_in_sage_milp_class()
            sage: P4 = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(320), bit_values= [0, 2, 2, 0, 2, 0, 2, 2, 0, 2, 0, 0, 2, 0, 0, 0, 0, 2, 2, 0, 0, 2, 2, 2, 2, 0, 2, 2, 2, 2, 0, 2, 2, 2, 0, 2, 2, 2, 0, 0, 2, 0, 2, 0, 2, 0, 0, 2, 2, 2, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 2, 0, 2, 0, 2, 2, 0, 2, 0, 2, 2, 0, 2, 0, 0, 2, 0, 0, 0, 0, 2, 2, 0, 0, 2, 2, 2, 2, 0, 2, 2, 2, 2, 0, 2, 2, 2, 0, 2, 2, 2, 0, 0, 2, 0, 2, 0, 2, 0, 0, 2, 2, 2, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 2, 0, 2, 0, 2, 2, 0, 2, 0, 2, 2, 0, 2, 0, 0, 2, 0, 0, 0, 0, 2, 2, 0, 0, 2, 2, 2, 2, 0, 2, 2, 2, 2, 0, 2, 2, 2, 0, 2, 2, 2, 0, 0, 2, 0, 2, 0, 2, 0, 0, 2, 2, 2, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 2, 0, 2, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 2, 2, 0, 2, 0, 2, 2, 0, 2, 0, 0, 2, 0, 0, 0, 0, 2, 2, 0, 0, 2, 2, 2, 2, 0, 2, 2, 2, 2, 0, 2, 2, 2, 0, 2, 2, 2, 0, 0, 2, 0, 2, 0, 2, 0, 0, 2, 2, 2, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 2, 0, 2])
            sage: P5 = set_fixed_variables(component_id='cipher_output_0_71', constraint_type='equal', bit_positions=range(320), bit_values= [0]*192 + [1] + [0]* 127)
            sage: trail = milp.find_one_bitwise_deterministic_truncated_xor_differential_trail(fixed_values=[P4, P5])

            # https://eprint.iacr.org/2016/689.pdf
            sage: from claasp.ciphers.block_ciphers.lea_block_cipher import LeaBlockCipher
            sage: key = 0x0f1e2d3c4b5a69788796a5b4c3d2e1f0
            sage: plaintext = 0x101112131415161718191a1b1c1d1e1f
            sage: cipher = LeaBlockCipher(block_bit_size=128, key_bit_size=128, number_of_rounds=2)
            sage: ciphertext = cipher.evaluate([plaintext, key])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext, key]) == plaintext

            sage: from claasp.ciphers.block_ciphers.hight_block_cipher import HightBlockCipher
            sage: key = 0x000000066770000000a0000000000001
            sage: plaintext = 0x0011223344556677
            sage: cipher = HightBlockCipher(block_bit_size=64, key_bit_size=128, number_of_rounds=2)
            sage: ciphertext = cipher.evaluate([plaintext, key])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext, key]) == plaintext

        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_in_sage_milp_class(middle_round, fixed_values)
        end = time.time()
        building_time = end - start
        solution = self.solve(MILP_BITWISE_IMPOSSIBLE, solver_name)
        solution['building_time'] = building_time

        return solution

    def find_one_bitwise_impossible_xor_differential_trail_with_fully_automatic_model(self, fixed_values=[], solver_name=SOLVER_DEFAULT):
        """
        Returns one bitwise impossible XOR differential trail.

        INPUTS:

        - ``solver_name`` -- *str*, the solver to call
        - ``middle_round`` -- **integer**; the round number for which the incompatibility occurs
        - ``fixed_values`` -- *list of dict*, the variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)

        EXAMPLE::

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


        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_fully_automatic_model_in_sage_milp_class(fixed_values)
        end = time.time()
        building_time = end - start
        solution = self.solve(MILP_BITWISE_IMPOSSIBLE_AUTO, solver_name)
        solution['building_time'] = building_time

        return solution

    def _get_component_values(self, objective_variables, components_variables):
        components_values = {}
        if self._forward_cipher == self._cipher:
            inconsistent_component_var = \
            [i for i in objective_variables.keys() if objective_variables[i] > 0 and "inconsistent" in i][0]
            inconsistent_component_id = "_".join(inconsistent_component_var.split("_")[:-3])

            full_cipher_components = self._cipher.get_all_components_ids()
            backward_components = self._backward_cipher.get_all_components_ids() + self._backward_cipher.inputs
            index = full_cipher_components.index(inconsistent_component_id)
            updated_cipher_components = full_cipher_components[:index + 1] + [
                c + MILP_BACKWARD_SUFFIX if c + MILP_BACKWARD_SUFFIX in backward_components else c for c in
                full_cipher_components[index:]]
            list_component_ids = self._forward_cipher.inputs + updated_cipher_components
        else:
            full_cipher_components = self._cipher.get_all_components_ids()
            backward_components = self._backward_cipher.get_all_components_ids()
            incompatible_value = backward_components[-1]

            incompatible_component_id = "_".join(incompatible_value.split("_")[:-1])
            index = full_cipher_components.index(incompatible_component_id)
            full_cipher_components.insert(index + 1, incompatible_value)
            list_component_ids = self._forward_cipher.inputs + full_cipher_components
        for component_id in list_component_ids:
            dict_tmp = self._get_component_value_weight(component_id, components_variables)
            components_values[component_id] = dict_tmp
        return components_values

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
        diff_str = {}
        suffix_dict = {"": output_size}
        final_output = self._get_final_output(component_id, components_variables, diff_str, suffix_dict)
        if len(final_output) == 1:
            final_output = final_output[0]

        return final_output