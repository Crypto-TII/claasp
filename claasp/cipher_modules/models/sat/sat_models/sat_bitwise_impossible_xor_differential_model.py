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

from claasp.cipher_modules.models.utils import set_component_solution
from claasp.cipher_modules.inverse_cipher import get_key_schedule_component_ids
from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_deterministic_truncated_xor_differential_model import (
    SatBitwiseDeterministicTruncatedXorDifferentialModel,
)
from claasp.cipher_modules.models.sat.utils import utils
from claasp.name_mappings import CIPHER_OUTPUT, IMPOSSIBLE_XOR_DIFFERENTIAL


class SatBitwiseImpossibleXorDifferentialModel(SatBitwiseDeterministicTruncatedXorDifferentialModel):
    def __init__(self, cipher, compact=False):
        super().__init__(cipher, compact)
        self._forward_cipher = None
        self._backward_cipher = None
        self._middle_round = None

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
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_impossible_xor_differential_model import SatBitwiseImpossibleXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=2)
            sage: sat = SatBitwiseImpossibleXorDifferentialModel(speck)
            sage: sat._forward_cipher = speck.get_partial_cipher(0, 1, keep_key_schedule=True)
            sage: backward_cipher = sat._cipher.cipher_partial_inverse(1, 1, keep_key_schedule=False)
            sage: sat._backward_cipher = backward_cipher.add_suffix_to_components("_backward", [backward_cipher.get_all_components_ids()[-1]])
            sage: sat.build_bitwise_impossible_xor_differential_trail_model()
            ...
        """
        component_list = self._forward_cipher.get_all_components() + self._backward_cipher.get_all_components()
        return self.build_bitwise_deterministic_truncated_xor_differential_trail_model(
            fixed_variables=fixed_variables, component_list=component_list
        )

    def find_one_bitwise_impossible_xor_differential_trail(
        self, middle_round, fixed_values=[], solver_name="cryptominisat"
    ):
        """
        Returns one bitwise impossible XOR differential trail.

        INPUTS:

        - ``middle_round`` -- **integer**; the round number for which the incompatibility occurs
        - ``fixed_values`` -- *list of dict*, the variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)
        - ``solver_name`` -- *str*, the solver to call

        EXAMPLES::

            # table 9 from https://eprint.iacr.org/2014/761.pdf
            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: simon = SimonBlockCipher(block_bit_size=32, number_of_rounds=11)
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_impossible_xor_differential_model import SatBitwiseImpossibleXorDifferentialModel
            sage: sat = SatBitwiseImpossibleXorDifferentialModel(simon)
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32), bit_values=[0]*31 + [1])
            sage: key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0]*64)
            sage: ciphertext = set_fixed_variables(component_id='cipher_output_10_13', constraint_type='equal', bit_positions=range(32), bit_values=[0]*6 + [2,0,2] + [0]*23)
            sage: trail = sat.find_one_bitwise_impossible_xor_differential_trail(6, fixed_values=[plaintext, key, ciphertext])

            # table 10 from https://eprint.iacr.org/2014/761.pdf
            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: simon = SimonBlockCipher(block_bit_size=48, key_bit_size=72, number_of_rounds=12)
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_impossible_xor_differential_model import SatBitwiseImpossibleXorDifferentialModel
            sage: sat = SatBitwiseImpossibleXorDifferentialModel(simon)
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(48), bit_values=[0]*47 + [1])
            sage: key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(72), bit_values=[0]*72)
            sage: ciphertext = set_fixed_variables(component_id='cipher_output_11_12', constraint_type='equal', bit_positions=range(48), bit_values=[1]+[0]*16 + [2,0,0,0,2,2,2] + [0]*24)
            sage: trail = sat.find_one_bitwise_impossible_xor_differential_trail(7, fixed_values=[plaintext, key, ciphertext])

            # https://eprint.iacr.org/2016/490.pdf
            # requires to comment the constraints ' '.join(incompatibility_ids) as we are considering half rounds not full rounds
            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.permutations.ascon_sbox_sigma_permutation import AsconSboxSigmaPermutation
            sage: ascon = AsconSboxSigmaPermutation(number_of_rounds=5)
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_impossible_xor_differential_model import SatBitwiseImpossibleXorDifferentialModel
            sage: sat = SatBitwiseImpossibleXorDifferentialModel(ascon)
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(320), bit_values=[1] + [0]*191 + [1] + [0]*63 + [1] + [0]*63 )
            sage: P1 = set_fixed_variables(component_id='intermediate_output_0_71', constraint_type='equal', bit_positions=range(320), bit_values= [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            sage: P2 = set_fixed_variables(component_id='intermediate_output_1_71', constraint_type='equal', bit_positions=range(320), bit_values= [2, 2, 0, 2, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 2, 2, 0, 2, 2, 0, 0, 0, 0, 2, 0, 0, 2, 2, 0, 0, 0, 0, 2, 0, 2, 0, 2, 2, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 0, 0, 2, 2, 0, 2, 0, 0, 2, 2, 0, 0, 2, 0, 0, 0, 2, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 2, 0, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 2, 0, 0, 2, 2, 0, 2, 2, 2, 2, 0, 0, 2, 2, 0, 0, 2, 2, 2, 0, 0, 0, 2, 2, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 2, 2, 0, 0, 0, 0, 2, 2, 0, 0, 2, 2, 0, 0, 2, 0, 2, 2, 2, 0, 2, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 2, 0, 0, 0, 2, 0, 0, 2, 0, 0, 2, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 0, 0])
            sage: P3 = set_fixed_variables(component_id='intermediate_output_2_71', constraint_type='equal', bit_positions=range(320), bit_values= [2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 0, 2, 2, 2, 2, 0, 2, 0, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 0, 2, 2, 2, 2, 0, 0, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 0, 2, 2, 2, 2, 0, 2, 0, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2])
            sage: P5 = set_fixed_variables(component_id='cipher_output_4_71', constraint_type='equal', bit_positions=range(320), bit_values= [0]*192 + [1] + [0]* 127)
            sage: trail = sat.find_one_bitwise_impossible_xor_differential_trail(4, fixed_values=[plaintext, P1, P2, P3, P5])

        """
        start = time.time()
        if middle_round is None:
            middle_round = self._cipher.number_of_rounds // 2
        assert middle_round < self._cipher.number_of_rounds
        self._middle_round = middle_round

        self._forward_cipher = self._cipher.get_partial_cipher(0, middle_round - 1, keep_key_schedule=True)
        backward_cipher = self._cipher.cipher_partial_inverse(
            middle_round, self._cipher.number_of_rounds - 1, keep_key_schedule=False
        )
        self._backward_cipher = backward_cipher.add_suffix_to_components(
            "_backward", [backward_cipher.get_all_components_ids()[-1]]
        )

        self.build_bitwise_impossible_xor_differential_trail_model(fixed_variables=fixed_values)

        forward_output = [c for c in self._forward_cipher.get_all_components() if c.type == CIPHER_OUTPUT][0]
        out_size, forward_out_ids_0, forward_out_ids_1 = forward_output._generate_output_double_ids()
        backward_out_ids_0 = [
            "_".join(id_.split("_")[:-2] + ["backward"] + id_.split("_")[-2:]) for id_ in forward_out_ids_0
        ]
        backward_out_ids_1 = [
            "_".join(id_.split("_")[:-2] + ["backward"] + id_.split("_")[-2:]) for id_ in forward_out_ids_1
        ]
        end = time.time()
        building_time = end - start

        incompatibility_ids = [f"incompatibility_{i}" for i in range(out_size)]
        for i in range(out_size):
            self._model_constraints.extend(
                utils.incompatibility(
                    incompatibility_ids[i],
                    (forward_out_ids_0[i], forward_out_ids_1[i]),
                    (backward_out_ids_0[i], backward_out_ids_1[i]),
                )
            )
        self._model_constraints.append(" ".join(incompatibility_ids))

        solution = self.solve(IMPOSSIBLE_XOR_DIFFERENTIAL, solver_name=solver_name)
        solution["building_time"] = building_time

        return solution

    def find_one_bitwise_impossible_xor_differential_trail_with_chosen_incompatible_components(
        self, component_id_list, fixed_values=[], solver_name="cryptominisat"
    ):
        """
        Returns one bitwise impossible XOR differential trail.

        INPUTS:

        - ``solver_name`` -- *str*, the solver to call
        - ``component_id_list`` -- **str**; the list of component ids for which the incompatibility occurs
        - ``fixed_values`` -- *list of dict*, the variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)

        EXAMPLES::

            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: simon = SimonBlockCipher(block_bit_size=32, number_of_rounds=11)
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_impossible_xor_differential_model import SatBitwiseImpossibleXorDifferentialModel
            sage: sat = SatBitwiseImpossibleXorDifferentialModel(simon)
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32), bit_values=[0]*31 + [1])
            sage: key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0]*64)
            sage: ciphertext = set_fixed_variables(component_id='cipher_output_10_13', constraint_type='equal', bit_positions=range(32), bit_values=[0]*6 + [2,0,2] + [0]*23)
            sage: trail = sat.find_one_bitwise_impossible_xor_differential_trail_with_chosen_incompatible_components(
                                    component_id_list=['intermediate_output_5_12'],
                                    fixed_values=[plaintext, key, ciphertext],
                                    solver_name='cryptominisat'
                                    )

            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.permutations.ascon_sbox_sigma_permutation import AsconSboxSigmaPermutation
            sage: ascon = AsconSboxSigmaPermutation(number_of_rounds=5)
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_impossible_xor_differential_model import SatBitwiseImpossibleXorDifferentialModel
            sage: sat = SatBitwiseImpossibleXorDifferentialModel(ascon)
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(320), bit_values=[1] + [0]*191 + [1] + [0]*63 + [1] + [0]*63 )
            sage: P1 = set_fixed_variables(component_id='intermediate_output_0_71', constraint_type='equal', bit_positions=range(320), bit_values= [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            sage: P2 = set_fixed_variables(component_id='intermediate_output_1_71', constraint_type='equal', bit_positions=range(320), bit_values= [2, 2, 0, 2, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 2, 2, 0, 2, 2, 0, 0, 0, 0, 2, 0, 0, 2, 2, 0, 0, 0, 0, 2, 0, 2, 0, 2, 2, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 0, 0, 2, 2, 0, 2, 0, 0, 2, 2, 0, 0, 2, 0, 0, 0, 2, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 2, 0, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 2, 0, 0, 2, 2, 0, 2, 2, 2, 2, 0, 0, 2, 2, 0, 0, 2, 2, 2, 0, 0, 0, 2, 2, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 2, 2, 0, 0, 0, 0, 2, 2, 0, 0, 2, 2, 0, 0, 2, 0, 2, 2, 2, 0, 2, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 2, 0, 0, 0, 2, 0, 0, 2, 0, 0, 2, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 0, 0])
            sage: P3 = set_fixed_variables(component_id='intermediate_output_2_71', constraint_type='equal', bit_positions=range(320), bit_values= [2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 0, 2, 2, 2, 2, 0, 2, 0, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 0, 2, 2, 2, 2, 0, 0, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 0, 2, 2, 2, 2, 0, 2, 0, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2])
            sage: P5 = set_fixed_variables(component_id='cipher_output_4_71', constraint_type='equal', bit_positions=range(320), bit_values= [0]*192 + [1] + [0]* 127)
            sage: trail = sat.find_one_bitwise_impossible_xor_differential_trail_with_chosen_incompatible_components(
                                        component_id_list=["sbox_3_56"],
                                        fixed_values=[plaintext, P1, P2, P3, P5],
                                        solver_name='cryptominisat'
                                        ) #doctest: +SKIP
        """
        start = time.time()

        if component_id_list is None:
            return self.find_one_bitwise_impossible_xor_differential_trail(
                middle_round=None, fixed_values=[], solver_name="cryptominisat"
            )
        assert set(component_id_list) <= set(self._cipher.get_all_components_ids()) - set(
            get_key_schedule_component_ids(self._cipher)
        )

        # determine middle round
        rounds = [self._cipher.get_round_from_component_id(cid) for cid in component_id_list]
        assert len(set(rounds)) == 1, "All chosen components must be in the same round"
        middle = rounds[0]

        # case: single round_output
        if len(component_id_list) == 1:
            comp = self._cipher.get_component_from_id(component_id_list[0])
            if comp.description == ["round_output"]:
                return self.find_one_bitwise_impossible_xor_differential_trail(middle + 1, fixed_values, solver_name)

        # build partial ciphers
        self._middle_round = middle
        self._forward_cipher = self._cipher.get_partial_cipher(0, middle, keep_key_schedule=True)
        backward_cipher = self._cipher.cipher_partial_inverse(
            middle + 1, self._cipher.number_of_rounds - 1, keep_key_schedule=False
        )

        suffix = "_backward"
        self._backward_cipher = backward_cipher.add_suffix_to_components(
            suffix, backward_cipher.get_all_components_ids()
        )

        # build base model
        self.build_bitwise_impossible_xor_differential_trail_model(fixed_variables=fixed_values)

        # generate incompatibility constraints for each chosen component
        incompat_ids = []
        for cid in component_id_list:
            # forward component
            fwd_comp = self._forward_cipher.get_component_from_id(cid)
            out_size, fwd_out_ids_0, fwd_out_ids_1 = fwd_comp._generate_output_double_ids()
            # backward component
            bwd_in_ids_0 = ["_".join(id_.split("_")[:-2] + ["backward"] + id_.split("_")[-2:]) for id_ in fwd_out_ids_0]
            bwd_in_ids_1 = ["_".join(id_.split("_")[:-2] + ["backward"] + id_.split("_")[-2:]) for id_ in fwd_out_ids_1]

            # add incompatibility for each bit of this component
            for i in range(out_size):
                inv_id = f"incompatibility_{cid}_{i}"
                incompat_ids.append(inv_id)
                self._model_constraints.extend(
                    utils.incompatibility(
                        inv_id, (fwd_out_ids_0[i], fwd_out_ids_1[i]), (bwd_in_ids_0[i], bwd_in_ids_1[i])
                    )
                )

        self._model_constraints.append(" ".join(incompat_ids))

        solution = self.solve(IMPOSSIBLE_XOR_DIFFERENTIAL, solver_name=solver_name)
        solution["building_time"] = time.time() - start
        return solution

    def _parse_solver_output(self, variable2value):
        last_backward_component = self._backward_cipher.get_all_components()[-1]
        last_backward_component_id = last_backward_component.id
        last_backward_component_output_bit_size = last_backward_component.output_bit_size
        values = []
        for i in range(last_backward_component_output_bit_size):
            variable_value = 0
            if f"{last_backward_component_id}_{i}_0" in variable2value:
                variable_value ^= variable2value[f"{last_backward_component_id}_{i}_0"] << 1
            if f"{last_backward_component_id}_{i}_1" in variable2value:
                variable_value ^= variable2value[f"{last_backward_component_id}_{i}_1"]
            values.append(f"{variable_value}")
        last_backward_component_value = "".join(values).replace("2", "?").replace("3", "?")

        components_solutions = self._get_cipher_inputs_components_solutions_double_ids(variable2value)
        for component in self._cipher.get_all_components():
            value = self._get_component_value_double_ids(component, variable2value)
            component_solution = set_component_solution(value)
            components_solutions[component.id] = component_solution
            if component.id == last_backward_component_id[:-9]:
                components_solutions[last_backward_component_id] = set_component_solution(last_backward_component_value)

        return components_solutions, None
