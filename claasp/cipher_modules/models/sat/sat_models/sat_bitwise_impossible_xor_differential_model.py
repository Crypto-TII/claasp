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
from claasp.cipher_modules.models.sat import solvers
from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_deterministic_truncated_xor_differential_model import (
    SatBitwiseDeterministicTruncatedXorDifferentialModel,
)
from claasp.cipher_modules.models.sat.utils import utils
from claasp.cipher_modules.models.utils import set_component_solution
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
        self, middle_round, fixed_values=[], solver_name=solvers.SOLVER_DEFAULT, options=None
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

        incompatibility_ids = [f"incompatibility_{forward_output.id}_{i}" for i in range(out_size)]

        for i in range(out_size):
            self._model_constraints.extend(
                utils.incompatibility(
                    incompatibility_ids[i],
                    (forward_out_ids_0[i], forward_out_ids_1[i]),
                    (backward_out_ids_0[i], backward_out_ids_1[i]),
                )
            )
        self._model_constraints.append(" ".join(incompatibility_ids))

        solution = self.solve(IMPOSSIBLE_XOR_DIFFERENTIAL, solver_name=solver_name, options=options)
        solution["building_time"] = building_time

        return solution

    def find_one_bitwise_impossible_xor_differential_trail_with_chosen_incompatible_components(
        self, component_id_list, fixed_values=[], solver_name=solvers.SOLVER_DEFAULT, options=None
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
            sage: trail = sat.find_one_bitwise_impossible_xor_differential_trail_with_chosen_incompatible_components(component_id_list=['intermediate_output_5_12'], fixed_values=[plaintext, key, ciphertext],solver_name='cryptominisat')

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
            sage: trail = sat.find_one_bitwise_impossible_xor_differential_trail_with_chosen_incompatible_components(component_id_list=["sbox_3_56"], fixed_values=[plaintext, P1, P2, P3, P5], solver_name='cryptominisat') #doctest: +SKIP
        """
        start = time.time()

        if component_id_list is None:
            return self.find_one_bitwise_impossible_xor_differential_trail(
                middle_round=None, fixed_values=[], solver_name=solvers.SOLVER_DEFAULT
            )
        assert set(component_id_list) <= set(self._cipher.get_all_components_ids()) - set(
            get_key_schedule_component_ids(self._cipher)
        )

        rounds = [self._cipher.get_round_from_component_id(cid) for cid in component_id_list]
        assert len(set(rounds)) == 1, "All chosen components must be in the same round"
        middle = rounds[0]

        if len(component_id_list) == 1:
            comp = self._cipher.get_component_from_id(component_id_list[0])
            if comp.description == ["round_output"]:
                return self.find_one_bitwise_impossible_xor_differential_trail(middle + 1, fixed_values, solver_name)

        assert middle < self._cipher.number_of_rounds - 1
        self._middle_round = middle
        self._forward_cipher = self._cipher.get_partial_cipher(0, middle, keep_key_schedule=True)
        backward_cipher = self._cipher.cipher_partial_inverse(
            middle + 1, self._cipher.number_of_rounds - 1, keep_key_schedule=False
        )

        suffix = "_backward"
        self._backward_cipher = backward_cipher.add_suffix_to_components(
            suffix, backward_cipher.get_all_components_ids()
        )

        self.build_bitwise_impossible_xor_differential_trail_model(fixed_variables=fixed_values)

        incompat_ids = []
        for cid in component_id_list:
            fwd_comp = self._forward_cipher.get_component_from_id(cid)
            out_size, fwd_out_ids_0, fwd_out_ids_1 = fwd_comp._generate_output_double_ids()

            bwd_in_ids_0 = ["_".join(id_.split("_")[:-2] + ["backward"] + id_.split("_")[-2:]) for id_ in fwd_out_ids_0]
            bwd_in_ids_1 = ["_".join(id_.split("_")[:-2] + ["backward"] + id_.split("_")[-2:]) for id_ in fwd_out_ids_1]

            for i in range(out_size):
                inv_id = f"incompatibility_{cid}_{i}"
                incompat_ids.append(inv_id)
                self._model_constraints.extend(
                    utils.incompatibility(
                        inv_id, (fwd_out_ids_0[i], fwd_out_ids_1[i]), (bwd_in_ids_0[i], bwd_in_ids_1[i])
                    )
                )

        self._model_constraints.append(" ".join(incompat_ids))

        solution = self.solve(IMPOSSIBLE_XOR_DIFFERENTIAL, solver_name=solver_name, options=options)
        solution["building_time"] = time.time() - start
        return solution

    def find_one_bitwise_impossible_xor_differential_trail_with_fully_automatic_model(
        self, fixed_values=[], include_all_components=False, solver_name=solvers.SOLVER_DEFAULT, options=None
    ):
        """
        Returns one bitwise impossible XOR differential trail.

        INPUTS:

        - ``solver_name`` -- *str*, the solver to call
        - ``fixed_values`` -- *list of dict*, the variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)
        - ``include_all_components`` -- **boolean** (default: `False`); when set to `True`, every component output can be
          a source of incompatibility; otherwise, only round outputs are considered

        EXAMPLES::

            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: simon = SimonBlockCipher(block_bit_size=32, number_of_rounds=11)
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_impossible_xor_differential_model import SatBitwiseImpossibleXorDifferentialModel
            sage: sat = SatBitwiseImpossibleXorDifferentialModel(simon)
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32), bit_values=[0]*31 + [1])
            sage: key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0]*64)
            sage: key_backward = set_fixed_variables(component_id='key_backward', constraint_type='equal', bit_positions=range(64), bit_values=[0]*64)
            sage: ciphertext_backward = set_fixed_variables(component_id='cipher_output_10_13_backward', constraint_type='equal', bit_positions=range(32), bit_values=[0]*6 + [2,0,2] + [0]*23)
            sage: trail = sat.find_one_bitwise_impossible_xor_differential_trail_with_fully_automatic_model(fixed_values=[plaintext, key, key_backward, ciphertext_backward])


            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.permutations.ascon_sbox_sigma_permutation import AsconSboxSigmaPermutation
            sage: ascon = AsconSboxSigmaPermutation(number_of_rounds=5)
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_impossible_xor_differential_model import SatBitwiseImpossibleXorDifferentialModel
            sage: sat = SatBitwiseImpossibleXorDifferentialModel(ascon)
            sage: P = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(320), bit_values= [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] )
            sage: trail = sat.find_one_bitwise_impossible_xor_differential_trail_with_fully_automatic_model(fixed_values=[P])
        """

        start = time.time()
        self._forward_cipher = self._cipher
        self._backward_cipher = self._cipher.cipher_inverse().add_suffix_to_components("_backward")

        self.build_bitwise_impossible_xor_differential_trail_model(fixed_variables=fixed_values)

        backward_components = []
        forward_output = [c for c in self._forward_cipher.get_all_components() if c.type == CIPHER_OUTPUT][0]
        forward_output_id = forward_output.id + "_backward"

        for comp in self._backward_cipher.get_all_components():
            if comp.description == ["round_output"]:
                if set(comp.input_id_links) == {forward_output_id}:
                    continue
                backward_components.append(comp)

        if include_all_components:
            key_flow = set(get_key_schedule_component_ids(self._cipher))
            backward_key_ids = {f"{k_id}_backward" for k_id in key_flow}
            backward_components = [
                c for c in self._backward_cipher.get_all_components() if c.id not in backward_key_ids
            ]

        incompat_ids = []
        for comp in backward_components:
            comp_id = comp.id
            try:
                fwd_comp = self._forward_cipher.get_component_from_id(comp_id.replace("_backward", ""))
            except ValueError:
                # Skip this backward component because we can't map it to a forward component (es: plaintext_backward).
                continue

            out_size, fwd_out_ids_0, fwd_out_ids_1 = fwd_comp._generate_output_double_ids()

            bwd_in_ids_0 = ["_".join(id_.split("_")[:-2] + ["backward"] + id_.split("_")[-2:]) for id_ in fwd_out_ids_0]
            bwd_in_ids_1 = ["_".join(id_.split("_")[:-2] + ["backward"] + id_.split("_")[-2:]) for id_ in fwd_out_ids_1]

            for i in range(out_size):
                inv_id = f"incompatibility_{fwd_comp.id}_{i}"
                incompat_ids.append(inv_id)
                self._model_constraints.extend(
                    utils.incompatibility(
                        inv_id, (fwd_out_ids_0[i], fwd_out_ids_1[i]), (bwd_in_ids_0[i], bwd_in_ids_1[i])
                    )
                )

        if incompat_ids:
            self._model_constraints.append(" ".join(incompat_ids))

        solution = self.solve(IMPOSSIBLE_XOR_DIFFERENTIAL, solver_name=solver_name, options=options)
        solution["building_time"] = time.time() - start

        return solution

    def _parse_solver_output(self, variable_to_value):
        active_incompatibilities = [
            var for var, val in variable_to_value.items() if var.startswith("incompatibility_") and val == 1
        ]

        incompatible_components = set()
        for var in active_incompatibilities:
            parts = var.split("_")
            comp_id = "_".join(parts[1:-1])
            incompatible_components.add(comp_id)

        components_solutions = self._get_cipher_inputs_components_solutions_double_ids(variable_to_value)

        if not incompatible_components:
            for component in self._cipher.get_all_components():
                value = self._get_component_value_double_ids(component, variable_to_value)
                components_solutions[component.id] = set_component_solution(value)
            return components_solutions, None

        incompatible_rounds = {}
        for comp_id in incompatible_components:
            round_num = self._cipher.get_round_from_component_id(comp_id)
            incompatible_rounds.setdefault(round_num, set()).add(comp_id)

        first_incompatible_round = min(incompatible_rounds)

        for component in self._cipher.get_all_components():
            comp_id = component.id
            comp_round = self._cipher.get_round_from_component_id(comp_id)

            if comp_round < first_incompatible_round:
                value = self._get_component_value_from_cipher(component, variable_to_value, "forward")
                components_solutions[comp_id] = set_component_solution(value)

            elif comp_round in incompatible_rounds and comp_id in incompatible_rounds[comp_round]:
                fwd = self._get_component_value_from_cipher(component, variable_to_value, "forward")
                bwd = self._get_component_value_from_cipher(component, variable_to_value, "backward")
                components_solutions[comp_id] = set_component_solution(fwd)
                components_solutions[comp_id + "_backward"] = set_component_solution(bwd)

            elif comp_round > first_incompatible_round:
                bwd = self._get_component_value_from_cipher(component, variable_to_value, "backward")
                components_solutions[comp_id + "_backward"] = set_component_solution(bwd)

            else:
                value = self._get_component_value_double_ids(component, variable_to_value)
                components_solutions[comp_id] = set_component_solution(value)

        return components_solutions, None

    def _get_component_value_from_cipher(self, component, variable_to_value, cipher_type):
        if cipher_type == "forward":
            forward_component = self._forward_cipher.get_component_from_id(component.id)
            return self._get_component_value_double_ids(forward_component, variable_to_value)

        if cipher_type == "backward":
            backward_id = f"{component.id}_backward"
            values = []
            for i in range(component.output_bit_size):
                variable_value = 0
                if f"{backward_id}_{i}_0" in variable_to_value:
                    variable_value ^= variable_to_value[f"{backward_id}_{i}_0"] << 1
                if f"{backward_id}_{i}_1" in variable_to_value:
                    variable_value ^= variable_to_value[f"{backward_id}_{i}_1"]
                values.append(f"{variable_value}")
            backward_component_value = "".join(values).replace("2", "?").replace("3", "?")
            return backward_component_value

        return self._get_component_value_double_ids(component, variable_to_value)
