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

from claasp.cipher_modules.models.cp.mzn_model import MznModel
from claasp.cipher_modules.models.sat.utils.utils import _generate_component_model_types, _set_model_type_for_components


class MznHadipourBoomerangModel(MznModel):
    def __init__(self, cipher, boomerang_structure):
        self.boomerang_structure = boomerang_structure
        self.top_part_number_of_rounds = boomerang_structure["top_part_number_of_rounds"]
        self.middle_part_number_of_rounds = boomerang_structure["middle_part_number_of_rounds"]
        self.bottom_part_number_of_rounds = boomerang_structure["bottom_part_number_of_rounds"]

        total_number_of_rounds = self.top_part_number_of_rounds + self.middle_part_number_of_rounds + self.bottom_part_number_of_rounds
        assert total_number_of_rounds == cipher.number_of_rounds

        e0_cipher = cipher.get_partial_cipher(
            start_round=0,
            end_round=self.top_part_number_of_rounds + self.middle_part_number_of_rounds - 1,
            keep_key_schedule=False
        )
        e1_cipher = cipher.cipher_partial_inverse(
            start_round=self.top_part_number_of_rounds,
            end_round=self.top_part_number_of_rounds + self.middle_part_number_of_rounds + self.bottom_part_number_of_rounds - 1,
            keep_key_schedule=False
        )
        # TODO:: Create a unified cipher from e0_cipher and e1_cipher
        unified_cipher = None
        super().__init__(unified_cipher)

        import ipdb;
        ipdb.set_trace()

    def build_hadipour_boomerang_model(self, weight=-1):
        top_part_components = []
        middle_part_components = []
        bottom_part_components = []

        component_and_model_types = _generate_component_model_types(self.cipher)
        for round_number in range(0, self.top_part_number_of_rounds):
            top_part_components.extend(self.cipher.get_components_in_round(round_number))
        e0_number_of_rounds = self.top_part_number_of_rounds + self.middle_part_number_of_rounds
        for round_number in range(self.top_part_number_of_rounds, e0_number_of_rounds):
            middle_part_components.extend(self.cipher.get_components_in_round(round_number))
        for round_number in range(e0_number_of_rounds, e0_number_of_rounds + self.bottom_part_number_of_rounds):
            bottom_part_components.extend(self.cipher.get_components_in_round(round_number))

        _set_model_type_for_components(
            component_and_model_types,
            middle_part_components,
            model_type="cp_deterministic_truncated_xor_differential_constraints"
        )
        self.build_generic_mzn_model_from_dictionary(component_and_model_types)

        # TODO:: Add Hadipour constraints
