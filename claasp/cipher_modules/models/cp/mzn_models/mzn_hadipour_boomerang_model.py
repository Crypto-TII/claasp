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

        e0em_cipher = cipher.get_partial_cipher(
            start_round=0,
            end_round=self.top_part_number_of_rounds + self.middle_part_number_of_rounds - 1,
            keep_key_schedule=False
        )
        e0em_cipher.add_prefix('upper_')

        e0em_cipher.print_as_python_dictionary()

        eme1_cipher = cipher.cipher_partial_inverse(
            start_round=self.top_part_number_of_rounds,
            end_round=self.top_part_number_of_rounds + self.middle_part_number_of_rounds + self.bottom_part_number_of_rounds - 1,
            keep_key_schedule=False
        )

        eme1_cipher.add_prefix('lower_')

        for i in range(0, self.middle_part_number_of_rounds):
            print(f"len of e0em before {len(e0em_cipher._rounds.rounds[self.top_part_number_of_rounds + i]._components)}")
            print(f"rounds of e0em: {self.top_part_number_of_rounds + i}")
            print(f"rounds of eme1: {self.bottom_part_number_of_rounds + self.middle_part_number_of_rounds -i}")
            e0em_cipher._rounds.rounds[self.top_part_number_of_rounds + i]._components.extend(eme1_cipher._rounds.rounds[self.bottom_part_number_of_rounds +
                                                                                                                        self.middle_part_number_of_rounds -i -1]._components)
            print(f"len of e0em after {len(e0em_cipher._rounds.rounds[self.top_part_number_of_rounds + i]._components)}")
        
        ## add also the last part of e1
        for i in range(0, self.bottom_part_number_of_rounds):
            e0em_cipher._rounds.rounds[self.top_part_number_of_rounds + self.middle_part_number_of_rounds + i]._components.extend(eme1_cipher._rounds.rounds[self.bottom_part_number_of_rounds 
                                                                                                                                                             - i - 1]._components)

        e0em_cipher.print_as_python_dictionary()

        # cipher._rounds.rounds[round_number]._components.extend([regular_component_copy])

        import ipdb;
        ipdb.set_trace()

        


        # TODO:: Create a unified cipher from e0em_cipher and eme1_cipher
        unified_cipher = None
        super().__init__(unified_cipher)

        

    def build_hadipour_boomerang_model(self, weight=-1):
        top_part_components = []
        middle_part_components = []
        bottom_part_components = []

        # creation of e0
        self.cipher.add_prefix('upper_')
        e0_rounds = [0, self.top_part_number_of_rounds] # the actual rounds of e0
        e0_number_of_rounds = self.top_part_number_of_rounds # the number of rounds of e0
        for round_number in range(e0_rounds[0], e0_rounds[1]):
            top_part_components.extend(self.cipher.get_components_in_round(round_number))
        self.cipher.remove_prefix('upper_')

        # creation of em
        self.cipher.add_prefix('middle_')
        em_rounds = [e0_rounds[0], e0_rounds[1] + self.middle_part_number_of_rounds] # the actual rounds of em
        em_number_of_rounds = self.middle_part_number_of_rounds # the number of rounds of em
        for round_number in range(em_rounds[0], em_rounds[1]):
            middle_part_components.extend(self.cipher.get_components_in_round(round_number))
        self.cipher.remove_prefix('middle_')
         
        # creation of e1
        self.cipher.add_prefix('lower_')
        e1_rounds = [em_rounds[1], em_rounds[1] + self.bottom_part_number_of_rounds]
        e1_number_of_rounds = self.bottom_part_number_of_rounds
        for round_number in range(e1_rounds[0], e1_rounds[1]):
            bottom_part_components.extend(self.cipher.get_components_in_round(round_number))
        self.cipher.remove_prefix('lower_')

        # by default we are defining every component to have a pure differential modeling
        component_and_model_types = _generate_component_model_types(
            self.cipher,
            model_type="cp_xor_differential_propagation_constraints"
        )

        # updating the type of modeling only for the middle part
        _set_model_type_for_components(
            component_and_model_types,
            middle_part_components,
            model_type="cp_deterministic_truncated_xor_differential_constraints"
        )

        # I would create a genere mzn model for boomerang attack, so we can take in input the three parts and modify them
        # according their prefix
        self.build_generic_mzn_model_from_dictionary(component_and_model_types)

        # TODO:: Add Hadipour constraints
