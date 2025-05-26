
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


class Round:
    def __init__(self, round_id):
        self._id = round_id
        self._components = []

    def add_component(self, component):
        self._components.append(component)

    def are_there_forbidden_components(self, forbidden_types, forbidden_descriptions):
        is_there_forbidden_component = False
        for component in self._components:
            is_there_forbidden_component = component.is_forbidden(forbidden_types,
                                                                  forbidden_descriptions)
            if is_there_forbidden_component:
                return is_there_forbidden_component

        return is_there_forbidden_component

    def component_from(self, index):
        return self._components[index]

    def get_component_from_id(self, component_id):
        for component in self._components:
            if component.is_id_equal_to(component_id):
                return component

    def get_components_ids(self):
        return [component.id for component in self._components]

    def get_number_of_components(self):
        # List goes from position 0 to len() - 1
        return self.number_of_components - 1

    def get_round_from_component_id(self, component_id):
        for component in self._components:
            if component.is_id_equal_to(component_id):
                return self._id

    def is_component_input(self, fixed_index, moving_index):
        return self._components[moving_index].id in \
            self._components[fixed_index].input_id_links

    def is_power_of_2_word_based(self, dto):
        for component in self._components:
            dto = component.is_power_of_2_word_based(dto)
            if dto.word_size is False:
                break

        return dto

    def print_round(self):
        for component_number in range(self.number_of_components):
            print("\n    # round = {} - round component = {}"
                  .format(self._id, component_number))
            requested_component = self.component_from(component_number)
            requested_component.print()

    def print_round_as_python_dictionary(self):
        print("  # round", self._id)
        print("  [")
        for component_number in range(self.number_of_components):
            print("  {")
            print(f"    # round = {self._id} - round component = {component_number}")
            requested_component = self.component_from(component_number)
            requested_component.print_as_python_dictionary()
            print("  },")
        print("  ],")

    #################### BOOMERANG #################
    def get_boomerang_representation(self, prefix='upper_'):
        for component_number in range(self.number_of_components):
            requested_component = self.component_from(component_number)
            requested_component.get_boomerang_representation(prefix)
    ################## BOOMERANG #######################

    def remove_component(self, component):
        self._components.remove(component)

    def remove_component_from_id(self, component_id):
        self._components.remove(self.get_component_from_id(component_id))

    def round_as_python_dictionary(self):
        round_dictionary = []
        for component_number in range(self.number_of_components):
            requested_component = self.component_from(component_number)
            round_dictionary.append(requested_component.as_python_dictionary())

        return round_dictionary

    def swap_components(self, fixed_index, moving_index):
        temp = self._components[moving_index]
        self._components[moving_index] = self._components[fixed_index]
        self._components[fixed_index] = temp

    @property
    def components(self):
        return self._components

    @property
    def id(self):
        return self._id

    @property
    def number_of_components(self):
        return len(self._components)

    def update_input_id_links_from_component_id(self, component_id, new_input_id_links):
        i = 0
        for component in self._components:
            if component.id == component_id:
                break
            i += 1
        self._components[i].set_input_id_links(new_input_id_links)

