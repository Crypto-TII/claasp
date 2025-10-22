
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

from claasp.round import Round
from claasp.DTOs.power_of_2_word_based_dto import PowerOf2WordBasedDTO


class Rounds:
    def __init__(self):
        self._current_round_number = None  # No rounds added on creation
        self._rounds = []

    def add_component(self, component):
        self.current_round.add_component(component)

    def add_round(self):
        if self._current_round_number is None:
            self._current_round_number = 0  # Rounds start counting from 0
        else:
            self._current_round_number += 1
        self._rounds.append(Round(self._current_round_number))

    def are_there_not_forbidden_components(self, forbidden_types, forbidden_descriptions):
        for cipher_round in self._rounds:
            are_there_forbidden_components = cipher_round.are_there_forbidden_components(forbidden_types,
                                                                                         forbidden_descriptions)
            if are_there_forbidden_components:
                return not are_there_forbidden_components

        return True

    def component_from(self, round_number, position):
        """
        Use this function to get a certain component from a certain round.

        INPUT:

        - ``round_number`` -- **integer**; the round number of the component
        - ``position`` -- **integer**; position of the component in a round

        EXAMPLES::

            sage: from claasp.rounds import Rounds
            sage: from claasp.component import Component
            sage: from claasp.input import Input
            sage: rounds = Rounds()
            sage: rounds.add_round()
            sage: component_input = Input(4, ["input","input"], [[0,1],[2,3]])
            sage: xor_0_0 = Component("xor_0_0", "xor", component_input, 2, "xor_0_0")
            sage: xor_0_1 = Component("xor_0_1", "xor", component_input, 2, "xor_0_1")
            sage: rounds.add_component(xor_0_0)
            sage: rounds.add_component(xor_0_1)
            sage: rounds.add_round()
            sage: xor_1_0 = Component("xor_1_0", "xor", component_input, 2, "xor_1_0")
            sage: xor_1_1 = Component("xor_1_1", "xor", component_input, 2, "xor_1_1")
            sage: rounds.add_component(xor_1_0)
            sage: rounds.add_component(xor_1_1)
            sage: component_0_0 = rounds.component_from(0, 0)
            sage: component_0_0.print()
                id = xor_0_0
                type = xor
                input_bit_size = 4
                input_id_link = ['input', 'input']
                input_bit_positions = [[0, 1], [2, 3]]
                output_bit_size = 2
                description = xor_0_0
            sage: component_1_0 = rounds.component_from(1, 0)
            sage: component_1_0.print()
                id = xor_1_0
                type = xor
                input_bit_size = 4
                input_id_link = ['input', 'input']
                input_bit_positions = [[0, 1], [2, 3]]
                output_bit_size = 2
                description = xor_1_0
        """
        requested_round = self.round_at(round_number)

        return requested_round.component_from(position)

    def components_in_round(self, round_number):
        return self.round_at(round_number).components

    def get_all_components(self):
        components = []
        for cipher_round in self._rounds:
            components += cipher_round.components

        return components

    def get_all_components_ids(self):
        components_ids = []
        for cipher_round in self._rounds:
            components_ids += cipher_round.get_components_ids()

        return components_ids

    def get_component_from_id(self, component_id):
        for cipher_round in self._rounds:
            component = cipher_round.get_component_from_id(component_id)
            if component is not None:
                return component
        raise ValueError(f'Component with id {component_id} not found.')

    def get_round_from_component_id(self, component_id):
        for cipher_round in self._rounds:
            round_number = cipher_round.get_round_from_component_id(component_id)

            if round_number is not None:
                return round_number

        return -1

    def is_power_of_2_word_based(self):
        dto = PowerOf2WordBasedDTO()

        for cipher_round in self._rounds:
            dto = cipher_round.is_power_of_2_word_based(dto)
            if dto.word_size is False:
                break

        return dto.word_size

    def number_of_components(self, round_number):
        return self._rounds[round_number].number_of_components

    def print_rounds(self):
        for round_number in range(self.number_of_rounds):
            requested_round = self.round_at(round_number)
            requested_round.print_round()

    def print_rounds_as_python_dictionary(self):
        for round_number in range(self.number_of_rounds):
            requested_round = self.round_at(round_number)
            requested_round.print_round_as_python_dictionary()
    
    def add_prefix(self, prefix='upper_'):
        for round_number in range(self.number_of_rounds):
            requested_round = self.round_at(round_number)
            requested_round.add_prefix(prefix)

    def remove_prefix(self, prefix='upper_'):
        for round_number in range(self.number_of_rounds):
            requested_round = self.round_at(round_number)
            requested_round.remove_prefix(prefix)

    def remove_round_component(self, round_number, component):
        self._rounds[round_number].remove_component(component)

    def remove_round_component_from_id(self, round_number, component_id):
        self._rounds[round_number].remove_component_from_id(component_id)

    def round_at(self, round_number):
        return self._rounds[round_number]

    def rounds_as_python_dictionary(self):
        rounds_dictionary = []
        for round_number in range(self.number_of_rounds):
            requested_round = self.round_at(round_number)
            rounds_dictionary.append(requested_round.round_as_python_dictionary())

        return rounds_dictionary

    @property
    def current_round(self):
        return self._rounds[self._current_round_number]

    @property
    def current_round_number(self):
        return self._current_round_number

    @property
    def current_round_number_of_components(self):
        return self.current_round.number_of_components

    @property
    def number_of_rounds(self):
        return len(self._rounds)

    @property
    def rounds(self):
        return self._rounds
