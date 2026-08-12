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

from claasp.cipher import Cipher
from claasp.DTOs.component_state import ComponentState
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY, PERMUTATION
from claasp.utils.utils import get_inputs_parameter
from enum import Enum


class Version(Enum):
    V1 = 1
    V2 = 2


class SubterraneanPermutation(Cipher):
    """
    Construct an instance of the SubterraneanPermutation class.

    This class is used to store compact representations of a cipher, used to generate the corresponding.

    REFERENCES:
        [CDGP1993]_, [DMR2019]_, [NISTLWCSUB].

    INPUT:

        - ``number_of_rounds`` -- **integer** (default: `1`); number of rounds of the permutation
        - ``version`` -- **Version** (default: `Version.V1`); version of the permutation

    EXAMPLES::

        sage: from claasp.ciphers.permutations.subterranean_permutation import SubterraneanPermutation
        sage: subt = SubterraneanPermutation()
        sage: subt.number_of_rounds
        1

        sage: hex(subt.evaluate([0, 0]))
        '0xfffffffffffffffefffff7ffffffffffffffffffffffffffffffffffffffffff'
    """

    def __init__(self, number_of_rounds=1, version=Version.V1):
        self.state_bit_size = 257
        self.key_bit_size = 256

        super().__init__(
            family_name='subterranean', cipher_type=PERMUTATION, cipher_inputs=[
                INPUT_PLAINTEXT, INPUT_KEY] if version == Version.V1 else [INPUT_PLAINTEXT], cipher_inputs_bit_size=[
                self.state_bit_size, self.key_bit_size] if version == Version.V1 else [
                self.state_bit_size], cipher_output_bit_size=self.state_bit_size, )

        input = ComponentState([INPUT_PLAINTEXT], [list(range(self.state_bit_size))])
        key = ComponentState([INPUT_KEY], [list(range(self.key_bit_size))])

        rounds = number_of_rounds

        for r in range(rounds):
            self.add_round()

            input = self._step_1(input) if version == Version.V1 else self._chi(input)
            input = self._step_2(input)
            input = self._step_3(input)
            if version == Version.V1:
                input = self._step_4(input, key)
            input = self._step_5(input)

            ids, bits = get_inputs_parameter([input])
            if r == rounds - 1:
                self.add_cipher_output_component(ids, bits, self.state_bit_size)
            else:
                self.add_round_output_component(ids, bits, self.state_bit_size)

    def _rotate(self, input: ComponentState, size: int, parameter: int) -> ComponentState:
        ids, bits = get_inputs_parameter([input])
        self.add_rotate_component(ids, bits, size, parameter)
        return ComponentState([self.get_current_component_id()], [list(range(size))])

    def _step_1(self, input: ComponentState) -> ComponentState:

        a2 = self._rotate(input, self.state_bit_size, -2)

        ids, bits = get_inputs_parameter([a2])
        neg = self.add_not_component(ids, bits, self.state_bit_size)

        a2 = ComponentState([neg.id], [list(range(self.state_bit_size))])

        a1 = self._rotate(input, self.state_bit_size, -1)

        ids, bits = get_inputs_parameter([a1, a2])
        a = self.add_or_component(ids, bits, self.state_bit_size)

        ids, bits = get_inputs_parameter([input])
        self.add_xor_component(ids + [a.id], bits + [list(range(self.state_bit_size))], self.state_bit_size)

        return ComponentState([self.get_current_component_id()], [list(range(self.state_bit_size))])

    def _step_2(self, input: ComponentState) -> ComponentState:
        # negation of the first bit
        neg = self.add_not_component([input.id[0]], [[input.input_bit_positions[0][0]]], 1)

        return ComponentState([neg.id, *input.id], [[0], input.input_bit_positions[0][1:]])

    def _step_3(self, input: ComponentState) -> ComponentState:
        a3 = self._rotate(input, self.state_bit_size, -3)
        a8 = self._rotate(input, self.state_bit_size, -8)

        ids, bits = get_inputs_parameter([input, a3, a8])
        self.add_xor_component(ids, bits, self.state_bit_size)

        return ComponentState([self.get_current_component_id()], [list(range(self.state_bit_size))])

    def _step_4(self, input: ComponentState, key: ComponentState) -> ComponentState:
        xor = self.add_xor_component([input.id[0], key.id[0]], [input.input_bit_positions[0]
                                     [1:]] + key.input_bit_positions, self.state_bit_size - 1)
        return ComponentState(
            [input.id[0], xor.id],
            [[input.input_bit_positions[0][0]], list(range(self.key_bit_size))]
        )

    def _step_5(self, input: ComponentState) -> ComponentState:
        permutation = [(pow(12, -1, self.state_bit_size) * i) % self.state_bit_size for i in range(self.state_bit_size)]
        ids, bits = get_inputs_parameter([input])
        self.add_permutation_component(ids, bits, self.state_bit_size, permutation)
        return ComponentState([self.get_current_component_id()], [list(range(self.state_bit_size))])

    def _chi(self, input: ComponentState) -> ComponentState:
        s1 = self._rotate(input, self.state_bit_size, - 1)

        ids, bits = get_inputs_parameter([s1])
        self.add_not_component(ids, bits, self.state_bit_size)

        not_s1 = ComponentState([self.get_current_component_id()], [list(range(self.state_bit_size))])

        s2 = self._rotate(input, self.state_bit_size, -2)

        ids, bits = get_inputs_parameter([not_s1, s2])

        mul = self.add_and_component(ids, bits, self.state_bit_size)

        self.add_xor_component(input.id + [mul.id], input.input_bit_positions +
                               [list(range(self.state_bit_size))], self.state_bit_size)
        return ComponentState([self.get_current_component_id()], [list(range(self.state_bit_size))])
