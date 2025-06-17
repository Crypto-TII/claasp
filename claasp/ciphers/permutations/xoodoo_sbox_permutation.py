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


from copy import deepcopy

from sage.rings.polynomial.polynomial_ring_constructor import PolynomialRing
from sage.rings.finite_rings.finite_field_constructor import GF

from claasp.cipher import Cipher
from claasp.name_mappings import INPUT_PLAINTEXT, PERMUTATION
from claasp.DTOs.component_state import ComponentState
from claasp.utils.utils import (
    simplify_inputs,
    get_ci,
    calculate_inputs,
    create_new_state_for_calculation,
    layer_and_lane_initialization,
)

LANE_NUM = 4
PLANE_NUM = 3
SBOX_SIZE = 3
LANE_SIZE = 32
THETA_ROT = [{"x": 1, "z": 5}, {"x": 1, "z": 14}]
RHOWEST_ROT = [{"x": 0, "z": 0}, {"x": 1, "z": 0}, {"x": 0, "z": 11}]
RHOEAST_ROT = [{"x": 0, "z": 0}, {"x": 0, "z": 1}, {"x": 2, "z": 8}]
SBOX = [0, 5, 3, 2, 6, 1, 4, 7]
PLANE_SIZE = LANE_NUM * LANE_SIZE
PARAMETERS_CONFIGURATION_LIST = [{"number_of_rounds": 12}]

R = PolynomialRing(GF(2), "t")
t = R.gen()
QI = {
    0: 1,
    6: 1 + t**2,
    5: 1 + t + t**2,
    4: t + t**2,
    3: 1 + t,
    2: t**2,
    1: t,
}
SI = {
    0: 1,
    5: 5,
    4: 4,
    3: 6,
    2: 2,
    1: 3,
}


class XoodooSboxPermutation(Cipher):
    """
    Construct an instance of the XoodooSboxPermutation class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

    - ``number_of_rounds`` -- **integer** (default: `12`); number of rounds of the cipher

    EXAMPLES::

        sage: from claasp.ciphers.permutations.xoodoo_sbox_permutation import XoodooSboxPermutation
        sage: xoodoo_permutation_sbox = XoodooSboxPermutation(number_of_rounds=3)
        sage: xoodoo_permutation_sbox.number_of_rounds
        3

        sage: xoodoo_permutation_sbox.component_from(0, 0).id
        'xor_0_0'
    """

    def __init__(self, number_of_rounds=12):
        self.state_bit_size = PLANE_NUM * PLANE_SIZE

        super().__init__(
            family_name="xoodoo_sbox",
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[self.state_bit_size],
            cipher_output_bit_size=self.state_bit_size,
        )

        planes = layer_and_lane_initialization()

        # round function
        for r in range(0, number_of_rounds):
            self.add_round()

            # round parameter
            round_i = r - number_of_rounds + 1
            ci = get_ci(round_i, QI, SI, t)
            planes = self.round_function(planes, ci)

            self.add_output_component(number_of_rounds, planes, r)

    def add_output_component(self, number_of_rounds, planes, r):
        inputs_id, inputs_pos = calculate_inputs(planes)
        inputs_id, inputs_pos = simplify_inputs(inputs_id, inputs_pos)
        is_last_round = r == number_of_rounds - 1
        if is_last_round:
            self.add_cipher_output_component(inputs_id, inputs_pos, self.state_bit_size)
        else:
            self.add_round_output_component(inputs_id, inputs_pos, self.state_bit_size)

    def apply_sbox_to_each_3bit_column(self, planes, planes_new):
        for j in range(LANE_NUM):
            for k in range(LANE_SIZE):
                inputs_id = []
                inputs_pos = []
                for i in range(PLANE_NUM):
                    inputs_id += [planes[i].id[j]]
                    inputs_pos += [[planes[i].input_bit_positions[j][k]]]
                self.add_SBOX_component(inputs_id, inputs_pos, SBOX_SIZE, SBOX)
                for i in range(PLANE_NUM):
                    planes_new[i].id[j] += [self.get_current_component_id()]
                    planes_new[i].input_bit_positions[j] += [[i]]
        planes = deepcopy(planes_new)

        return planes

    def chi_definition(self, planes):
        planes_new = create_new_state_for_calculation()
        planes = self.apply_sbox_to_each_3bit_column(planes, planes_new)

        return planes

    def iota_definition(self, ci, planes):
        # create Ci
        self.add_constant_component(LANE_SIZE, ci)
        c = ComponentState([self.get_current_component_id()], [list(range(LANE_SIZE))])
        # A0,0 = A0,0 + Ci
        inputs_id = c.id + [planes[0].id[0]]
        inputs_pos = c.input_bit_positions + [planes[0].input_bit_positions[0]]
        self.add_XOR_component(inputs_id, inputs_pos, LANE_SIZE)
        planes[0].id[0] = self.get_current_component_id()
        planes[0].input_bit_positions[0] = list(range(LANE_SIZE))

    def rhoeast_definition(self, planes):
        # Ai = Ai <<< (roheast_rot[i][x], rohwest_rot[i][z])
        for i in range(1, 3):
            planes[i] = self.rotate_x_z(planes[i], RHOEAST_ROT[i]["x"], RHOEAST_ROT[i]["z"])

        return planes

    def rhowest_definition(self, planes):
        # Ai = Ai <<< (rohwest_rot[i][x], rohwest_rot[i][z])
        for i in range(1, 3):
            planes[i] = self.rotate_x_z(planes[i], RHOWEST_ROT[i]["x"], RHOWEST_ROT[i]["z"])

    def rotate_x_z(self, plane, rotx, rotz):
        # x direction rotation
        new_plane = ComponentState(
            [deepcopy(plane.id[(j - rotx) % LANE_NUM]) for j in range(LANE_NUM)],
            [deepcopy(plane.input_bit_positions[(j - rotx) % LANE_NUM]) for j in range(LANE_NUM)],
        )

        # z direction rotation
        if rotz != 0:
            for j in range(LANE_NUM):
                if isinstance(new_plane.id[j], list):
                    lanej = ComponentState(new_plane.id[j], new_plane.input_bit_positions[j])
                else:
                    lanej = ComponentState([new_plane.id[j]], [new_plane.input_bit_positions[j]])
                self.add_rotate_component(lanej.id, lanej.input_bit_positions, LANE_SIZE, rotz)
                new_plane.id[j] = self.get_current_component_id()
                new_plane.input_bit_positions[j] = list(range(LANE_SIZE))

        return new_plane

    def round_function(self, planes, ci):
        self.theta_definition(planes)
        self.rhowest_definition(planes)
        self.iota_definition(ci, planes)
        planes = self.chi_definition(planes)

        return self.rhoeast_definition(planes)

    def theta_definition(self, planes):
        # P = A0+A1+A2
        inputs_id, inputs_pos = calculate_inputs(planes)
        inputs_id, inputs_pos = simplify_inputs(inputs_id, inputs_pos)
        self.add_XOR_component(inputs_id, inputs_pos, PLANE_SIZE)
        p = ComponentState(
            [self.get_current_component_id() for _ in range(LANE_NUM)],
            [[k + j * LANE_SIZE for k in range(LANE_SIZE)] for j in range(LANE_NUM)],
        )
        # Qi = P <<< (theta_rot_i_x, theta_rot_i_z)
        q = []
        for k in range(2):
            q.append(self.rotate_x_z(p, THETA_ROT[k]["x"], THETA_ROT[k]["z"]))
        # P = Q1 + Q2
        inputs_id = []
        inputs_pos = []
        for k in range(2):
            inputs_id = inputs_id + q[k].id
            inputs_pos = inputs_pos + q[k].input_bit_positions
        inputs_id, inputs_pos = simplify_inputs(inputs_id, inputs_pos)
        self.add_XOR_component(inputs_id, inputs_pos, PLANE_SIZE)
        p = ComponentState([self.get_current_component_id()], [list(range(PLANE_SIZE))])
        # Ai = Ai + P
        for i in range(PLANE_NUM):
            inputs_id = []
            inputs_pos = []
            if isinstance(planes[i].id[0], list):
                for j in range(LANE_NUM):
                    inputs_id = inputs_id + planes[i].id[j]
                    inputs_pos = inputs_pos + planes[i].input_bit_positions[j]
            else:
                inputs_id = planes[i].id
                inputs_pos = planes[i].input_bit_positions
            inputs_id = inputs_id + p.id
            inputs_pos = inputs_pos + p.input_bit_positions
            inputs_id, inputs_pos = simplify_inputs(inputs_id, inputs_pos)
            self.add_XOR_component(inputs_id, inputs_pos, PLANE_SIZE)
            plane = ComponentState(
                [self.get_current_component_id() for _ in range(LANE_NUM)],
                [[k + j * LANE_SIZE for k in range(LANE_SIZE)] for j in range(LANE_NUM)],
            )
            planes[i] = plane
