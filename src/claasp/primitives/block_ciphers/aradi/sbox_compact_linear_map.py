"""Legacy-derived compact-linear-map S-box realization of Aradi."""

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

from claasp.graph.bit_builder import BitGraphPrimitive, linear_layer_to_binary_matrix
from claasp.primitive_inputs import BLOCK_CIPHER, INPUT_KEY, INPUT_PLAINTEXT

input_types = [INPUT_KEY, INPUT_PLAINTEXT]
PARAMETERS_CONFIGURATION_LIST = [{"number_of_rounds": 16}]


def get_key_word_bit_indexes(word_index):
    return list(range(32 * (8 - word_index - 1), 32 * (8 - word_index)))


def circular_shift_left_bitarray(bitarray, shift):
    """Perform a circular left shift on a BitArray."""
    return bitarray[shift:] + bitarray[:shift]


def aradi_linear_layer_bitarray(input_bitarray, a_shift, b_shift, c_shift):
    assert len(input_bitarray) == 32, "Input must be a 32-bit BitArray."
    upper = input_bitarray[:16]
    lower = input_bitarray[16:]
    shifted_upper_a = circular_shift_left_bitarray(upper, a_shift)
    shifted_upper_b = circular_shift_left_bitarray(upper, b_shift)
    shifted_lower_c = circular_shift_left_bitarray(lower, c_shift)
    shifted_upper_al = circular_shift_left_bitarray(lower, a_shift)
    new_upper = upper ^ shifted_upper_a ^ shifted_lower_c
    new_lower = lower ^ shifted_upper_al ^ shifted_upper_b
    output_bitarray = new_upper + new_lower
    return output_bitarray


def create_linear_layers(shift_a, shift_b, shift_c):
    linear_layers = []
    for i in range(4):
        aradi_linear_layer = linear_layer_to_binary_matrix(
            lambda input_bitarray, a=shift_a[i], b=shift_b[i], c=shift_c[i]: (
                aradi_linear_layer_bitarray(input_bitarray, a, b, c)
            ),
            32,
            32,
            [],
        )
        aradi_linear_layer = aradi_linear_layer.rows()
        linear_layers.append([list(row) for row in zip(*aradi_linear_layer)])

    return linear_layers


class AradiSBoxCompactLinearMap(BitGraphPrimitive):
    """
    Creates a block primitive with SBox components and compact linear layers, where linear operations are defined
    using binary matrices instead of traditional shift and XOR operations.

    This class is used to store compact representations of a primitive,
    used to generate the corresponding primitive.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `64`); the bit size of the primitive's input and output blocks.
    - ``key_bit_size`` -- **integer** (default: `128`); primitive key bit size of the primitive
    - ``number_of_rounds`` -- **integer** (default: `0`); number of rounds of the primitive.
    - ``sub_keys_zero`` -- **boolean** (default: `False`)
    - ``transformations_flag`` -- **boolean** (default: `True`)

    EXAMPLES::

        >>> primitive = AradiSBoxCompactLinearMap()
        >>> inputs = {name: 0 for name in primitive.graph.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0xd06c8ab75d191521', 128)
    """

    def __init__(self, number_of_rounds=16):
        self.block_bit_size = 128
        self.key_bit_size = 256
        self.WORD_SIZE = 32
        self.SBOX = [0, 1, 2, 3, 4, 13, 15, 6, 8, 11, 5, 14, 12, 7, 10, 9]

        super().__init__(
            family_name="aradi",
            primitive_type=BLOCK_CIPHER,
            primitive_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            primitive_inputs_bit_size=[self.block_bit_size, self.key_bit_size],
            primitive_output_bit_size=self.block_bit_size,
        )
        self.A = [11, 10, 9, 8]
        self.B = [8, 9, 4, 9]
        self.C = [14, 11, 14, 7]

        self.linear_layers = create_linear_layers(self.A, self.B, self.C)

        state = INPUT_PLAINTEXT
        key = INPUT_KEY

        for round_i in range(number_of_rounds):
            self._builder.add_round()
            round_key = self.get_round_key_id(key, round_i)
            state = self.round_function(state, round_key, round_i)
            key = self.update_key(key, round_i)

        round_key = self.get_round_key_id(key, 0)
        w = self.add_xor_component([round_key, state], [list(range(32)), list(range(32))], 32).id
        x = self.add_xor_component(
            [round_key, state], [list(range(32, 64)), list(range(32, 64))], 32
        ).id
        y = self.add_xor_component(
            [round_key, state], [list(range(64, 96)), list(range(64, 96))], 32
        ).id
        z = self.add_xor_component(
            [round_key, state], [list(range(96, 128)), list(range(96, 128))], 32
        ).id
        self.add_primitive_output_component([w, x, y, z], [list(range(32)) for _ in range(4)], 128)

    def get_round_key_id(self, key, round_i):
        """Return the round key id used while authoring this primitive graph."""
        j = round_i % 2
        return self.add_round_key_output_component(
            [key, key, key, key], [get_key_word_bit_indexes(4 * j + i) for i in range(4)], 128
        ).id

    def l_function(self, xy_id_links, xy_input_bits, round_index):
        """Build the l function stage in this primitive's typed operation graph."""
        j = round_index % 4
        aradi_linear_layer = self.linear_layers[j]

        l_function_output = self.add_linear_layer_component(
            xy_id_links, xy_input_bits, 32, aradi_linear_layer
        )

        return l_function_output

    def m_function(self, i, j, xy_id_links, xy_input_bits):
        """Build the m function stage in this primitive's typed operation graph."""
        y_indices = xy_input_bits[32:64]
        x_indices = xy_input_bits[:32]
        rot_i_y = self.add_rotate_component(xy_id_links, [y_indices], 32, -i).id
        rot_j_x = self.add_rotate_component(xy_id_links, [x_indices], 32, -j).id
        left_part = self.add_xor_component(
            xy_id_links + [rot_i_y, rot_j_x], [x_indices] + [list(range(32)) for _ in range(2)], 32
        ).id
        right_part = self.add_xor_component(
            xy_id_links + [rot_i_y], [x_indices] + [list(range(32))], 32
        ).id
        return left_part, right_part

    def update_key(self, key, round_i):
        """Build the update key transition in this primitive's typed operation graph."""
        round_constant = self.add_constant_component(32, round_i).id
        k1, k0 = self.m_function(
            1, 3, [key], get_key_word_bit_indexes(1) + get_key_word_bit_indexes(0)
        )
        key_word_bit_indexes = get_key_word_bit_indexes(3) + get_key_word_bit_indexes(2)
        k3, k2 = self.m_function(9, 28, [key], key_word_bit_indexes)
        key_word_bit_indexes = get_key_word_bit_indexes(5) + get_key_word_bit_indexes(4)
        k5, k4 = self.m_function(1, 3, [key], key_word_bit_indexes)
        key_word_bit_indexes = get_key_word_bit_indexes(7) + get_key_word_bit_indexes(6)
        k7, k6 = self.m_function(9, 28, [key], key_word_bit_indexes)
        k7 = self.add_xor_component(
            [k7, round_constant], [list(range(32)) for _ in range(2)], 32
        ).id
        if round_i % 2 == 0:
            updated_key = self.add_intermediate_output_component(
                [k7, k5, k6, k4, k3, k1, k2, k0],
                [list(range(32)) for _ in range(8)],
                256,
                f"key_{round_i}",
            )
        else:
            updated_key = self.add_intermediate_output_component(
                [k7, k3, k5, k1, k6, k2, k4, k0],
                [list(range(32)) for _ in range(8)],
                256,
                f"key_{round_i}",
            )
        return updated_key.id

    def round_function(self, state, round_key, round_i):
        """Build the round function stage in this primitive's typed operation graph."""

        def create_xor_component(start_idx, length=32):
            return self.add_xor_component(
                [round_key, state],
                [
                    list(range(start_idx, start_idx + length)),
                    list(range(start_idx, start_idx + length)),
                ],
                length,
            ).id

        w, x, y, z = [create_xor_component(i * 32) for i in range(4)]
        sb_outputs = [
            self.add_sbox_component([w, x, y, z], [[i], [i], [i], [i]], 4, self.SBOX).id
            for i in range(32)
        ]

        self.add_intermediate_output_component(
            sb_outputs * 4, [[i] for i in range(4)] * 32, 128, f"sbox_output_{round_i}"
        )

        def process_linear_layer(bit_idx):
            id_links = [sb_id for sb_id in sb_outputs]
            input_bits = [[bit_idx] for _ in sb_outputs]
            return self.l_function(id_links, input_bits, round_i)

        w_function_output = process_linear_layer(0)
        x_function_output = process_linear_layer(1)
        y_function_output = process_linear_layer(2)
        z_function_output = process_linear_layer(3)

        state = self.add_round_output_component(
            [
                w_function_output.id,
                x_function_output.id,
                y_function_output.id,
                z_function_output.id,
            ],
            [list(range(32)) for _ in range(4)],
            128,
        )

        return state.id
