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


from claasp.components.modular_component import Modular


class ModMul(Modular):
    """
    Construct a modular multiplication component.


    INPUT:

    - ``current_round_number`` -- **integer**; round index where the component is created. ``0`` is valid.
    - ``current_round_number_of_components`` -- **integer**; index of the component inside the round. ``0`` is valid.
    - ``input_id_links`` -- **list**; input component identifiers (usually strings). Must align with ``input_bit_positions``.
    - ``input_bit_positions`` -- **list**; bit positions for each input identifier (list of lists). Must align with ``input_id_links``.
    - ``output_bit_size`` -- **integer**; output size in bits. ``0`` is valid only when supported by the component semantics.
    - ``modulus`` -- **integer**; modulus used by modular arithmetic operations. Must be greater than ``0``.

    NOTE:

        The number of operands is automatically inferred as
        ``sum(len(p) for p in input_bit_positions) / output_bit_size``.
        Multiple operands are fully supported: the result is computed as a left-to-right sequential
        multiplication ``(a0 * a1 * a2 * ...) mod 2^output_bit_size``.

    EXAMPLES::

        sage: from claasp.components.modmul_component import ModMul
        sage: component = ModMul(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2, 2)
        sage: print(component.id)
        modmul_0_0
        sage: print(component.type)
        word_operation
        sage: print(component.description)  # 4 total bits / output_bit_size 2 = 2 operands
        ['MODMUL', 2, 2]
        sage: component3 = ModMul(0, 1, ['a', 'b', 'c'], [[0, 1], [0, 1], [0, 1]], 2, 4)
        sage: print(component3.description)  # 6 total bits / output_bit_size 2 = 3 operands
        ['MODMUL', 3, 4]
    """
    def __init__(
        self,
        current_round_number,
        current_round_number_of_components,
        input_id_links,
        input_bit_positions,
        output_bit_size,
        modulus,
    ):
        super().__init__(
            current_round_number,
            current_round_number_of_components,
            input_id_links,
            input_bit_positions,
            output_bit_size,
            "modmul",
            modulus,
        )

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        return [
            f"  {self.id} = bit_vector_MODMUL([{','.join(params)} ], {self.description[1]}, {self.output_bit_size})"
        ]

    def get_byte_based_vectorized_python_code(self, params):
        return [f"  {self.id} = byte_vector_MODMUL({params})"]
