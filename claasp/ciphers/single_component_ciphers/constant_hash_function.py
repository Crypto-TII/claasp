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


from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import HASH_FUNCTION

PARAMETERS_CONFIGURATION_LIST = [{"output_bit_size": 3, "value": 0b010}]


class ConstantHashFunction(SingleComponentCipher):
    """
    Return a single-component constant-output cipher.

    This wrapper uses ``hash_function`` as a fallback cipher type because a constant output is neither a
    permutation nor a block cipher.

    INPUT:

    - ``output_bit_size`` -- **integer** (default: `3`); output bit size of the constant component
    - ``value`` -- **integer** (default: `0b010`); constant value emitted by the cipher

    EXAMPLES::

        sage: from claasp.ciphers.single_component_ciphers.constant_hash_function import ConstantHashFunction
        sage: constant = ConstantHashFunction(output_bit_size=3, value=0b101)
        sage: constant.type
        'hash_function'

        sage: constant.number_of_rounds
        1

        sage: constant.component_from(0, 0).id
        'constant_0_0'

        sage: constant.evaluate([])
        5
    """

    def __init__(self, output_bit_size=3, value=0b010):
        super().__init__(
            family_name="constant_hash_function",
            cipher_type=HASH_FUNCTION,
            cipher_inputs=[],
            cipher_inputs_bit_size=[],
            cipher_output_bit_size=output_bit_size,
        )
        constant_component = self.add_constant_component(output_bit_size, value)
        add_cipher_output_from_component(self, constant_component)