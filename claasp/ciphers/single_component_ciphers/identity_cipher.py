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


from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher
from claasp.name_mappings import INPUT_PLAINTEXT, PERMUTATION

PARAMETERS_CONFIGURATION_LIST = [{"block_bit_size": 32}]


class IdentityCipher(SingleComponentCipher):
    """
    Return a cipher object containing the graph representation of the Identity permutation.

    The identity permutation returns the message itself, i.e.
    IdentityPermutation(m) = m.
    This cipher is mainly used for testing.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `32`); cipher input and output block bit size of the cipher

    EXAMPLES::

        sage: from claasp.ciphers.single_component_ciphers.identity_cipher import IdentityCipher
        sage: identity = IdentityCipher()
        sage: identity.type
        'permutation'

        sage: identity.id
        'identity_cipher_p32_o32_r1'

        sage: identity.file_name
        'identity_cipher_p32_o32_r1.py'

        sage: identity.number_of_rounds
        1
    """

    def __init__(self, block_bit_size=32):
        super().__init__(
            family_name="identity_cipher",
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[block_bit_size],
            cipher_output_bit_size=block_bit_size,
        )
        self.add_cipher_output_component([INPUT_PLAINTEXT], [list(range(block_bit_size))], block_bit_size)
