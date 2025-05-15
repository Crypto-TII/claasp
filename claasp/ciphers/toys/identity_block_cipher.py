
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
from claasp.name_mappings import BLOCK_CIPHER, INPUT_PLAINTEXT, INPUT_KEY

PARAMETERS_CONFIGURATION_LIST = [{'block_bit_size': 32, 'key_bit_size': 32, 'number_of_rounds': 1}]


class IdentityBlockCipher(Cipher):
    """
    Return a cipher object containing the graph representation the Identity Block Cipher.

    The Identity Block Cipher encryption returns the message itself, i.e.
    IdentityBlockCipherEncryption(k,m) = m.
    This block cipher is mainly used for testing.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `32`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `32`); cipher key bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `1`); number of rounds of the cipher

    EXAMPLES::

        sage: from claasp.ciphers.toys.identity_block_cipher import IdentityBlockCipher
        sage: identity = IdentityBlockCipher()
        sage: identity.type
        'block_cipher'

        sage: identity.id
        'identity_block_cipher_p32_k32_o32_r1'

        sage: identity.file_name
        'identity_block_cipher_p32_k32_o32_r1.py'

        sage: identity.number_of_rounds
        1

        sage: identity = IdentityBlockCipher(block_bit_size=32, key_bit_size=16, number_of_rounds=2)
        sage: identity.number_of_rounds
        2
    """

    def __init__(self, block_bit_size=32, key_bit_size=32, number_of_rounds=1):
        super().__init__(family_name="identity_block_cipher",
                         cipher_type=BLOCK_CIPHER,
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                         cipher_inputs_bit_size=[block_bit_size, key_bit_size],
                         cipher_output_bit_size=block_bit_size)

        # cipher rounds
        cipher_input = INPUT_PLAINTEXT
        key_input = INPUT_KEY

        for current_round in range(number_of_rounds):
            self.add_round()

            # key schedule
            input_link = [key_input]
            input_bit_positions = [list(range(key_bit_size))]
            self.add_concatenate_component(input_link, input_bit_positions, key_bit_size)
            key_input = self.get_current_component_id()

            # add round key output component
            input_link = [key_input]
            input_bit_positions = [list(range(key_bit_size))]
            self.add_round_key_output_component(input_link, input_bit_positions, key_bit_size)
            # end key schedule

            # encryption start
            input_link = [cipher_input]
            input_bit_positions = [list(range(block_bit_size))]
            self.add_concatenate_component(input_link, input_bit_positions, block_bit_size)
            cipher_input = self.get_current_component_id()

            # add cipher output component
            input_link = [cipher_input]
            input_bit_positions = [list(range(block_bit_size))]

            if current_round == number_of_rounds - 1:
                self.add_cipher_output_component(input_link, input_bit_positions, block_bit_size)
            else:
                self.add_round_output_component(input_link, input_bit_positions, block_bit_size)
