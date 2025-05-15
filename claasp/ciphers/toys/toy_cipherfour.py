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
from claasp.utils.utils import get_number_of_rounds_from
from claasp.name_mappings import BLOCK_CIPHER, INPUT_PLAINTEXT, INPUT_KEY

PARAMETERS_CONFIGURATION_LIST = [
    {'block_bit_size': 16, 'key_bit_size': 96, 'number_of_rounds': 5}
]


class ToyCipherFour(Cipher):
    """
    Construct an instance of the ToyCipherFour class.
    This class implements CipherFOUR [Knudsen2011TheBC]_,
    with a default block size of 16 bits and a key size of 96 bits.
    This toy block cipher splits the key into multiple round keys.

    REFERENCES:

    Knudsen, L. R., & Robshaw, M. J. B. (2011). *The Block Cipher Companion*. Springer [Knudsen2011TheBC]_.


    INPUT:

    - ``block_bit_size`` -- **integer** (default: `16`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `80`); cipher key bit size of the cipher
    - ``sbox`` -- **integer list** (default: [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]); lookup table of the S-box.
    - ``permutations`` -- **integer list** (default: [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15])
    - ``number_of_rounds`` -- **integer** (default: `5`); number of rounds of the cipher.


    EXAMPLES::

        sage: from claasp.ciphers.toys.toy_cipherfour import ToyCipherFour
        sage: toy_cipher = ToyCipherFour()
        sage: plaintext = 0x1234; key = 0x111122223333444455556666
        sage: toy_cipher.evaluate([plaintext, key])
        17897
        sage: hex(toy_cipher.evaluate([plaintext, key]))
        '0x45e9'
        sage: toy_cipher.number_of_rounds
        5

        sage: toy_cipher = ToyCipherFour(block_bit_size=16, key_bit_size=80, number_of_rounds=10)
        sage: plaintext = 0x5678; key = 0x123456781234567812abcdef
        sage: hex(toy_cipher.evaluate([plaintext, key]))
        '0xbeec'

        sage: toy_cipher = ToyCipherFour(block_bit_size=16, key_bit_size=80, sbox=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0], permutations=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], number_of_rounds=5)
        sage: plaintext = 0x9abc; key = 0x3333555577779999bbbbcccc
        sage: hex(toy_cipher.evaluate([plaintext, key]))
        '0xef01'
        sage: toy_cipher.evaluate([plaintext, key])
        61185
    """

    def __init__(self,
                 block_bit_size=16,
                 key_bit_size=16,
                 rotation_layer=1,
                 sbox=None,
                 permutations=None,
                 number_of_rounds=5):

        if sbox is None:
            sbox = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]

        if permutations is None:
            permutations = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]


        self.sbox_bit_size = len(bin(len(sbox))) - 3
        self.number_of_sboxes = block_bit_size // self.sbox_bit_size
        self._num_rounds = number_of_rounds
        self.block_bit_size = block_bit_size
        self.rotation_layer = rotation_layer
        self.sbox = sbox
        self.permutations = permutations
        super().__init__(family_name="toyspn1",
                         cipher_type=BLOCK_CIPHER,
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                         cipher_inputs_bit_size=[block_bit_size, key_bit_size * (number_of_rounds + 1)],
                         cipher_output_bit_size=block_bit_size)

        state = INPUT_PLAINTEXT
        key= INPUT_KEY

        for round_idx in range(number_of_rounds - 1):
            # XOR with round key
            self.add_round()
            xor = self.add_XOR_component(
                [state, key],
                [[i for i in range(block_bit_size)],
                 [i for i in range(round_idx*block_bit_size, (round_idx+1)*block_bit_size)]],
                block_bit_size)
            state = xor.id  # Update state to XOR output

            # S-box layer
            sbox_outputs = []
            for ns in range(self.number_of_sboxes):
                sbox_component = self.add_SBOX_component(
                    [state],
                    [[ns * self.sbox_bit_size + i for i in range(self.sbox_bit_size)]],
                    self.sbox_bit_size,
                    self.sbox)
                sbox_outputs.append(sbox_component.id)

            # Permutation layer
            state = self.permutation_layer(sbox_outputs)

            self.add_round_output_component([state],
                                            [[i for i in range(block_bit_size)]],
                                            block_bit_size)

        self.add_round()

        # XOR with round key
        xor = self.add_XOR_component(
            [state, key],
            [[i for i in range(block_bit_size)],
             [i for i in range(4*block_bit_size, 5*block_bit_size)]],
            block_bit_size)
        state = xor.id

        # Last round does not include permutation
        sbox_outputs = []
        for ns in range(self.number_of_sboxes):
            sbox_component = self.add_SBOX_component(
                [state],
                [[ns * self.sbox_bit_size + i for i in range(self.sbox_bit_size)]],
                self.sbox_bit_size,
                self.sbox)
            sbox_outputs.append(sbox_component.id)

        # Ensure we have at least 4 SBOX outputs
        if len(sbox_outputs) < 4:
            raise IndexError(f"Expected at least 4 SBOX outputs, but got {len(sbox_outputs)}.")

        # Final XOR with the last round key
        xor = self.add_XOR_component(
            [sbox_outputs[0]] + [sbox_outputs[1]] + [sbox_outputs[2]] + [sbox_outputs[3]]+[key],
            [list(range(4))]*4 + [[i for i in range(5*block_bit_size, 6*block_bit_size)]],
            block_bit_size)
        state = xor.id

        self.add_cipher_output_component(
            [state],
            [[i for i in range(block_bit_size)]],
            block_bit_size)

    def permutation_layer(self, sbox_output):
        perm = self.add_permutation_component(
            [sbox_output[0]] + [sbox_output[1]] + [sbox_output[2]] + [sbox_output[3]],
            [list(range(4))]*4,
            self.block_bit_size,
            self.permutations)
        return perm.id