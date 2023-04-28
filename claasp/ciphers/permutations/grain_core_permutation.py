
# ****************************************************************************
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
from claasp.name_mappings import INPUT_STATE
from claasp.utils.utils import extract_inputs

PARAMETERS_CONFIGURATION_LIST = [{'number_of_rounds': 160}]
reference_code = '''
def grain_core_encrypt(state):
    from claasp.utils.integer_functions import bytearray_to_wordlist, wordlist_to_bytearray

    state_bit_size = 80
    rounds = {0}

    s = bytearray_to_wordlist(state, 1, state_bit_size)

    for _ in range(rounds):
        new_bit = s[62] ^ s[51] ^ s[38] ^ s[23] ^ s[13] ^ s[0]
        s[:79] = s[1:]
        s[-1] = new_bit

    return wordlist_to_bytearray(s, 1, state_bit_size)
'''


class GrainCorePermutation(Cipher):
    """
    Construct an instance of the GrainCorePermutation class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

    - ``number_of_rounds`` -- **integer** (default: `None`); number of rounds of the permutation. By default, the
      cipher uses the corresponding amount given the other parameters (if available)

    EXAMPLES::

        sage: from claasp.ciphers.permutations.grain_core_permutation import GrainCorePermutation
        sage: grain_core = GrainCorePermutation()
        sage: grain_core.number_of_rounds
        160

        sage: grain_core.component_from(0, 0).id
        'xor_0_0'

        sage: grain_core.print_cipher_structure_as_python_dictionary_to_file(  # doctest: +SKIP
        ....: "claasp/graph_representations/permutations/" + gc.file_name)  # doctest: +SKIP
    """

    def __init__(self, number_of_rounds=None):
        self.state_bit_size = 80

        if number_of_rounds is None:
            n = PARAMETERS_CONFIGURATION_LIST[0]['number_of_rounds']
        else:
            n = number_of_rounds

        super().__init__(family_name="grain_core",
                         cipher_type="permutation",
                         cipher_inputs=[INPUT_STATE],
                         cipher_inputs_bit_size=[self.state_bit_size],
                         cipher_output_bit_size=self.state_bit_size,
                         cipher_reference_code=reference_code.format(n))

        state = [INPUT_STATE], [list(range(self.state_bit_size))]

        for _ in range(n):
            self.add_round()

            state_id_list, state_bit_positions = extract_inputs(*state, [0, 13, 23, 38, 51, 62])
            new_bit_id = self.add_XOR_component(state_id_list, state_bit_positions, 1).id

            state_id_list, state_bit_positions = extract_inputs(*state, list(range(1, 80)))
            state = state_id_list + [new_bit_id], state_bit_positions + [[0]]

            self.add_round_output_component(*state, 80).id

        self.add_cipher_output_component(*state, 80)
