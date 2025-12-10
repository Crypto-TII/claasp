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
from claasp.name_mappings import BLOCK_CIPHER, INPUT_PLAINTEXT, INPUT_KEY

# Constants for IDEA cipher
IDEA_BLOCK_SIZE = 64
IDEA_KEY_SIZE = 128
WORD_SIZE = 16
NUMBER_OF_ROUNDS = 8

class IdeaBlockCipher(Cipher):
    """
    Construct an instance of the IdeaBlockCipher class.

    This class is used to store compact representations of the IDEA cipher,
    used to generate the corresponding cipher implementation.

    IDEA (International Data Encryption Algorithm) is a block cipher designed by
    James Massey and Xuejia Lai in 1991. It operates on 64-bit blocks using a 128-bit key.

    The cipher consists of 8 identical rounds followed by an output transformation.
    Each round uses 6 16-bit subkeys, and the output transformation uses 4 more,
    for a total of 52 subkeys.

    IDEA uses three operations:

    - Bitwise XOR
    - Addition modulo 2^16
    - Multiplication modulo 2^16 + 1, with 0 treated as 2^16

    INPUT:

    - ``number_of_rounds`` -- **integer** (default: `8`); number of encryption rounds of the cipher.
      The total number of logical rounds in the cipher graph is ``number_of_rounds + 2``
      (1 for key schedule, ``number_of_rounds`` for cipher rounds, 1 for output transformation)

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.idea_block_cipher import IdeaBlockCipher
        sage: idea = IdeaBlockCipher()
        sage: idea.family_name
        'idea'

        sage: idea.inputs
        ['plaintext', 'key']

        sage: idea.inputs_bit_size
        [64, 128]

        sage: idea.output_bit_size
        64

        sage: idea.component_from(0, 0).id
        'rot_0_0'
    """

    def __init__(self, number_of_rounds=NUMBER_OF_ROUNDS):
        self.WORD_SIZE = WORD_SIZE
        self.MODULUS_MUL = 2**self.WORD_SIZE + 1
        self.MODULUS_ADD = 2**self.WORD_SIZE

        super().__init__(
            family_name="idea",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[IDEA_BLOCK_SIZE, IDEA_KEY_SIZE],
            cipher_output_bit_size=IDEA_BLOCK_SIZE,
        )
        
        # The key schedule is built in its own round to keep the graph organized
        self.add_round()
        subkeys = self._generate_subkeys()

        # Split plaintext into 4 words of 16 bits
        p = [ComponentState([INPUT_PLAINTEXT], [list(range(i * self.WORD_SIZE, (i + 1) * self.WORD_SIZE))]) for i in range(4)]

        # 8 IDEA rounds
        for r in range(number_of_rounds):
            self.add_round()
            round_keys = subkeys[r * 6 : (r + 1) * 6]
            is_last_round = (r == number_of_rounds - 1)
            p = self._idea_round(p, round_keys, is_last_round)

        # Output Transformation (half round) in a new logical "round"
        self.add_round()
        final_keys = subkeys[number_of_rounds * 6:]
        
        y1 = self._add_modmul_component(p[0], final_keys[0])
        y2 = self._add_modadd_component(p[1], final_keys[1])
        y3 = self._add_modadd_component(p[2], final_keys[2])
        y4 = self._add_modmul_component(p[3], final_keys[3])
        
        final_state = [y1, y2, y3, y4]

        # Concatenate final output
        final_ids = [s.id[0] for s in final_state]
        final_positions = [s.input_bit_positions[0] for s in final_state]

        self.add_cipher_output_component(final_ids, final_positions, IDEA_BLOCK_SIZE)

    def _generate_subkeys(self):
        """Generate the 52 16-bit subkeys according to IDEA key schedule."""
        subkeys = []
        key_state = ComponentState([INPUT_KEY], [list(range(IDEA_KEY_SIZE))])

        # 52 subkeys in total (8 rounds * 6 + 4 final)
        for _ in range(7):  # We need 52/8 ≈ 7 iterations of extraction/rotation
            # Extract 8 subkeys from current key state
            for j in range(8):
                if len(subkeys) < 52:
                    start_bit = j * self.WORD_SIZE
                    subkeys.append(
                         ComponentState([key_state.id[0]], [list(range(start_bit, start_bit + self.WORD_SIZE))])
                    )
            
            # If we haven't generated all keys yet, rotate the key state
            if len(subkeys) < 52:
                # The rotation component is added to the cipher graph
                self.add_rotate_component(key_state.id, key_state.input_bit_positions, IDEA_KEY_SIZE, -25)
                # The new key state is the output of the rotation component
                key_state = ComponentState([self.get_current_component_id()], [list(range(IDEA_KEY_SIZE))])
        
        return subkeys

    def _idea_round(self, state, round_keys, is_last_round):
        """Perform a complete IDEA round."""
        p1, p2, p3, p4 = state
        k1, k2, k3, k4, k5, k6 = round_keys

        # Operation layer
        y1 = self._add_modmul_component(p1, k1)
        y2 = self._add_modadd_component(p2, k2)
        y3 = self._add_modadd_component(p3, k3)
        y4 = self._add_modmul_component(p4, k4)

        # MA structure (Multiplication-Addition)
        t0 = self._add_xor_component(y1, y3)
        t1 = self._add_xor_component(y2, y4)
        t2 = self._add_modmul_component(t0, k5)
        t3 = self._add_modadd_component(t1, t2)
        t4 = self._add_modmul_component(t3, k6)
        t5 = self._add_modadd_component(t2, t4)

        # Final XOR to produce round outputs
        out1 = self._add_xor_component(y1, t4)
        out2_temp = self._add_xor_component(y2, t5)
        out3_temp = self._add_xor_component(y3, t4)
        out4 = self._add_xor_component(y4, t5)

        # The swap of middle words (out2 and out3) is skipped in the last round
        if is_last_round:
            return [out1, out2_temp, out3_temp, out4]
        else:
            return [out1, out3_temp, out2_temp, out4]  # Swap p2 and p3 for next round

    # --- Helper methods to add components and return a ComponentState ---
    def _add_modmul_component(self, s1, s2):
        self.add_idea_modmul_component(
            [s1.id[0], s2.id[0]],
            [s1.input_bit_positions[0], s2.input_bit_positions[0]],
            self.WORD_SIZE,
            self.MODULUS_MUL
        )
        return ComponentState([self.get_current_component_id()], [list(range(self.WORD_SIZE))])

    def _add_modadd_component(self, s1, s2):
        self.add_MODADD_component(
            [s1.id[0], s2.id[0]],
            [s1.input_bit_positions[0], s2.input_bit_positions[0]],
            self.WORD_SIZE,
            modulus=self.MODULUS_ADD
        )
        return ComponentState([self.get_current_component_id()], [list(range(self.WORD_SIZE))])

    def _add_xor_component(self, s1, s2):
        self.add_XOR_component(
            [s1.id[0], s2.id[0]],
            [s1.input_bit_positions[0], s2.input_bit_positions[0]],
            self.WORD_SIZE,
        )
        return ComponentState([self.get_current_component_id()], [list(range(self.WORD_SIZE))])

