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
from claasp.name_mappings import BLOCK_CIPHER, INPUT_KEY, INPUT_PLAINTEXT
from claasp.utils.utils import get_inputs_parameter

WORD_SIZE = 32

# Rotation amounts for each Alzette sub-round: (ry, rx).
# Sub-round i performs: x += ROT(y, ry), y ^= ROT(x, rx), x ^= c.
# Source: Algorithm 1 of [BBBGPUV2020]_.
ALZETTE_ROTATIONS = [(31, 24), (17, 17), (0, 31), (24, 16)]

# First five SPARKLE round constants, used as Alzette constants in CRAX-S.
# Source: Equation (1) of [BBBGPUV2020]_.
SPARKLE_CONSTANTS = [
    0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738, 0xBB1185EB,
]

PARAMETERS_CONFIGURATION_LIST = [
    {"block_bit_size": 64, "key_bit_size": 128, "number_of_rounds": 10},
]


class CraxBlockCipher(Cipher):
    """
    Construct an instance of the CraxBlockCipher class.

    CRAX-S-10 is a lightweight 64-bit block cipher with a 128-bit key, built
    on top of the Alzette 64-bit ARX-box.  Its structure is a key-alternating
    cipher: each of the 10 steps XORs the current step index and a pair of
    32-bit subkeys into the 64-bit state ``(x, y)``, then applies one call to
    Alzette with the appropriate SPARKLE round constant.  A final key-whitening
    step XORs ``(K_0, K_1)`` after the last Alzette call.

    State layout (64 bits)::

        bits 0..31  →  x  (left / most-significant word)
        bits 32..63 →  y  (right / least-significant word)

    Key layout (128 bits)::

        bits   0..31  →  K_0
        bits  32..63  →  K_1
        bits  64..95  →  K_2
        bits  96..127 →  K_3

    Per step ``s`` (0-indexed)::

        x ^= s                             # step counter into x
        x ^= K_{2*(s mod 2)}              # K_0 (even) or K_2 (odd)
        y ^= K_{2*(s mod 2)+1}            # K_1 (even) or K_3 (odd)
        (x, y) = Alzette_{RCON[s mod 5]}(x, y)

    Final whitening::

        x ^= K_0 ;  y ^= K_1

    INPUT:

    - ``number_of_rounds`` -- **integer** (default: `10`); number of steps
      (Alzette calls).  The full-round recommended instance uses 10 steps.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.crax_block_cipher import CraxBlockCipher
        sage: crax = CraxBlockCipher()
        sage: crax.number_of_rounds
        10

        sage: crax.id
        'crax_p64_k128_o64_r10'

        sage: crax.component_from(0, 0).id
        'constant_0_0'

        sage: # Test vector 1: zero plaintext and zero key.
        sage: # Source: https://github.com/jedisct1/zig-lwbc32/blob/main/src/crax.zig
        sage: crax.evaluate([0x0000000000000000, 0x00000000000000000000000000000000]) == 0x72edfac9453f5f4c
        True

        sage: # Test vector 2: incremental key, incremental plaintext.
        sage: # Source: https://github.com/jedisct1/zig-lwbc32/blob/main/src/crax.zig
        sage: crax.evaluate([0x3322110077665544, 0x03020100070605040b0a09080f0e0d0c]) == 0x6203c5be7ae77255
        True
    """

    def __init__(self, number_of_rounds=10):
        super().__init__(
            family_name='crax',
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[64, 128],
            cipher_output_bit_size=64,
        )

        # Initial state: x = bits 0..31, y = bits 32..63 of plaintext.
        state_x = ComponentState([INPUT_PLAINTEXT], [list(range(WORD_SIZE))])
        state_y = ComponentState([INPUT_PLAINTEXT], [list(range(WORD_SIZE, 2 * WORD_SIZE))])

        for step in range(number_of_rounds):
            self.add_round()

            # --- Round constant for this Alzette call ---
            rcon_val = SPARKLE_CONSTANTS[step % 5]
            self.add_constant_component(WORD_SIZE, rcon_val)
            ci = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

            # --- Step counter XOR into x ---
            # x ^= step  (step is a small integer 0..9, fits in 32 bits)
            self.add_constant_component(WORD_SIZE, step)
            step_const = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
            inputs_id, inputs_pos = get_inputs_parameter([state_x, step_const])
            self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
            state_x = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

            # --- Key XOR ---
            # Even steps: x ^= K0, y ^= K1
            # Odd  steps: x ^= K2, y ^= K3
            key_word_x_start = 0 if step % 2 == 0 else 2 * WORD_SIZE
            key_word_y_start = WORD_SIZE if step % 2 == 0 else 3 * WORD_SIZE

            key_x = ComponentState([INPUT_KEY], [list(range(key_word_x_start, key_word_x_start + WORD_SIZE))])
            key_y = ComponentState([INPUT_KEY], [list(range(key_word_y_start, key_word_y_start + WORD_SIZE))])

            inputs_id, inputs_pos = get_inputs_parameter([state_x, key_x])
            self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
            state_x = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

            inputs_id, inputs_pos = get_inputs_parameter([state_y, key_y])
            self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
            state_y = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

            # --- Alzette call ---
            state_x, state_y = self._alzette_call(state_x, state_y, ci)

            # Emit round output (used for intermediate analysis).
            inputs_id, inputs_pos = get_inputs_parameter([state_x, state_y])
            self.add_round_output_component(inputs_id, inputs_pos, 64)

        # --- Final key whitening: x ^= K0, y ^= K1 ---
        key_x = ComponentState([INPUT_KEY], [list(range(WORD_SIZE))])
        key_y = ComponentState([INPUT_KEY], [list(range(WORD_SIZE, 2 * WORD_SIZE))])

        inputs_id, inputs_pos = get_inputs_parameter([state_x, key_x])
        self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
        state_x = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        inputs_id, inputs_pos = get_inputs_parameter([state_y, key_y])
        self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
        state_y = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        inputs_id, inputs_pos = get_inputs_parameter([state_x, state_y])
        self.add_cipher_output_component(inputs_id, inputs_pos, 64)

    def _alzette_call(self, state_x, state_y, ci):
        """Apply one Alzette call: four sub-rounds of (x+=ROT(y,ry), y^=ROT(x,rx), x^=c)."""
        for ry, rx in ALZETTE_ROTATIONS:
            state_x, state_y = self._alzette_sub_round(state_x, state_y, ci, ry, rx)
        return state_x, state_y

    def _alzette_sub_round(self, state_x, state_y, ci, ry, rx):
        """One Alzette sub-round: x += ROT(y, ry), y ^= ROT(x, rx), x ^= c."""
        # x <- x + ROT(y, ry)
        if ry == 0:
            inputs_id, inputs_pos = get_inputs_parameter([state_x, state_y])
        else:
            self.add_rotate_component(
                state_y.id, state_y.input_bit_positions, WORD_SIZE, ry
            )
            rot_y = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
            inputs_id, inputs_pos = get_inputs_parameter([state_x, rot_y])
        self.add_modadd_component(inputs_id, inputs_pos, WORD_SIZE)
        state_x = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # y <- y XOR ROT(x, rx)
        self.add_rotate_component(
            state_x.id, state_x.input_bit_positions, WORD_SIZE, rx
        )
        rot_x = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        inputs_id, inputs_pos = get_inputs_parameter([state_y, rot_x])
        self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
        state_y = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # x <- x XOR c
        inputs_id, inputs_pos = get_inputs_parameter([state_x, ci])
        self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
        state_x = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        return state_x, state_y
