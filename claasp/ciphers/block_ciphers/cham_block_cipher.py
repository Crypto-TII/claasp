# ****************************************************************************
# Copyright 2026 Technology Innovation Institute
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
from claasp.utils.utils import get_number_of_rounds_from

# Default rounds follow the CHAM Revised specification [JeongCHAM2020]_.
# Original CHAM [RohCHAM2018]_ used 80/80/96 rounds for the three variants.
PARAMETERS_CONFIGURATION_LIST = [
    {"block_bit_size": 64,  "key_bit_size": 128, "number_of_rounds": 88},
    {"block_bit_size": 128, "key_bit_size": 128, "number_of_rounds": 112},
    {"block_bit_size": 128, "key_bit_size": 256, "number_of_rounds": 120},
]


class ChamBlockCipher(Cipher):
    """
    Construct an instance of the ChamBlockCipher class.

    This class models the CHAM family of lightweight ARX block ciphers
    introduced in [RohCHAM2018]_ and revised in [JeongCHAM2020]_.

    CHAM operates on a 64-bit or 128-bit block split into four words.  The key
    schedule derives ``2 * W`` round keys from ``W`` master-key words using
    XOR and rotation.  Each cipher round updates one of the four state words
    via the ARX formula

    - even round ``rc``:
      ``x[j] = ROL((x[j] ⊕ rc) + (ROL(x[(j+1)%4], 1) ⊕ rk[rc % 2W]), 8)``
    - odd  round ``rc``:
      ``x[j] = ROL((x[j] ⊕ rc) + (ROL(x[(j+1)%4], 8) ⊕ rk[rc % 2W]), 1)``

    where ``j = rc % 4`` and ``W`` is the number of key words.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `64`); block size in bits,
      either 64 or 128
    - ``key_bit_size`` -- **integer** (default: `128`); key size in bits,
      either 128 or 256
    - ``number_of_rounds`` -- **integer** (default: `0`); number of rounds.
      When set to 0 the default for the chosen parameter set is used:
      88 (CHAM-64/128 Revised), 112 (CHAM-128/128 Revised),
      120 (CHAM-128/256 Revised).  Pass 80/80/96 to obtain the
      original CHAM round counts from [RohCHAM2018]_.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.cham_block_cipher import ChamBlockCipher
        sage: cham = ChamBlockCipher()
        sage: cham.number_of_rounds
        88

        sage: # Test vector from [JeongCHAM2020]_ Appendix A (CHAM-64/128 Revised, 88 rounds)
        sage: key = 0x010003020504070609080b0a0d0c0f0e
        sage: pt  = 0x1100332255447766
        sage: cham.evaluate([key, pt]) == 0x65791204123fe5a9
        True

        sage: cham128 = ChamBlockCipher(block_bit_size=128, key_bit_size=128, number_of_rounds=4)
        sage: cham128.id
        'cham_block_cipher_k128_p128_o128_r4'
    """

    def __init__(self, block_bit_size=64, key_bit_size=128, number_of_rounds=0):
        self.block_bit_size = block_bit_size
        self.word_size = block_bit_size // 4
        self.num_key_words = key_bit_size // self.word_size

        number_of_rounds = get_number_of_rounds_from(
            block_bit_size, key_bit_size, number_of_rounds, PARAMETERS_CONFIGURATION_LIST
        )

        super().__init__(
            family_name="cham_block_cipher",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_KEY, INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[key_bit_size, block_bit_size],
            cipher_output_bit_size=block_bit_size,
        )

        state = [
            ComponentState([INPUT_PLAINTEXT], [list(range(j * self.word_size, (j + 1) * self.word_size))])
            for j in range(4)
        ]

        round_keys = None
        for rc in range(number_of_rounds):
            self.add_round()

            if rc == 0:
                round_keys = self._key_schedule()

            rk_idx = rc % (2 * self.num_key_words)
            j = rc % 4
            j_next = (j + 1) % 4
            state[j] = self._sub_round(state, j, j_next, round_keys[rk_idx], rc)

            inputs_id, inputs_pos = [], []
            for s in state:
                inputs_id += s.id
                inputs_pos += s.input_bit_positions

            if rc == number_of_rounds - 1:
                self.add_cipher_output_component(inputs_id, inputs_pos, block_bit_size)
            else:
                self.add_round_output_component(inputs_id, inputs_pos, block_bit_size)

    def _word_state(self, component):
        return ComponentState([component.id], [list(range(self.word_size))])

    def _key_schedule(self):
        """Compute 2*W round keys and return them as a list of ComponentStates."""
        w = self.word_size
        W = self.num_key_words
        rk = [None] * (2 * W)

        for i in range(W):
            k_bits = list(range(i * w, (i + 1) * w))
            k_state = ComponentState([INPUT_KEY], [k_bits])

            # ROL(k[i], 1)
            rot1 = self.add_rotate_component(k_state.id, k_state.input_bit_positions, w, -1)
            rot1_state = self._word_state(rot1)

            # k[i] ^ ROL(k[i], 1)
            xor_01 = self.add_xor_component(
                k_state.id + rot1_state.id,
                k_state.input_bit_positions + rot1_state.input_bit_positions,
                w,
            )
            xor_01_state = self._word_state(xor_01)

            # ROL(k[i], 8)
            rot8 = self.add_rotate_component(k_state.id, k_state.input_bit_positions, w, -8)
            rot8_state = self._word_state(rot8)

            # rk[i] = k[i] ^ ROL(k[i], 1) ^ ROL(k[i], 8)
            rk_low = self.add_xor_component(
                xor_01_state.id + rot8_state.id,
                xor_01_state.input_bit_positions + rot8_state.input_bit_positions,
                w,
            )
            rk[i] = self._word_state(rk_low)

            # ROL(k[i], 11)
            rot11 = self.add_rotate_component(k_state.id, k_state.input_bit_positions, w, -11)
            rot11_state = self._word_state(rot11)

            # rk[(i+W)^1] = k[i] ^ ROL(k[i], 1) ^ ROL(k[i], 11)
            rk_high = self.add_xor_component(
                xor_01_state.id + rot11_state.id,
                xor_01_state.input_bit_positions + rot11_state.input_bit_positions,
                w,
            )
            rk[(i + W) ^ 1] = self._word_state(rk_high)

        return rk

    def _sub_round(self, state, j, j_next, rk_word, rc):
        """Apply one CHAM sub-round updating state word j.

        Even rc: x[j] = ROL((x[j]^rc) + (ROL(x[j_next], 1) ^ rk), 8)
        Odd  rc: x[j] = ROL((x[j]^rc) + (ROL(x[j_next], 8) ^ rk), 1)
        """
        w = self.word_size
        W = list(range(w))

        inner_rot = -1 if rc % 2 == 0 else -8
        outer_rot = -8 if rc % 2 == 0 else -1

        # constant rc
        const_rc = self.add_constant_component(w, rc)
        const_rc_state = ComponentState([const_rc.id], [W])

        # x[j] ^ rc
        xor_j_rc = self.add_xor_component(
            state[j].id + const_rc_state.id,
            state[j].input_bit_positions + const_rc_state.input_bit_positions,
            w,
        )
        xor_j_rc_state = ComponentState([xor_j_rc.id], [W])

        # ROL(x[j_next], inner_rot)
        rot_feed = self.add_rotate_component(
            state[j_next].id, state[j_next].input_bit_positions, w, inner_rot
        )
        rot_feed_state = self._word_state(rot_feed)

        # ROL(x[j_next], inner_rot) ^ rk
        xor_rk = self.add_xor_component(
            rot_feed_state.id + rk_word.id,
            rot_feed_state.input_bit_positions + rk_word.input_bit_positions,
            w,
        )
        xor_rk_state = ComponentState([xor_rk.id], [W])

        # (x[j] ^ rc) + (ROL(x[j_next], inner_rot) ^ rk)
        modadd = self.add_modadd_component(
            xor_j_rc_state.id + xor_rk_state.id,
            xor_j_rc_state.input_bit_positions + xor_rk_state.input_bit_positions,
            w,
        )
        modadd_state = self._word_state(modadd)

        # ROL(result, outer_rot)
        rot_out = self.add_rotate_component(
            modadd_state.id, modadd_state.input_bit_positions, w, outer_rot
        )

        return self._word_state(rot_out)
