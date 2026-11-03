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

# SAECHAM is defined only for a 64-bit block and 128-bit key [DampersSAECHAM2025]_.
PARAMETERS_CONFIGURATION_LIST = [
    {"block_bit_size": 64, "key_bit_size": 128, "number_of_rounds": 88},
]

_BLOCK_BIT_SIZE = 64
_KEY_BIT_SIZE = 128
_WORD_SIZE = 16          # block / 4
_NUM_KEY_WORDS = 8       # key / word_size
_DEFAULT_ROUNDS = 88


class SaechamBlockCipher(Cipher):
    """
    Construct an instance of the SaechamBlockCipher class.

    This class models SAECHAM, a lightweight ARX block cipher proposed in
    [DampersSAECHAM2025]_.  SAECHAM uses a 64-bit block and a 128-bit key
    and is designed as a variant of CHAM [RohCHAM2018]_ with a modified
    round function that improves differential resistance.

    The key schedule is identical to CHAM-64/128 and produces 16 round keys.
    Each of the 88 cipher rounds updates one of the four 16-bit state words:

    - even round ``rc``:
      ``x[j] = (ROL(x[j], 8) ⊕ rc) + (ROL(x[(j+1)%4], 8) ⊕ rk[rc % 16])``
    - odd  round ``rc``:
      ``x[j] = (ROL(x[j], 7) ⊕ rc) + (ROL(x[(j+1)%4], 8) ⊕ rk[rc % 16])``

    where ``j = rc % 4`` and all operations are modulo ``2^16``.

    INPUT:

    - ``number_of_rounds`` -- **integer** (default: `88`); number of rounds.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.saecham_block_cipher import SaechamBlockCipher
        sage: saecham = SaechamBlockCipher()
        sage: saecham.number_of_rounds
        88

        sage: # Test vector from [DampersSAECHAM2025]_ (SAECHAM-64/128, 88 rounds)
        sage: key = 0x010003020504070609080b0a0d0c0f0e
        sage: pt  = 0x1100332255447766
        sage: saecham.evaluate([key, pt]) == 0xfe475393e6ba01f1
        True

        sage: reduced = SaechamBlockCipher(number_of_rounds=4)
        sage: reduced.id
        'saecham_block_cipher_k128_p64_o64_r4'
    """

    def __init__(self, number_of_rounds=_DEFAULT_ROUNDS):
        super().__init__(
            family_name="saecham_block_cipher",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_KEY, INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[_KEY_BIT_SIZE, _BLOCK_BIT_SIZE],
            cipher_output_bit_size=_BLOCK_BIT_SIZE,
        )

        state = [
            ComponentState(
                [INPUT_PLAINTEXT],
                [list(range(j * _WORD_SIZE, (j + 1) * _WORD_SIZE))],
            )
            for j in range(4)
        ]

        round_keys = None
        for rc in range(number_of_rounds):
            self.add_round()

            if rc == 0:
                round_keys = self._key_schedule()

            rk_idx = rc % (2 * _NUM_KEY_WORDS)
            j = rc % 4
            j_next = (j + 1) % 4
            state[j] = self._sub_round(state, j, j_next, round_keys[rk_idx], rc)

            inputs_id, inputs_pos = [], []
            for s in state:
                inputs_id += s.id
                inputs_pos += s.input_bit_positions

            if rc == number_of_rounds - 1:
                self.add_cipher_output_component(inputs_id, inputs_pos, _BLOCK_BIT_SIZE)
            else:
                self.add_round_output_component(inputs_id, inputs_pos, _BLOCK_BIT_SIZE)

    def _word_state(self, component):
        return ComponentState([component.id], [list(range(_WORD_SIZE))])

    def _key_schedule(self):
        """Compute the 16 CHAM round keys from the 128-bit master key."""
        rk = [None] * (2 * _NUM_KEY_WORDS)

        for i in range(_NUM_KEY_WORDS):
            k_bits = list(range(i * _WORD_SIZE, (i + 1) * _WORD_SIZE))
            k_state = ComponentState([INPUT_KEY], [k_bits])

            # ROL(k[i], 1)
            rot1 = self.add_rotate_component(k_state.id, k_state.input_bit_positions, _WORD_SIZE, -1)
            rot1_state = self._word_state(rot1)

            # k[i] ^ ROL(k[i], 1)
            xor_01 = self.add_xor_component(
                k_state.id + rot1_state.id,
                k_state.input_bit_positions + rot1_state.input_bit_positions,
                _WORD_SIZE,
            )
            xor_01_state = self._word_state(xor_01)

            # ROL(k[i], 8)
            rot8 = self.add_rotate_component(k_state.id, k_state.input_bit_positions, _WORD_SIZE, -8)
            rot8_state = self._word_state(rot8)

            # rk[i] = k[i] ^ ROL(k[i], 1) ^ ROL(k[i], 8)
            rk_low = self.add_xor_component(
                xor_01_state.id + rot8_state.id,
                xor_01_state.input_bit_positions + rot8_state.input_bit_positions,
                _WORD_SIZE,
            )
            rk[i] = self._word_state(rk_low)

            # ROL(k[i], 11)
            rot11 = self.add_rotate_component(k_state.id, k_state.input_bit_positions, _WORD_SIZE, -11)
            rot11_state = self._word_state(rot11)

            # rk[(i+W)^1] = k[i] ^ ROL(k[i], 1) ^ ROL(k[i], 11)
            rk_high = self.add_xor_component(
                xor_01_state.id + rot11_state.id,
                xor_01_state.input_bit_positions + rot11_state.input_bit_positions,
                _WORD_SIZE,
            )
            rk[(i + _NUM_KEY_WORDS) ^ 1] = self._word_state(rk_high)

        return rk

    def _sub_round(self, state, j, j_next, rk_word, rc):
        """Apply one SAECHAM sub-round updating state word j.

        Even rc: x[j] = (ROL(x[j], 8) ^ rc) + (ROL(x[j_next], 8) ^ rk)
        Odd  rc: x[j] = (ROL(x[j], 7) ^ rc) + (ROL(x[j_next], 8) ^ rk)
        """
        W = list(range(_WORD_SIZE))

        word_rot = -8 if rc % 2 == 0 else -7

        # ROL(x[j], word_rot)
        rot_j = self.add_rotate_component(
            state[j].id, state[j].input_bit_positions, _WORD_SIZE, word_rot
        )
        rot_j_state = self._word_state(rot_j)

        # constant rc
        const_rc = self.add_constant_component(_WORD_SIZE, rc)
        const_rc_state = ComponentState([const_rc.id], [W])

        # ROL(x[j], word_rot) ^ rc
        xor_j_rc = self.add_xor_component(
            rot_j_state.id + const_rc_state.id,
            rot_j_state.input_bit_positions + const_rc_state.input_bit_positions,
            _WORD_SIZE,
        )
        xor_j_rc_state = ComponentState([xor_j_rc.id], [W])

        # ROL(x[j_next], 8)
        rot_feed = self.add_rotate_component(
            state[j_next].id, state[j_next].input_bit_positions, _WORD_SIZE, -8
        )
        rot_feed_state = self._word_state(rot_feed)

        # ROL(x[j_next], 8) ^ rk
        xor_rk = self.add_xor_component(
            rot_feed_state.id + rk_word.id,
            rot_feed_state.input_bit_positions + rk_word.input_bit_positions,
            _WORD_SIZE,
        )
        xor_rk_state = ComponentState([xor_rk.id], [W])

        # (ROL(x[j], word_rot) ^ rc) + (ROL(x[j_next], 8) ^ rk)
        modadd = self.add_modadd_component(
            xor_j_rc_state.id + xor_rk_state.id,
            xor_j_rc_state.input_bit_positions + xor_rk_state.input_bit_positions,
            _WORD_SIZE,
        )

        return self._word_state(modadd)
