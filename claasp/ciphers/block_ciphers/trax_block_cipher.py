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
from claasp.name_mappings import BLOCK_CIPHER, INPUT_KEY, INPUT_PLAINTEXT, INPUT_TWEAK
from claasp.utils.utils import get_inputs_parameter

WORD_SIZE = 32

# Alzette rotation amounts for each of the 4 sub-rounds: (ry, rx).
# Sub-round i performs: x += ROT(y, ry), y ^= ROT(x, rx), x ^= c.
# Source: Algorithm 1 of [BBBGPUV2020]_.
ALZETTE_ROTATIONS = [(31, 24), (17, 17), (0, 31), (24, 16)]

# Eight SPARKLE round constants used as Alzette instance constants.
# Source: Equation (1) of [BBBGPUV2020]_.
SPARKLE_CONSTANTS = [
    0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738,
    0xBB1185EB, 0x4F7C7B57, 0xCFBFA1C8, 0xC2B3293D,
]

# Number of Alzette branches (pairs) in TRAX-L's 256-bit state.
NUM_BRANCHES = 4

PARAMETERS_CONFIGURATION_LIST = [
    {"block_bit_size": 256, "key_bit_size": 256, "tweak_bit_size": 128, "number_of_rounds": 17},
]


class TraxBlockCipher(Cipher):
    """
    Construct an instance of the TraxBlockCipher class.

    TRAX-L-17 is a 256-bit tweakable block cipher with a 256-bit key and a
    128-bit tweak, built on Alzette 64-bit ARX-boxes.  This is the "L"
    (large) member of the TRAX family described in [BBBGPUV2020]_.

    The 256-bit state consists of four Alzette branches
    ``(x0,y0), (x1,y1), (x2,y2), (x3,y3)``
    each holding two 32-bit words.  The 256-bit plaintext is laid out as::

        bits   0.. 31 → x0   bits  32.. 63 → y0
        bits  64.. 95 → x1   bits  96..127 → y1
        bits 128..159 → x2   bits 160..191 → y2
        bits 192..223 → x3   bits 224..255 → y3

    The 256-bit key uses the same interleaved word layout::

        bits   0.. 31 → K[0] … bits 224..255 → K[7]

    The 128-bit tweak is split into four 32-bit words::

        bits  0..31 → T[0]   bits  32..63 → T[1]
        bits 64..95 → T[2]   bits 96..127 → T[3]

    **Key schedule** (source: Appendix D.2 of [BBBGPUV2020]_)::

        initial key state: K[0..7] = master key
        for s in 0 .. number_of_rounds:
            subkey_s = K[0..7]          # snapshot current key state
            K[0] += K[1] + RCON[(2s) mod 8]
            K[2] ^= K[3] ^ s
            K[4] += K[5] + RCON[(2s+1) mod 8]
            K[6] ^= K[7] ^ (s << 16)
            K[0..7] = K[1..7] || K[0]  # left rotation of words

    **Encryption step** s (0-indexed, source: Appendix B / D.2 of [BBBGPUV2020]_)::

        if s is odd:
            (x0,y0) ^= (T[0], T[1])
            (x1,y1) ^= (T[2], T[3])
        (xi, yi) ^= (subkey_s[2i], subkey_s[2i+1]) for i = 0..3
        (xi, yi) = Alzette_{RCON[(4s+i) mod 8]}(xi, yi) for i = 0..3
        (x0..x3, y0..y3) = L4(x0..x3, y0..y3)   # Sparkle256 linear layer

    **Linear layer L4** (Sparkle256 diffusion, lines 51-55 of the reference C
    code in Appendix D.2 of [BBBGPUV2020]_)::

        tmpx = ELL(x2 ^ x3);  y0 ^= tmpx;  y1 ^= tmpx
        tmpy = ELL(y2 ^ y3);  x0 ^= tmpy;  x1 ^= tmpy
        (x0, x1, x2, x3) = (x3, x2, x0, x1)    # word shuffle
        (y0, y1, y2, y3) = (y3, y2, y0, y1)
    where ELL(v) = ROT(v ^ (v << 16), 16); ``<<`` is an ordinary
    zero-filling left *shift* on a 32-bit word (not a rotation), and
    ``ROT`` is a right rotation.

    A **final key addition** with subkey_{number_of_rounds} follows the last
    Alzette + L4 step.

    WARNING: no independently-published numeric test vector for TRAX-L-17
    could be found (it is not part of a NIST submission and the designers'
    reference material at https://sparkle-lwc.github.io/trax and Appendix
    D.2 of [BBBGPUV2020]_ gives only C source code, no known-answer tests).
    The vectors below were instead obtained by transcribing that reference C
    code (``traxl17_genkeys_ref`` / ``traxl17_enc_ref``) line-by-line into an
    independent Python implementation and running it; see
    https://sparkle-lwc.github.io/trax for the source code transcribed.

    INPUT:

    - ``number_of_rounds`` -- **integer** (default: `17`); number of steps
      (Alzette layers).  The recommended full instance is TRAX-L-17 with 17
      steps.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.trax_block_cipher import TraxBlockCipher
        sage: trax = TraxBlockCipher()
        sage: trax.number_of_rounds
        17

        sage: trax.id
        'trax_p256_k256_t128_o256_r17'

        sage: trax.component_from(0, 0).id
        'modadd_0_0'

        sage: # Test vector 1: all-zero plaintext, key and tweak.
        sage: # Computed with an independent Python port of the reference C code
        sage: # from https://sparkle-lwc.github.io/trax (Appendix D.2 of [BBBGPUV2020]_).
        sage: trax.evaluate([0, 0, 0]) == 0x76e1920dad2b0f289933e3d098dc2e806a7425a2439bafb119daa29e936d8cac
        True

        sage: # Test vector 2: incremental plaintext/key, non-zero tweak.
        sage: # Computed with the same independent Python port as test vector 1.
        sage: pt = int.from_bytes(bytes(range(32)), 'big')
        sage: key = int.from_bytes(bytes(range(32, 64)), 'big')
        sage: tweak = int.from_bytes(bytes(range(16)), 'big')
        sage: trax.evaluate([pt, key, tweak]) == 0xe310343a4d030212dca53c766016bcd4987e57bdda5efbcd1eadaa00901dc842
        True
    """

    def __init__(self, number_of_rounds=17):
        super().__init__(
            family_name='trax',
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY, INPUT_TWEAK],
            cipher_inputs_bit_size=[256, 256, 128],
            cipher_output_bit_size=256,
        )

        # Initial state: xi occupies bits 64i..64i+31, yi occupies bits 64i+32..64i+63.
        state_x = [
            ComponentState([INPUT_PLAINTEXT], [list(range(b * 2 * WORD_SIZE, b * 2 * WORD_SIZE + WORD_SIZE))])
            for b in range(NUM_BRANCHES)
        ]
        state_y = [
            ComponentState([INPUT_PLAINTEXT], [list(range(b * 2 * WORD_SIZE + WORD_SIZE, (b + 1) * 2 * WORD_SIZE))])
            for b in range(NUM_BRANCHES)
        ]

        # Key state: K[0..7], each a 32-bit word drawn from INPUT_KEY.
        key_state = [
            ComponentState([INPUT_KEY], [list(range(k * WORD_SIZE, (k + 1) * WORD_SIZE))])
            for k in range(2 * NUM_BRANCHES)
        ]

        # Tweak words T[0..3], each 32-bit, from INPUT_TWEAK.
        tweak = [
            ComponentState([INPUT_TWEAK], [list(range(t * WORD_SIZE, (t + 1) * WORD_SIZE))])
            for t in range(NUM_BRANCHES)
        ]

        for step in range(number_of_rounds):
            self.add_round()

            # Snapshot current subkey (K[0..7]) for this step.
            # The subkey for step s is used before the key-state update.
            subkey = list(key_state)  # shallow copy of the current key_state list

            # Update key state (key schedule step s, applied after snapshot):
            # K[0] += K[1] + RCON[(2s) mod 8]
            # K[2] ^= K[3] ^ s
            # K[4] += K[5] + RCON[(2s+1) mod 8]
            # K[6] ^= K[7] ^ (s << 16)
            # K[0..7] left-rotated by 1 word position
            key_state = self._key_schedule_step(key_state, step)

            # --- Tweak addition on odd steps ---
            if step % 2 == 1:
                for b in range(2):  # only branches 0 and 1 receive the tweak
                    inputs_id, inputs_pos = get_inputs_parameter([state_x[b], tweak[2 * b]])
                    self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
                    state_x[b] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

                    inputs_id, inputs_pos = get_inputs_parameter([state_y[b], tweak[2 * b + 1]])
                    self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
                    state_y[b] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

            # --- Subkey addition ---
            for b in range(NUM_BRANCHES):
                inputs_id, inputs_pos = get_inputs_parameter([state_x[b], subkey[2 * b]])
                self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
                state_x[b] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

                inputs_id, inputs_pos = get_inputs_parameter([state_y[b], subkey[2 * b + 1]])
                self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
                state_y[b] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

            # --- Alzette calls on all 4 branches ---
            for b in range(NUM_BRANCHES):
                rcon_val = SPARKLE_CONSTANTS[(4 * step + b) % 8]
                self.add_constant_component(WORD_SIZE, rcon_val)
                ci = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
                state_x[b], state_y[b] = self._alzette_call(state_x[b], state_y[b], ci)

            # --- Linear layer L4 (Sparkle256 diffusion) ---
            state_x, state_y = self._linear_layer(state_x, state_y)

            # Emit round output for intermediate analysis.
            all_state = []
            for b in range(NUM_BRANCHES):
                all_state.append(state_x[b])
                all_state.append(state_y[b])
            inputs_id, inputs_pos = get_inputs_parameter(all_state)
            self.add_round_output_component(inputs_id, inputs_pos, 256)

        # --- Final key addition with subkey_{number_of_rounds} ---
        # After the loop, key_state holds the next updated key state.
        # We use the snapshot made at the start of step `number_of_rounds`, which
        # is exactly the key_state value after the loop finishes (it was updated
        # number_of_rounds times: step 0 updated it after snapshot to produce key_state_1,
        # ..., step n-1 updated it to produce key_state_n which is key_state now).
        final_subkey = key_state

        for b in range(NUM_BRANCHES):
            inputs_id, inputs_pos = get_inputs_parameter([state_x[b], final_subkey[2 * b]])
            self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
            state_x[b] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

            inputs_id, inputs_pos = get_inputs_parameter([state_y[b], final_subkey[2 * b + 1]])
            self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
            state_y[b] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # Cipher output: x0,y0,x1,y1,x2,y2,x3,y3 (interleaved).
        all_state = []
        for b in range(NUM_BRANCHES):
            all_state.append(state_x[b])
            all_state.append(state_y[b])
        inputs_id, inputs_pos = get_inputs_parameter(all_state)
        self.add_cipher_output_component(inputs_id, inputs_pos, 256)

    # ------------------------------------------------------------------
    # Key schedule helpers
    # ------------------------------------------------------------------

    def _key_schedule_step(self, key_state, step):
        """
        Apply one TRAX-L key schedule update to ``key_state``, returning the
        updated list of eight 32-bit ``ComponentState`` objects.

        Operations (from Appendix D.2 of [BBBGPUV2020]_)::

            K[0] = K[0] + K[1] + RCON[(2s) mod 8]  (modular addition)
            K[2] = K[2] XOR K[3] XOR s
            K[4] = K[4] + K[5] + RCON[(2s+1) mod 8]  (modular addition)
            K[6] = K[6] XOR K[7] XOR (s << 16)
            K[0..7] ← K[1..7] || K[0]           (word rotation)
        """
        k = list(key_state)

        # K[0] += K[1] + RCON[(2*step) % 8]
        # Computed as: K[0] = ModAdd(K[0], K[1]) then ModAdd(result, RCON)
        inputs_id, inputs_pos = get_inputs_parameter([k[0], k[1]])
        self.add_modadd_component(inputs_id, inputs_pos, WORD_SIZE)
        k01 = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        rcon0 = SPARKLE_CONSTANTS[(2 * step) % 8]
        self.add_constant_component(WORD_SIZE, rcon0)
        rcon0_cs = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        inputs_id, inputs_pos = get_inputs_parameter([k01, rcon0_cs])
        self.add_modadd_component(inputs_id, inputs_pos, WORD_SIZE)
        new_k0 = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # K[2] ^= K[3] ^ s
        self.add_constant_component(WORD_SIZE, step)
        step_cs = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        inputs_id, inputs_pos = get_inputs_parameter([k[2], k[3], step_cs])
        self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
        new_k2 = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # K[4] += K[5] + RCON[(2*step+1) % 8]
        inputs_id, inputs_pos = get_inputs_parameter([k[4], k[5]])
        self.add_modadd_component(inputs_id, inputs_pos, WORD_SIZE)
        k45 = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        rcon1 = SPARKLE_CONSTANTS[(2 * step + 1) % 8]
        self.add_constant_component(WORD_SIZE, rcon1)
        rcon1_cs = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        inputs_id, inputs_pos = get_inputs_parameter([k45, rcon1_cs])
        self.add_modadd_component(inputs_id, inputs_pos, WORD_SIZE)
        new_k4 = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # K[6] ^= K[7] ^ (step << 16)
        self.add_constant_component(WORD_SIZE, (step << 16) & 0xFFFFFFFF)
        step16_cs = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        inputs_id, inputs_pos = get_inputs_parameter([k[6], k[7], step16_cs])
        self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
        new_k6 = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # Word rotation: new_k = [k[1], new_k2, k[3], new_k4, k[5], new_k6, k[7], new_k0]
        # i.e., K[b-1] = K[b] for b=1..7, then K[7] = (old)K[0] after updates.
        # From C code: tmp=key_[0]; for b in 1..7: key_[b-1]=key_[b]; key_[7]=tmp
        # After the in-place modifications: key_[0]=new_k0, key_[2]=new_k2,
        # key_[4]=new_k4, key_[6]=new_k6, key_[1,3,5,7] unchanged.
        # Then rotate: result = [key_[1], key_[2], key_[3], key_[4], key_[5], key_[6], key_[7], key_[0]]
        # = [k[1], new_k2, k[3], new_k4, k[5], new_k6, k[7], new_k0]
        return [k[1], new_k2, k[3], new_k4, k[5], new_k6, k[7], new_k0]

    # ------------------------------------------------------------------
    # Alzette helpers (shared with CraxBlockCipher)
    # ------------------------------------------------------------------

    def _alzette_call(self, state_x, state_y, ci):
        """Apply one full Alzette call: four sub-rounds of (x+=ROT(y,ry), y^=ROT(x,rx), x^=c)."""
        for ry, rx in ALZETTE_ROTATIONS:
            state_x, state_y = self._alzette_sub_round(state_x, state_y, ci, ry, rx)
        return state_x, state_y

    def _alzette_sub_round(self, state_x, state_y, ci, ry, rx):
        """One Alzette sub-round: x += ROT(y, ry), y ^= ROT(x, rx), x ^= c."""
        # x <- x + ROT(y, ry)
        if ry == 0:
            inputs_id, inputs_pos = get_inputs_parameter([state_x, state_y])
        else:
            self.add_rotate_component(state_y.id, state_y.input_bit_positions, WORD_SIZE, ry)
            rot_y = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
            inputs_id, inputs_pos = get_inputs_parameter([state_x, rot_y])
        self.add_modadd_component(inputs_id, inputs_pos, WORD_SIZE)
        state_x = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # y <- y XOR ROT(x, rx)
        self.add_rotate_component(state_x.id, state_x.input_bit_positions, WORD_SIZE, rx)
        rot_x = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        inputs_id, inputs_pos = get_inputs_parameter([state_y, rot_x])
        self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
        state_y = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # x <- x XOR c
        inputs_id, inputs_pos = get_inputs_parameter([state_x, ci])
        self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
        state_x = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        return state_x, state_y

    # ------------------------------------------------------------------
    # Linear layer
    # ------------------------------------------------------------------

    def _linear_layer(self, state_x, state_y):
        """
        Apply the Sparkle256 linear layer L4 to the four-branch state.

        From Appendix D.2 of [BBBGPUV2020]_::

            tmpx = ELL(x2 ^ x3);  y0 ^= tmpx;  y1 ^= tmpx
            tmpy = ELL(y2 ^ y3);  x0 ^= tmpy;  x1 ^= tmpy
            (x0,x1,x2,x3) ← (x3,x2,x0,x1)
            (y0,y1,y2,y3) ← (y3,y2,y0,y1)

        where ELL(v) = ROT(v XOR (v << 16), 16), with ``<<`` an ordinary
        zero-filling left *shift* (not a rotation) and ``ROT`` a right
        rotation.
        """
        x = list(state_x)
        y = list(state_y)

        # --- ELL(x2 ^ x3) ---
        inputs_id, inputs_pos = get_inputs_parameter([x[2], x[3]])
        self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
        x2_xor_x3 = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        tmpx = self._ell(x2_xor_x3)

        # y0 ^= tmpx,  y1 ^= tmpx
        inputs_id, inputs_pos = get_inputs_parameter([y[0], tmpx])
        self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
        y[0] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        inputs_id, inputs_pos = get_inputs_parameter([y[1], tmpx])
        self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
        y[1] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # --- ELL(y2 ^ y3) ---
        inputs_id, inputs_pos = get_inputs_parameter([y[2], y[3]])
        self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
        y2_xor_y3 = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        tmpy = self._ell(y2_xor_y3)

        # x0 ^= tmpy,  x1 ^= tmpy
        inputs_id, inputs_pos = get_inputs_parameter([x[0], tmpy])
        self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
        x[0] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        inputs_id, inputs_pos = get_inputs_parameter([x[1], tmpy])
        self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
        x[1] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # --- Word shuffle ---
        # From the reference C code (sequential, not a simultaneous tuple assignment):
        #   tmpx=x[0]; x[0]=x[3]; x[3]=x[1]; x[1]=x[2]; x[2]=tmpx;
        # which evaluates to new_x = [old_x3, old_x2, old_x0, old_x1].
        # (x[0], x[1] here are already the *updated* values from the tmpy XOR above;
        #  x[2], x[3] are the original, untouched values.)
        new_x = [x[3], x[2], x[0], x[1]]
        new_y = [y[3], y[2], y[0], y[1]]

        return new_x, new_y

    def _ell(self, v):
        """
        Compute ELL(v) = ROT(v XOR (v << 16), 16) for a 32-bit word v.

        Source (Appendix D.2 of [BBBGPUV2020]_)::

            #define ELL(x) (ROT(((x) ^ ((x) << 16)), 16))

        ``v << 16`` here is an ordinary C ``uint32_t`` *shift*, not a
        rotation: bits 15..0 move to bits 31..16 and the low 16 bits are
        zero-filled (the original high 16 bits are discarded).  In this
        component graph that is a SHIFT component with a *negative*
        parameter (``add_shift_component`` uses positive parameters for a
        right shift and negative for a left shift).  ``ROT(., 16)`` is the
        ordinary right-rotation used elsewhere in this cipher.
        """
        # v << 16  (true left shift, zero-filled, NOT a rotation)
        self.add_shift_component(v.id, v.input_bit_positions, WORD_SIZE, -16)
        shifted_v = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # v XOR (v << 16)
        inputs_id, inputs_pos = get_inputs_parameter([v, shifted_v])
        self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
        xored = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # ROT(result, 16)
        self.add_rotate_component(xored.id, xored.input_bit_positions, WORD_SIZE, 16)
        result = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        return result
