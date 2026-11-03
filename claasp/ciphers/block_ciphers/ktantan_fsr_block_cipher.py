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

"""
FSR-based implementation of the KTANTAN block cipher.

Same register/FSR structure as ``katan_fsr_block_cipher.py``; the only
difference from KATAN is the key schedule.  In KTANTAN the 80-bit key is
a fixed parameter that gets multiplexed into round keys via a small 8-bit
state LFSR (``t``).  Because the mux operations are pure Python integer
arithmetic they create *no* additional CLAASP components; the round-key
``ComponentState`` objects point directly at ``INPUT_KEY`` bit positions.
This yields an even smaller component graph than the FSR KATAN variant.
"""

from claasp.cipher import Cipher
from claasp.ciphers.block_ciphers.katan_block_cipher import (
    CONFIGURATION,
    get_ir_bit,
    normalize_number_of_rounds,
)
from claasp.DTOs.component_state import ComponentState
from claasp.name_mappings import BLOCK_CIPHER, INPUT_KEY, INPUT_PLAINTEXT

PARAMETERS_CONFIGURATION_LIST = [
    {"block_bit_size": 32, "key_bit_size": 80, "number_of_rounds": 254},
    {"block_bit_size": 48, "key_bit_size": 80, "number_of_rounds": 254},
    {"block_bit_size": 64, "key_bit_size": 80, "number_of_rounds": 254},
]


class KtantanFSRBlockCipher(Cipher):
    """
    Construct an instance of the KtantanFSRBlockCipher class.

    FSR-based re-implementation of KTANTAN that uses one ``add_fsr_component``
    per CLAASP round.  The register structure is identical to KATAN; only the
    key schedule differs (mux-based selection from the fixed 80-bit key).

    Reference:
    - C implementation: http://www.cs.technion.ac.il/~orrd/KATAN/katan.c

    INPUT:

        - ``block_bit_size`` -- **integer** (default: `32`); Valid values: 32, 48, 64.
        - ``key_bit_size`` -- **integer** (default: `80`); must be 80.
        - ``number_of_rounds`` -- **integer** (default: `None`); defaults to 254.
        - ``ir_mode`` -- **string** (default: `"strict"`); how to handle rounds beyond the
            254-bit IR sequence. Use `"cycle"` to repeat the IR sequence.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.ktantan_fsr_block_cipher import KtantanFSRBlockCipher
        sage: ktantan_fsr = KtantanFSRBlockCipher()
        sage: ktantan_fsr.number_of_rounds
        254

        sage: key = 0xFFFFFFFFFFFFFFFFFFFF
        sage: plaintext = 0x00000000
        sage: hex(ktantan_fsr.evaluate([plaintext, key]))
        '0x22ea3988'

        sage: KtantanFSRBlockCipher(block_bit_size=64, number_of_rounds=8).id
        'ktantan_fsr_p64_k80_o64_r8'

        sage: KtantanFSRBlockCipher(number_of_rounds=255, ir_mode='cycle').number_of_rounds
        255
    """

    def __init__(self, block_bit_size=32, key_bit_size=80, number_of_rounds=None, ir_mode="strict"):
        if block_bit_size not in CONFIGURATION:
            raise ValueError("No available configuration for the given block size.")
        if key_bit_size != 80:
            raise ValueError("KTANTAN uses a fixed 80-bit key.")

        config = CONFIGURATION[block_bit_size]
        len_l1 = config["len_l1"]
        len_l2 = config["len_l2"]
        x = config["x"]
        y = config["y"]
        steps = config["steps"]

        number_of_rounds = normalize_number_of_rounds(number_of_rounds)

        super().__init__(
            family_name="ktantan_fsr",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[block_bit_size, key_bit_size],
            cipher_output_bit_size=block_bit_size,
        )

        # ------------------------------------------------------------------ #
        # Feedback polynomials (same formula as katan_fsr_block_cipher)      #
        # ------------------------------------------------------------------ #
        fa_poly_no_ir = [
            [block_bit_size - 1 - x[0]],
            [block_bit_size - 1 - x[1]],
            [block_bit_size - 1 - x[2], block_bit_size - 1 - x[3]],
            [block_bit_size],
        ]
        fa_poly_with_ir = [
            [block_bit_size - 1 - x[0]],
            [block_bit_size - 1 - x[1]],
            [block_bit_size - 1 - x[2], block_bit_size - 1 - x[3]],
            [block_bit_size - 1 - x[4]],
            [block_bit_size],
        ]
        fb_poly = [
            [len_l2 - 1 - y[0]],
            [len_l2 - 1 - y[1]],
            [len_l2 - 1 - y[2], len_l2 - 1 - y[3]],
            [len_l2 - 1 - y[4], len_l2 - 1 - y[5]],
            [block_bit_size + 1],
        ]

        # ------------------------------------------------------------------ #
        # Key bits: all point directly to INPUT_KEY positions (no XOR comps) #
        # ------------------------------------------------------------------ #
        key_bits = [
            ComponentState([INPUT_KEY], [[key_bit_size - 1 - i]])
            for i in range(key_bit_size)
        ]

        # Pre-compute all round keys (pure Python — no CLAASP components added)
        ka, kb = self._expand_round_keys(key_bits, number_of_rounds)

        # ------------------------------------------------------------------ #
        # Initial state and output positions (same mapping as katan_fsr)     #
        # ------------------------------------------------------------------ #
        initial_state_bits = list(range(len_l1, block_bit_size)) + list(range(len_l1))
        output_positions = list(range(len_l2, block_bit_size)) + list(range(len_l2))

        state_source = INPUT_PLAINTEXT
        state_bits = initial_state_bits
        fsr = None

        for round_number in range(number_of_rounds):
            self.add_round()

            fa_poly = fa_poly_with_ir if get_ir_bit(round_number, ir_mode) else fa_poly_no_ir

            fsr_desc = [
                [[len_l2, fa_poly], [len_l1, fb_poly]],
                1,
            ]
            if steps > 1:
                fsr_desc.append(steps)

            ka_r = ka[round_number]
            kb_r = kb[round_number]

            fsr = self.add_fsr_component(
                [state_source, ka_r.id[0], kb_r.id[0]],
                [state_bits, ka_r.input_bit_positions[0], kb_r.input_bit_positions[0]],
                block_bit_size,
                fsr_desc,
            )
            state_source = fsr.id
            state_bits = list(range(block_bit_size))

            if round_number != number_of_rounds - 1:
                self.add_round_output_component(
                    [fsr.id], [output_positions], block_bit_size
                )

        self.add_cipher_output_component(
            [fsr.id], [output_positions], block_bit_size
        )

    # ---------------------------------------------------------------------- #
    # KTANTAN key schedule (pure Python — no CLAASP components)              #
    # ---------------------------------------------------------------------- #

    @staticmethod
    def _mux4(values, s0, s1):
        return values[s0 + (s1 << 1)]

    @staticmethod
    def _mux16(values, s):
        return values[s[0] + (s[1] << 1) + (s[2] << 2) + (s[3] << 3)]

    def _expand_round_keys(self, key_bits, number_of_rounds):
        ka = []
        kb = []
        t = [1] * 8

        for _ in range(number_of_rounds):
            tmp = t[7] ^ t[6] ^ t[4] ^ t[2]
            t = [tmp] + t[:-1]

            s16 = [t[4], t[5], t[6], t[7]]
            a0 = self._mux16(key_bits[0:16], s16)
            a4 = self._mux16(key_bits[64:80], s16)

            x4f = [
                self._mux16(key_bits[16:32], s16),
                self._mux16(key_bits[32:48], s16),
                self._mux16(key_bits[48:64], s16),
                self._mux16(key_bits[64:80], s16),
            ]
            x4g = [
                self._mux16(key_bits[0:16], s16),
                self._mux16(key_bits[16:32], s16),
                self._mux16(key_bits[32:48], s16),
                self._mux16(key_bits[48:64], s16),
            ]

            ka.append(a0 if t[3] == 0 and t[2] == 0 else self._mux4(x4f, t[0], t[1]))
            kb.append(a4 if t[3] == 0 and t[2] == 1 else self._mux4(x4g, 1 - t[0], 1 - t[1]))

        return ka, kb
