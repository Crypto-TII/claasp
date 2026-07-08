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
FSR-based implementation of the KATAN block cipher.

This module re-encodes each CLAASP round as a single ``add_FSR_component`` call
instead of the ~8-10 individual XOR/AND gate components used in
``katan_block_cipher.py``.  The result is a significantly smaller component
graph (~254 FSR + key-schedule components vs ~2500 gate components), which
reduces both construction time and evaluation time.

Register layout inside the FSR input vector (total: block_size + 2 bits)
-------------------------------------------------------------------------
* Positions 0 .. len_l2-1        : L2 register (MSB-first inside the register,
                                    i.e. FSR[j] = l2[len_l2-1-j]).
* Positions len_l2 .. block-1    : L1 register (same reversed mapping).
* Position  block_size           : ka = key_bits[2*r]   (not shifted by FSR).
* Position  block_size + 1       : kb = key_bits[2*r+1] (not shifted by FSR).

The two extra key-bit positions sit beyond the last register, so ``fsr_binary``
never touches them during the rotation; they are used only as inputs to the
feedback polynomials.

Feedback polynomials
---------------------
* L2 register (register 0, len_l2 bits): feedback = fa
    fa = l1[x1] ^ l1[x2] ^ (l1[x3] & l1[x4]) ^ (IR[r] & l1[x5]) ^ ka
    In FSR indices:  l1[xi] -> FSR[block_size - 1 - xi],  ka -> FSR[block_size]

* L1 register (register 1, len_l1 bits): feedback = fb  (same every round)
    fb = l2[y1] ^ l2[y2] ^ (l2[y3] & l2[y4]) ^ (l2[y5] & l2[y6]) ^ kb
    In FSR indices:  l2[yi] -> FSR[len_l2 - 1 - yi],  kb -> FSR[block_size+1]

Output bit order
-----------------
The gate-level cipher outputs ``reversed(l2 + l1)``.  In FSR coordinates that
equals  FSR[len_l2 .. block-1] ++ FSR[0 .. len_l2-1].
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


class KatanFSRBlockCipher(Cipher):
    """
    Construct an instance of the KatanFSRBlockCipher class.

    FSR-based re-implementation of KATAN that uses one ``add_fsr_component``
    per CLAASP round instead of individual XOR/AND gate components.

    Reference:
    - Python reference implementation: https://gist.github.com/raullenchai/2662701

    INPUT:

        - ``block_bit_size`` -- **integer** (default: `32`); Valid values: 32, 48, 64.
        - ``key_bit_size`` -- **integer** (default: `80`); must be 80.
        - ``number_of_rounds`` -- **integer** (default: `None`); defaults to 254.
        - ``ir_mode`` -- **string** (default: `"strict"`); how to handle rounds beyond the
            254-bit IR sequence. Use `"cycle"` to repeat the IR sequence.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.katan_fsr_block_cipher import KatanFSRBlockCipher
        sage: katan_fsr = KatanFSRBlockCipher()
        sage: katan_fsr.number_of_rounds
        254

        sage: key = 0xFFFFFFFFFFFFFFFFFFFF
        sage: plaintext = 0x00000000
        sage: hex(katan_fsr.evaluate([plaintext, key]))
        '0x7e1ff945'

        sage: KatanFSRBlockCipher(block_bit_size=48, number_of_rounds=4).id
        'katan_fsr_p48_k80_o48_r4'

        sage: KatanFSRBlockCipher(number_of_rounds=255, ir_mode='cycle').number_of_rounds
        255
    """

    def __init__(self, block_bit_size=32, key_bit_size=80, number_of_rounds=None, ir_mode="strict"):
        if block_bit_size not in CONFIGURATION:
            raise ValueError("No available configuration for the given block size.")
        if key_bit_size != 80:
            raise ValueError("KATAN uses a fixed 80-bit key.")

        config = CONFIGURATION[block_bit_size]
        len_l1 = config["len_l1"]
        len_l2 = config["len_l2"]
        x = config["x"]   # (x1, x2, x3, x4, x5) — L1 tap indices
        y = config["y"]   # (y1, y2, y3, y4, y5, y6) — L2 tap indices
        steps = config["steps"]  # register clocks per CLAASP round

        number_of_rounds = normalize_number_of_rounds(number_of_rounds)

        super().__init__(
            family_name="katan_fsr",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[block_bit_size, key_bit_size],
            cipher_output_bit_size=block_bit_size,
        )

        # ------------------------------------------------------------------ #
        # Pre-compute FSR feedback polynomials (static per cipher variant)   #
        # ------------------------------------------------------------------ #
        # l1[xi] -> FSR position (block_size - 1 - xi)
        # l2[yi] -> FSR position (len_l2 - 1 - yi)
        # ka     -> FSR position  block_size
        # kb     -> FSR position  block_size + 1

        # L2 register (register 0) feedback = fa  (uses L1 taps + ka)
        fa_poly_no_ir = [
            [block_bit_size - 1 - x[0]],
            [block_bit_size - 1 - x[1]],
            [block_bit_size - 1 - x[2], block_bit_size - 1 - x[3]],  # AND(l1[x3], l1[x4])
            [block_bit_size],                                          # ka
        ]
        fa_poly_with_ir = [
            [block_bit_size - 1 - x[0]],
            [block_bit_size - 1 - x[1]],
            [block_bit_size - 1 - x[2], block_bit_size - 1 - x[3]],  # AND(l1[x3], l1[x4])
            [block_bit_size - 1 - x[4]],                              # IR * l1[x5]  (IR=1 only)
            [block_bit_size],                                          # ka
        ]

        # L1 register (register 1) feedback = fb  (uses L2 taps + kb; same every round)
        fb_poly = [
            [len_l2 - 1 - y[0]],
            [len_l2 - 1 - y[1]],
            [len_l2 - 1 - y[2], len_l2 - 1 - y[3]],  # AND(l2[y3], l2[y4])
            [len_l2 - 1 - y[4], len_l2 - 1 - y[5]],  # AND(l2[y5], l2[y6])
            [block_bit_size + 1],                      # kb
        ]

        # ------------------------------------------------------------------ #
        # Key bits (ComponentState list, expanded via LFSR on demand)        #
        # ------------------------------------------------------------------ #
        key_bits = [
            ComponentState([INPUT_KEY], [[key_bit_size - 1 - i]])
            for i in range(key_bit_size)
        ]

        # ------------------------------------------------------------------ #
        # State bit positions                                                 #
        # ------------------------------------------------------------------ #
        # Initial state comes from INPUT_PLAINTEXT in FSR order:
        #   FSR[0..len_l2-1]      <- plaintext[len_l1 .. block_size-1]
        #   FSR[len_l2..block-1]  <- plaintext[0     .. len_l1-1]
        initial_state_bits = list(range(len_l1, block_bit_size)) + list(range(len_l1))

        # Output order:  reversed(l2 + l1)
        #   = [FSR[len_l2], ..., FSR[block-1], FSR[0], ..., FSR[len_l2-1]]
        output_positions = list(range(len_l2, block_bit_size)) + list(range(len_l2))

        # ------------------------------------------------------------------ #
        # Round construction                                                  #
        # ------------------------------------------------------------------ #
        state_source = INPUT_PLAINTEXT
        state_bits = initial_state_bits
        fsr = None

        for round_number in range(number_of_rounds):
            self.add_round()

            # Expand key schedule: need key_bits[2r] and key_bits[2r+1]
            while len(key_bits) <= 2 * round_number + 1:
                key_bits.append(self._xor_bits([
                    key_bits[-80],
                    key_bits[-61],
                    key_bits[-50],
                    key_bits[-13],
                ]))

            ka = key_bits[2 * round_number]
            kb = key_bits[2 * round_number + 1]

            # L2 feedback polynomial changes with the per-round IR bit.
            fa_poly = fa_poly_with_ir if get_ir_bit(round_number, ir_mode) else fa_poly_no_ir

            fsr_desc = [
                [[len_l2, fa_poly], [len_l1, fb_poly]],
                1,   # bit cell size = 1
            ]
            if steps > 1:
                fsr_desc.append(steps)

            fsr = self.add_fsr_component(
                [state_source, ka.id[0], kb.id[0]],
                [state_bits, ka.input_bit_positions[0], kb.input_bit_positions[0]],
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

    def _xor_bits(self, bits):
        if len(bits) == 1:
            return bits[0]
        component_id = self.add_xor_component(
            [bit.id[0] for bit in bits], [bit.input_bit_positions[0] for bit in bits], 1
        ).id
        return ComponentState([component_id], [[0]])
