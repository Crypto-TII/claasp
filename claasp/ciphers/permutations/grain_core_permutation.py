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
from claasp.name_mappings import INPUT_STATE, PERMUTATION

PARAMETERS_CONFIGURATION_LIST = [{"number_of_rounds": 160}]

# Grain v1 ("Grain-80") core initialization feedback, expressed as absolute bit indices into the
# single 160-bit concatenated state used by add_fsr_component (register 1 = LFSR, register 2 = NFSR):
#   absolute index k, 0  <= k < 80  -> LFSR position s_k
#   absolute index k, 80 <= k < 160 -> NFSR position b_(k-80)
#
# LFSR_CORE_POLY computes, per clock, the new LFSR bit that is fed into the register:
#   new_s = f(x) XOR z_i
# where f(x) = s_{i+62}+s_{i+51}+s_{i+38}+s_{i+23}+s_{i+13}+s_i is the linear LFSR feedback and z_i is
# the full Grain v1 output/keystream bit (filter function h(x) XORed with a 7-bit linear sum of NFSR
# taps). During the 160-clock initialization phase z_i is fed back into both registers.
LFSR_CORE_POLY = [
    [0], [13], [23], [38], [51], [62],  # f(x): LFSR linear feedback
    [25], [143], [3, 64], [46, 64], [64, 143], [3, 25, 46], [3, 46, 64], [3, 46, 143], [25, 46, 143],
    [46, 64, 143],  # h(x)
    [81], [82], [84], [90], [111], [123], [136],  # 7-bit NFSR sum (taps 1,2,4,10,31,43,56 -> abs 80+k)
]

# NFSR_CORE_POLY computes, per clock, the new NFSR bit that is fed into the register:
#   new_b = (s_i + g(x)) XOR z_i
# where g(x) is the (nonlinear) NFSR feedback polynomial (linear taps plus AND product terms) and z_i is
# the same full output bit as above.
NFSR_CORE_POLY = [
    [80], [89], [94], [101], [108], [113], [117], [125], [132], [140], [142], [0],  # g(x) linear part + s_i
    [143, 140], [117, 113], [95, 89],
    [140, 132, 125], [113, 108, 101],
    [143, 125, 108, 89], [140, 132, 117, 113], [143, 140, 101, 95],
    [143, 140, 132, 125, 117], [113, 108, 101, 95, 89],
    [132, 125, 117, 113, 108, 101],  # g(x) product/AND terms
    [25], [143], [3, 64], [46, 64], [64, 143], [3, 25, 46], [3, 46, 64], [3, 46, 143], [25, 46, 143],
    [46, 64, 143],  # h(x)
    [81], [82], [84], [90], [111], [123], [136],  # 7-bit NFSR sum
]

# One register per FSR, cell size (word size) of 1 bit, one clock performed per add_fsr_component call.
GRAIN_CORE_DESCRIPTION = [[[80, LFSR_CORE_POLY], [80, NFSR_CORE_POLY]], 1]


class GrainCorePermutation(Cipher):
    """
    Construct an instance of the GrainCorePermutation class.

    This class implements the 160-clock key/IV-initialization core of **Grain v1** (the "Grain-80" variant:
    80-bit key, 64-bit IV, 160-bit internal state), as specified by Hell, Johansson and Meier, "Grain: A
    stream cipher for constrained environments" (2005), later tweaked and submitted to the eSTREAM project,
    where the tweaked version became known as "Grain v1" and was selected for the eSTREAM portfolio. This is
    **not** Grain-128, Grain-128a, or Grain-128AEAD -- those are different, incompatible members of the
    Grain family with different state sizes and (for the 128a/AEAD variants) authentication.

    Grain v1's internal state is 160 bits, made of an 80-bit LFSR (linear feedback shift register, denoted
    ``s``) and an 80-bit NFSR (nonlinear feedback shift register, denoted ``b``). This class models exactly
    one clock of the initialization ("key-scheduling") phase per round, applied to the full 160-bit state:

    - LFSR feedback (linear): ``s_{i+80} = s_{i+62} + s_{i+51} + s_{i+38} + s_{i+23} + s_{i+13} + s_i``
    - NFSR feedback (nonlinear): ``b_{i+80} = s_i + g(b_i, ..., b_{i+63})`` (see the reference for the full
      polynomial ``g``, reproduced verbatim in ``NFSR_CORE_POLY`` below)
    - Filter function: ``h(x)`` with ``x0=s_{i+3}, x1=s_{i+25}, x2=s_{i+46}, x3=s_{i+64}, x4=b_{i+63}``
    - Output bit: ``z_i = h(x) + b_{i+1} + b_{i+2} + b_{i+4} + b_{i+10} + b_{i+31} + b_{i+43} + b_{i+56}``

    During initialization, unlike during keystream generation, the output bit ``z_i`` is fed back (XORed)
    into both the new LFSR bit and the new NFSR bit before they are shifted into their respective registers:
    ``new_s = f(x) XOR z_i`` and ``new_b = (s_i + g(x)) XOR z_i``, where ``f(x)`` is the LFSR's own linear
    feedback. This is exactly what ``INPUT_STATE`` clocked 160 times (``INITCLOCKS`` in the reference C
    implementation) represents; the default ``number_of_rounds`` of 160 matches this.

    The single 160-bit ``INPUT_STATE`` is laid out as follows:

    - bits 0-79: LFSR content, with bit ``i`` holding ``s_i`` (``s_0`` at bit 0, ..., ``s_79`` at bit 79)
    - bits 80-159: NFSR content, with bit ``80 + i`` holding ``b_i`` (``b_0`` at bit 80, ..., ``b_79`` at
      bit 159)

    This class purposefully stops at the end of the 160-clock initialization core: it does not perform
    key/IV loading (turning an 80-bit key and 64-bit IV into the initial 160-bit state) and it does not
    implement keystream generation (which, unlike initialization, does not feed ``z_i`` back into the
    registers, and instead releases it as output). A full ``GrainStreamCipher`` implementing key/IV setup
    and keystream extraction on top of this core is out of scope here.

    INPUT:

    - ``number_of_rounds`` -- **integer** (default: `None`); number of initialization clocks of the
      permutation. By default, the cipher uses 160 (Grain v1's ``INITCLOCKS``).

    EXAMPLES::

        sage: from claasp.ciphers.permutations.grain_core_permutation import GrainCorePermutation
        sage: grain_core = GrainCorePermutation()
        sage: grain_core.number_of_rounds
        160

        sage: grain_core.component_from(0, 0).id
        'fsr_0_0'

        sage: grain_core.evaluate([0x0000000000000000ffff00000000000000000000]) == 0x4eb431bcc5344efb12da6d7b0599918a2f079726
        True
    """

    def __init__(self, number_of_rounds=None):
        self.state_bit_size = 160

        if number_of_rounds is None:
            n = PARAMETERS_CONFIGURATION_LIST[0]["number_of_rounds"]
        else:
            n = number_of_rounds

        super().__init__(
            family_name="grain_core",
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_STATE],
            cipher_inputs_bit_size=[self.state_bit_size],
            cipher_output_bit_size=self.state_bit_size,
        )

        state_id = INPUT_STATE
        state_positions = list(range(self.state_bit_size))

        for _ in range(n):
            self.add_round()

            state_id = self.add_fsr_component(
                [state_id], [state_positions], self.state_bit_size, GRAIN_CORE_DESCRIPTION
            ).id
            state_positions = list(range(self.state_bit_size))

            self.add_round_output_component([state_id], [state_positions], self.state_bit_size)

        self.add_cipher_output_component([state_id], [state_positions], self.state_bit_size)
