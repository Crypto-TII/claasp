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
SHA-2 family cipher.

This module has been coded following the original RFC 6234. Every variable name
has been chosen to strictly adhere to the RFC.

The input is named *key* because the hash functions in the SHA-2 family can be
seen like a symmetric cipher whose plaintext is the initial state and key is
the input.
"""

from claasp.cipher import Cipher
from claasp.name_mappings import INPUT_MESSAGE
from claasp.DTOs.component_state import ComponentState


PARAMETERS_CONFIGURATION_LIST = [
    {"output_bit_size": 256, "number_of_rounds": 64},
    {"output_bit_size": 224, "number_of_rounds": 64},
    {"output_bit_size": 512, "number_of_rounds": 80},
    {"output_bit_size": 384, "number_of_rounds": 80},
]


class SHA2HashFunction(Cipher):
    """
    Returns a cipher object of SHA-224, SHA-256, SHA-384 or SHA-512.

    .. WARNING::

        This cipher handles just the Graph Representation of 1 block input.

    INPUT:

    - ``output_bit_size`` -- **integer** (default: `256`); size of the cipher output, must be equal to 224, 256,
      384, 512
    - ``number_of_rounds`` -- **integer** (default: `64`); the number of rounds

    EXAMPLES::

        sage: from claasp.ciphers.hash_functions.sha2_hash_function import SHA2HashFunction
        sage: sha2 = SHA2HashFunction()
        sage: sha2.print_cipher_structure_as_python_dictionary_to_file(  # doctest: +SKIP
        ....: "claasp/graph_representations/hash_functions/sha256")  # doctest: +SKIP

        sage: from claasp.ciphers.hash_functions.sha2_hash_function import SHA2HashFunction
        sage: sha2 = SHA2HashFunction()
        sage: message = 0x43686961726180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030
        sage: digest = 0x0d8d2647a12b0d544989a6b03603b8b3c27e2c4e0be08671745366d1a8bc4d95
        sage: sha2.evaluate([message]) == digest
        True
    """

    def __init__(self, output_bit_size=256, number_of_rounds=64):
        if output_bit_size not in (224, 256, 384, 512):
            raise ValueError("output_bit_size should be in the set {224, 256, 384, 512}.")

        if output_bit_size in (224, 256):
            self.word_size = 32
            key_for_K_dict = 256
            max_rounds = 64
        else:
            self.word_size = 64
            key_for_K_dict = 512
            max_rounds = 80

        super().__init__(
            family_name="SHA2_family",
            cipher_type="hash_function",
            cipher_inputs=[INPUT_MESSAGE],
            cipher_inputs_bit_size=[self.word_size * 16],
            cipher_output_bit_size=output_bit_size,
        )

        # constants K as function on output_bit_size
        # fmt: off
        K = {
            256: (
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
            ),
            512: (
                0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
                0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
                0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
                0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
                0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
                0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
                0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
                0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
                0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
                0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
                0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
                0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
                0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
                0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
                0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
                0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
                0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
                0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
                0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
            )
        }

        # states H as function on output_bit_size
        H = {
            256: (
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ),
            224: (
                0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
                0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
            ),
            384: (
                0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
                0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
            ),
            512: (
                0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
            )
        }
        # fmt: on

        if self.output_bit_size in (256, 512):
            numbers_of_words_in_digest = 8
        elif self.output_bit_size == 224:
            numbers_of_words_in_digest = 7
        elif self.output_bit_size == 384:
            numbers_of_words_in_digest = 6

        W = [
            ComponentState(INPUT_MESSAGE, [list(range(t * self.word_size, (t + 1) * self.word_size))])
            for t in range(16)
        ]

        self.add_round()

        Kt = self.add_constant_component(self.word_size, K[key_for_K_dict][0])

        initial_state = [self.add_constant_component(self.word_size, state) for state in H[self.output_bit_size]]
        a = initial_state[0]
        b = initial_state[1]
        c = initial_state[2]
        d = initial_state[3]
        e = initial_state[4]
        f = initial_state[5]
        g = initial_state[6]
        h = initial_state[7]

        T1_MODADD_d, T1_MODADD_T2 = self.round_function(a, b, c, d, e, f, g, h, Kt, W[0])
        h, g, f, e, d, c, b, a = g, f, e, T1_MODADD_d, c, b, a, T1_MODADD_T2

        for t in range(1, min(16, number_of_rounds)):
            self.add_round_output_component_sha2(a, b, c, d, e, f, g, h)
            self.add_round()
            Kt = self.add_constant_component(self.word_size, K[key_for_K_dict][t])
            T1_MODADD_d, T1_MODADD_T2 = self.round_function(a, b, c, d, e, f, g, h, Kt, W[t])
            h, g, f, e, d, c, b, a = g, f, e, T1_MODADD_d, c, b, a, T1_MODADD_T2

        for t in range(16, min(max_rounds, number_of_rounds)):
            self.add_round_output_component_sha2(a, b, c, d, e, f, g, h)
            self.add_round()
            W.append(self.schedule(W, t))
            Kt = self.add_constant_component(self.word_size, K[key_for_K_dict][t])
            T1_MODADD_d, T1_MODADD_T2 = self.round_function(a, b, c, d, e, f, g, h, Kt, W[t])
            h, g, f, e, d, c, b, a = g, f, e, T1_MODADD_d, c, b, a, T1_MODADD_T2

        if number_of_rounds == max_rounds:
            self.add_round_output_component_sha2(a, b, c, d, e, f, g, h)
            self.add_round()
            a = self.add_modadd_component_sha2(a, initial_state[0])
            b = self.add_modadd_component_sha2(b, initial_state[1])
            c = self.add_modadd_component_sha2(c, initial_state[2])
            d = self.add_modadd_component_sha2(d, initial_state[3])
            e = self.add_modadd_component_sha2(e, initial_state[4])
            f = self.add_modadd_component_sha2(f, initial_state[5])
            g = self.add_modadd_component_sha2(g, initial_state[6])
            h = self.add_modadd_component_sha2(h, initial_state[7])

        cipher_output_state = (a, b, c, d, e, f, g, h)

        self.add_cipher_output_component(
            [cipher_output_state[i].id for i in range(numbers_of_words_in_digest)],
            [list(range(self.word_size)) for _ in range(numbers_of_words_in_digest)],
            self.word_size * numbers_of_words_in_digest,
        )

    def add_and_component_sha2(self, component_0, component_1):
        return self.add_AND_component(
            [component_0.id, component_1.id], [list(range(self.word_size)), list(range(self.word_size))], self.word_size
        )

    def add_modadd_component_sha2(self, component_0, component_1):
        return self.add_MODADD_component(
            [component_0.id, component_1.id], [list(range(self.word_size)), list(range(self.word_size))], self.word_size
        )

    def add_rotate_component_sha2(self, component, amount):
        return self.add_rotate_component([component.id], [list(range(self.word_size))], self.word_size, amount)

    def add_round_output_component_sha2(self, a, b, c, d, e, f, g, h):
        return self.add_round_output_component(
            [a.id, b.id, c.id, d.id, e.id, f.id, g.id, h.id],
            [list(range(self.word_size)) for _ in range(8)],
            self.word_size * 8,
        )

    def add_xor_component_sha2(self, component_0, component_1):
        return self.add_XOR_component(
            [component_0.id, component_1.id], [list(range(self.word_size)), list(range(self.word_size))], self.word_size
        )

    def compute_bsig0_bsig1(self, component_0, component_1):
        if self.output_bit_size in (224, 256):
            ROTR_2 = self.add_rotate_component_sha2(component_0, 2)
            ROTR_13 = self.add_rotate_component_sha2(component_0, 13)
            ROTR_22 = self.add_rotate_component_sha2(component_0, 22)

            BSIG0 = self.add_XOR_component(
                [ROTR_2.id, ROTR_13.id, ROTR_22.id], [list(range(self.word_size)) for _ in range(3)], self.word_size
            )

            ROTR_6 = self.add_rotate_component_sha2(component_1, 6)
            ROTR_11 = self.add_rotate_component_sha2(component_1, 11)
            ROTR_25 = self.add_rotate_component_sha2(component_1, 25)

            BSIG1 = self.add_XOR_component(
                [ROTR_6.id, ROTR_11.id, ROTR_25.id], [list(range(self.word_size)) for _ in range(3)], self.word_size
            )

        elif self.output_bit_size in (384, 512):
            ROTR_28 = self.add_rotate_component_sha2(component_0, 28)
            ROTR_34 = self.add_rotate_component_sha2(component_0, 34)
            ROTR_39 = self.add_rotate_component_sha2(component_0, 39)

            BSIG0 = self.add_XOR_component(
                [ROTR_28.id, ROTR_34.id, ROTR_39.id], [list(range(self.word_size)) for _ in range(3)], self.word_size
            )

            ROTR_14 = self.add_rotate_component_sha2(component_1, 14)
            ROTR_18 = self.add_rotate_component_sha2(component_1, 18)
            ROTR_41 = self.add_rotate_component_sha2(component_1, 41)

            BSIG1 = self.add_XOR_component(
                [ROTR_14.id, ROTR_18.id, ROTR_41.id], [list(range(self.word_size)) for _ in range(3)], self.word_size
            )

        return BSIG0, BSIG1

    def compute_ch(self, x, y, z):
        x_AND_y = self.add_and_component_sha2(x, y)
        NOT_x = self.add_NOT_component([x.id], [list(range(self.word_size))], self.word_size)
        NOT_x_XOR_z = self.add_and_component_sha2(NOT_x, z)

        return self.add_xor_component_sha2(x_AND_y, NOT_x_XOR_z)

    def compute_maj(self, x, y, z):
        x_AND_y = self.add_and_component_sha2(x, y)
        y_AND_z = self.add_and_component_sha2(y, z)
        x_AND_z = self.add_and_component_sha2(x, z)

        return self.add_XOR_component(
            [x_AND_y.id, y_AND_z.id, x_AND_z.id], [list(range(self.word_size)) for _ in range(3)], self.word_size
        )

    def compute_ssig0_ssig1(self, W, t):
        if self.output_bit_size in (224, 256):
            ROTR_7 = self.add_rotate_component([W[t - 15].id], W[t - 15].input_bit_positions, self.word_size, 7)
            ROTR_18 = self.add_rotate_component([W[t - 15].id], W[t - 15].input_bit_positions, self.word_size, 18)
            SHR_3 = self.add_SHIFT_component([W[t - 15].id], W[t - 15].input_bit_positions, self.word_size, 3)

            SSIG0 = self.add_XOR_component(
                [ROTR_7.id, ROTR_18.id, SHR_3.id], [list(range(self.word_size)) for _ in range(3)], self.word_size
            )

            ROTR_17 = self.add_rotate_component([W[t - 2].id], W[t - 2].input_bit_positions, self.word_size, 17)
            ROTR_19 = self.add_rotate_component([W[t - 2].id], W[t - 2].input_bit_positions, self.word_size, 19)
            SHR_10 = self.add_SHIFT_component([W[t - 2].id], W[t - 2].input_bit_positions, self.word_size, 10)

            SSIG1 = self.add_XOR_component(
                [ROTR_17.id, ROTR_19.id, SHR_10.id], [list(range(self.word_size)) for _ in range(3)], self.word_size
            )

        elif self.output_bit_size in (384, 512):
            ROTR_1 = self.add_rotate_component([W[t - 15].id], W[t - 15].input_bit_positions, self.word_size, 1)
            ROTR_8 = self.add_rotate_component([W[t - 15].id], W[t - 15].input_bit_positions, self.word_size, 8)
            SHR_7 = self.add_SHIFT_component([W[t - 15].id], W[t - 15].input_bit_positions, self.word_size, 7)

            SSIG0 = self.add_XOR_component(
                [ROTR_1.id, ROTR_8.id, SHR_7.id], [list(range(self.word_size)) for _ in range(3)], self.word_size
            )

            ROTR_19 = self.add_rotate_component([W[t - 2].id], W[t - 2].input_bit_positions, self.word_size, 19)
            ROTR_61 = self.add_rotate_component([W[t - 2].id], W[t - 2].input_bit_positions, self.word_size, 61)
            SHR_6 = self.add_SHIFT_component([W[t - 2].id], W[t - 2].input_bit_positions, self.word_size, 6)

            SSIG1 = self.add_XOR_component(
                [ROTR_19.id, ROTR_61.id, SHR_6.id], [list(range(self.word_size)) for _ in range(3)], self.word_size
            )

        return SSIG0, SSIG1

    def round_function(self, a, b, c, d, e, f, g, h, Kt, W):
        BSIG0_a, BSIG1_e = self.compute_bsig0_bsig1(a, e)
        CH_e_f_g = self.compute_ch(e, f, g)

        T1 = self.add_MODADD_component(
            [h.id, BSIG1_e.id, CH_e_f_g.id, Kt.id, W.id],
            [list(range(self.word_size)) for _ in range(4)] + W.input_bit_positions,
            self.word_size,
        )

        MAJ_a_b_c = self.compute_maj(a, b, c)
        T2 = self.add_modadd_component_sha2(BSIG0_a, MAJ_a_b_c)
        T1_MODADD_d = self.add_modadd_component_sha2(T1, d)
        T1_MODADD_T2 = self.add_modadd_component_sha2(T1, T2)

        return T1_MODADD_d, T1_MODADD_T2

    def schedule(self, W, t):
        W15, W2 = self.compute_ssig0_ssig1(W, t)

        Wt = self.add_MODADD_component(
            [W15.id, W2.id, W[t - 7].id, W[t - 16].id],
            [list(range(self.word_size)), list(range(self.word_size))]
            + W[t - 7].input_bit_positions
            + W[t - 16].input_bit_positions,
            self.word_size,
        )

        return ComponentState(Wt.id, [list(range(self.word_size))])
