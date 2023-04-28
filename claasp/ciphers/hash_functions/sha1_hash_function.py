
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


"""
SHA-1 cipher.

This module has been coded following the original RFC 3174. Every variable name
has been chosen to strictly adhere to the RFC.

The input is named *key* because the hash function SHA-1 can be seen like a
symmetric cipher whose plaintext is the initial state and key is the input.
"""
from claasp.cipher import Cipher
from claasp.name_mappings import INPUT_KEY
from claasp.DTOs.component_state import ComponentState

PARAMETERS_CONFIGURATION_LIST = [{'word_size': 32, 'number_of_rounds': 80}]


class SHA1HashFunction(Cipher):
    """
    Returns a cipher object of SHA1.

    .. WARNING::

        This cipher handles just the Graph Representation of 1 block input.

    INPUT:

    - ``word_size`` -- **integer** (default: `32`); the size of the word
    - ``number_of_rounds`` -- **integer** (default: `80`); the number of rounds

    EXAMPLES::

        sage: from claasp.ciphers.hash_functions.sha1_hash_function import SHA1HashFunction
        sage: sha1 = SHA1HashFunction()
        sage: plaintext = 0x43686961726180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030
        sage: ciphertext = 0x04f0c8e0efe316e609390a3d98e97f5acc53c199
        sage: sha1.evaluate([plaintext]) == ciphertext
        True
    """

    def __init__(self, word_size=32, number_of_rounds=80):

        self.word_size = word_size

        K = (0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6)
        H = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0)

        super().__init__(family_name="SHA1",
                         cipher_type="hash_function",
                         cipher_inputs=[INPUT_KEY],
                         cipher_inputs_bit_size=[word_size * 16],
                         cipher_output_bit_size=160)

        W = [ComponentState(INPUT_KEY, [list(range(i * self.word_size, (i + 1) * self.word_size))])
             for i in range(16)]

        self.add_round()
        Kt = self.add_constant_component(word_size, K[0])
        initial_state = [self.add_constant_component(word_size, h) for h in H]
        A = initial_state[0]
        B = initial_state[1]
        C = initial_state[2]
        D = initial_state[3]
        E = initial_state[4]
        TEMP, ROT_30_B = self.rounds_0_19(A, B, C, D, E, Kt, W[0])
        E, D, C, B, A = D, C, ROT_30_B, A, TEMP
        for t in range(1, min(16, number_of_rounds)):
            self.add_round_output_component_in_sha1(A, B, C, D, E)
            self.add_round()
            TEMP, ROT_30_B = self.rounds_0_19(A, B, C, D, E, Kt, W[t])
            E, D, C, B, A = D, C, ROT_30_B, A, TEMP

        for t in range(16, min(20, number_of_rounds)):
            self.add_round_output_component_in_sha1(A, B, C, D, E)
            self.add_round()
            W.append(self.schedule(W, t))
            TEMP, S_30_B = self.rounds_0_19(A, B, C, D, E, Kt, W[t])
            E, D, C, B, A = D, C, S_30_B, A, TEMP

        if number_of_rounds >= 20:
            self.add_round_output_component_in_sha1(A, B, C, D, E)
            self.add_round()
            Kt = self.add_constant_component(word_size, K[1])
            W.append(self.schedule(W, 20))
            TEMP, S_30_B = self.rounds_20_39(A, B, C, D, E, Kt, W[20])
            E, D, C, B, A = D, C, S_30_B, A, TEMP
            for t in range(21, min(40, number_of_rounds)):
                self.add_round_output_component_in_sha1(A, B, C, D, E)
                self.add_round()
                W.append(self.schedule(W, t))
                TEMP, S_30_B = self.rounds_20_39(A, B, C, D, E, Kt, W[t])
                E, D, C, B, A = D, C, S_30_B, A, TEMP

        if number_of_rounds >= 40:
            self.add_round_output_component_in_sha1(A, B, C, D, E)
            self.add_round()
            Kt = self.add_constant_component(word_size, K[2])
            W.append(self.schedule(W, 40))
            TEMP, S_30_B = self.rounds_40_59(A, B, C, D, E, Kt, W[40])
            E, D, C, B, A = D, C, S_30_B, A, TEMP
            for t in range(41, min(60, number_of_rounds)):
                self.add_round_output_component_in_sha1(A, B, C, D, E)
                self.add_round()
                W.append(self.schedule(W, t))
                TEMP, S_30_B = self.rounds_40_59(A, B, C, D, E, Kt, W[t])
                E, D, C, B, A = D, C, S_30_B, A, TEMP

        if number_of_rounds >= 60:
            self.add_round_output_component_in_sha1(A, B, C, D, E)
            self.add_round()
            Kt = self.add_constant_component(word_size, K[3])
            W.append(self.schedule(W, 60))
            TEMP, S_30_B = self.rounds_20_39(A, B, C, D, E, Kt, W[60])
            E, D, C, B, A = D, C, S_30_B, A, TEMP
            for t in range(61, number_of_rounds):
                self.add_round_output_component_in_sha1(A, B, C, D, E)
                self.add_round()
                W.append(self.schedule(W, t))
                TEMP, S_30_B = self.rounds_20_39(A, B, C, D, E, Kt, W[t])
                E, D, C, B, A = D, C, S_30_B, A, TEMP

        if number_of_rounds == 80:
            self.add_round_output_component_in_sha1(A, B, C, D, E)
            A = self.add_modadd_component_in_sha1(A, initial_state[0])
            B = self.add_modadd_component_in_sha1(B, initial_state[1])
            C = self.add_modadd_component_in_sha1(C, initial_state[2])
            D = self.add_modadd_component_in_sha1(D, initial_state[3])
            E = self.add_modadd_component_in_sha1(E, initial_state[4])

        self.add_cipher_output_component(
            [A.id, B.id, C.id, D.id, E.id],
            [list(range(self.word_size)) for _ in range(5)],
            self.word_size * 5)

    def add_and_component_in_sha1(self, component_0, component_1):
        return self.add_AND_component([component_0.id, component_1.id],
                                      [list(range(self.word_size)), list(range(self.word_size))],
                                      self.word_size)

    def add_modadd_component_in_sha1(self, component_0, component_1):
        return self.add_MODADD_component([component_0.id, component_1.id],
                                         [list(range(self.word_size)), list(range(self.word_size))],
                                         self.word_size)

    def add_rotate_component_in_sha1(self, component, amount):
        return self.add_rotate_component([component.id],
                                         [list(range(self.word_size))],
                                         self.word_size,
                                         amount)

    def add_round_output_component_in_sha1(self, A, B, C, D, E):
        return self.add_round_output_component([A.id, B.id, C.id, D.id, E.id],
                                               [list(range(self.word_size)) for _ in range(5)],
                                               self.word_size * 5)

    def compute_temp_and_s_30_b(self, A, B, E, ft_B_C_D, K, W):
        S_5_A = self.add_rotate_component_in_sha1(A, -(5 % self.word_size))
        TEMP = self.add_MODADD_component([S_5_A.id, ft_B_C_D.id, E.id, K.id, W.id],
                                         [list(range(self.word_size)) for _ in range(4)] + W.input_bit_positions,
                                         self.word_size)
        S_30_B = self.add_rotate_component_in_sha1(B, -(30 % self.word_size))

        return TEMP, S_30_B

    def rounds_0_19(self, A, B, C, D, E, K, W):
        B_AND_C = self.add_and_component_in_sha1(B, C)
        NOT_B = self.add_NOT_component([B.id], [list(range(self.word_size))], self.word_size)
        NOT_B_AND_D = self.add_and_component_in_sha1(NOT_B, D)
        ft_B_C_D = self.add_OR_component([B_AND_C.id, NOT_B_AND_D.id],
                                         [list(range(self.word_size)), list(range(self.word_size))],
                                         self.word_size)

        return self.compute_temp_and_s_30_b(A, B, E, ft_B_C_D, K, W)

    def rounds_20_39(self, A, B, C, D, E, K, W):
        ft_B_C_D = self.add_XOR_component(
            [B.id, C.id, D.id],
            [list(range(self.word_size)), list(range(self.word_size)), list(range(self.word_size))],
            self.word_size)

        return self.compute_temp_and_s_30_b(A, B, E, ft_B_C_D, K, W)

    def rounds_40_59(self, A, B, C, D, E, K, W):
        B_AND_C = self.add_and_component_in_sha1(B, C)
        B_AND_D = self.add_and_component_in_sha1(B, D)
        C_AND_D = self.add_and_component_in_sha1(C, D)
        ft_B_C_D = self.add_OR_component(
            [B_AND_C.id, B_AND_D.id, C_AND_D.id],
            [list(range(self.word_size)), list(range(self.word_size)), list(range(self.word_size))],
            self.word_size)

        return self.compute_temp_and_s_30_b(A, B, E, ft_B_C_D, K, W)

    def schedule(self, W, t):
        Wt_temp = self.add_XOR_component([W[t - 3].id, W[t - 8].id, W[t - 14].id, W[t - 16].id],
                                         W[t - 3].input_bit_positions + W[t - 8].input_bit_positions +
                                         W[t - 14].input_bit_positions + W[t - 16].input_bit_positions,
                                         self.word_size)
        Wt = self.add_rotate_component_in_sha1(Wt_temp, -1)

        return ComponentState(Wt.id, [list(range(self.word_size))])
