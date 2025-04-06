
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
MD5 cipher.

This module has been coded following the original RFC 1321. Every variable name
has been chosen to strictly adhere to the RFC.

The input is named *key* because the hash function MD5 can be seen like a
symmetric cipher whose plaintext is the initial state and key is the input.
"""
from claasp.cipher import Cipher
from claasp.DTOs.component_state import ComponentState
from claasp.name_mappings import INPUT_MESSAGE

PARAMETERS_CONFIGURATION_LIST = [{"word_size": 32, "number_of_rounds": 64}]


class MD5HashFunction(Cipher):
    """
    Returns a cipher object of MD5.

    .. WARNING::

        This cipher handles just the Graph Representation of 1 block input.
        In this implementation, a round is a single step inside the round of the RFC 1321.

    INPUT:

    - ``word_size`` -- **integer** (default: `32`); the size of the word
    - ``number_of_rounds`` -- **integer** (default: `64`); the number of rounds

    EXAMPLES::

        sage: from claasp.ciphers.hash_functions.md5_hash_function import MD5HashFunction
        sage: md5 = MD5HashFunction()
        sage: message = 0x5175656c2066657a20736768656d626f20636f70726520646176616e74692e8000000000000000000000000000000000000000000000000000000000000000f8
        sage: digest = 0x3956fba8c05053e5a27040b8ab9a7545
        sage: md5.evaluate([message]) == digest
        True
    """

    def __init__(self, word_size=32, number_of_rounds=64):

        self.word_size = word_size

        super().__init__(family_name="MD5",
                         cipher_type="hash_function",
                         cipher_inputs=[INPUT_MESSAGE],
                         cipher_inputs_bit_size=[word_size * 16],
                         cipher_output_bit_size=64)

        k = (lambda i: i, lambda i: (5 * i + 1) % 16, lambda i: (3 * i + 5) % 16, lambda i: 7 * i % 16)

        s = ((7, 12, 17, 22), (5, 9, 14, 20), (4, 11, 16, 23), (6, 10, 15, 21))

        aux = (self.F, self.G, self.H, self.I)

        T = (0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
             0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
             0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
             0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
             0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
             0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
             0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
             0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391)

        unit_len = self.word_size // 4
        swap_little_big_positions = []
        for i in range(unit_len * 3, -1, -unit_len):
            swap_little_big_positions.extend(tuple(range(i, i + unit_len)))

        X = [ComponentState(INPUT_MESSAGE, [list(map(lambda p: p + i * self.word_size, swap_little_big_positions))])
             for i in range(14)]
        X += [ComponentState(INPUT_MESSAGE, [list(range(15 * self.word_size, 16 * self.word_size))]),
              ComponentState(INPUT_MESSAGE, [list(range(14 * self.word_size, 15 * self.word_size))])]

        self.add_round()

        A = self.add_constant_component(self.word_size, 0x67452301)
        B = self.add_constant_component(self.word_size, 0xefcdab89)
        C = self.add_constant_component(self.word_size, 0x98badcfe)
        D = self.add_constant_component(self.word_size, 0x10325476)

        AA = A
        BB = B
        CC = C
        DD = D

        A, B, C, D = self.md5_step(A, B, C, D, 0, s[0][0], 0, self.F, X, T)

        for i in range(1, number_of_rounds):
            self.add_round_output_component_in_md5(A, B, C, D)
            self.add_round()
            index = i // 16
            A, B, C, D = self.md5_step(A, B, C, D, k[index](i), s[index][i % 4], i, aux[index], X, T)

        if number_of_rounds < 64:
            self.add_cipher_output_component([A.id, B.id, C.id, D.id],
                                             [list(range(self.word_size)) for _ in range(4)],
                                             self.word_size * 4)
        else:
            self.add_round_output_component_in_md5(A, B, C, D)
            A = self.add_modadd_component_in_md5(A, AA)
            B = self.add_modadd_component_in_md5(B, BB)
            C = self.add_modadd_component_in_md5(C, CC)
            D = self.add_modadd_component_in_md5(D, DD)
            self.add_cipher_output_component([A.id, B.id, C.id, D.id],
                                             [swap_little_big_positions for _ in range(4)],
                                             self.word_size * 4)

    def md5_step(self, a, b, c, d, k, s, i, function, X, T):
        Ti = self.add_constant_component(self.word_size, T[i])
        a_Fbcd = self.add_modadd_component_in_md5(a, function(b, c, d))
        Xk_Ti = self.add_modadd_component_in_md5_for_x(X[k], Ti)
        a_Fbcd_Xk_Ti = self.add_modadd_component_in_md5(a_Fbcd, Xk_Ti)
        rot_s = self.add_rotate_component_in_md5(a_Fbcd_Xk_Ti, -s)
        a = self.add_modadd_component_in_md5(b, rot_s)

        return d, a, b, c

    def F(self, X, Y, Z):
        X_and_Y = self.add_and_component_in_md5(X, Y)
        notX = self.add_not_component_in_md5(X)
        notX_and_Z = self.add_and_component_in_md5(notX, Z)
        return self.add_or_component_in_md5(X_and_Y, notX_and_Z)

    def G(self, X, Y, Z):
        return self.F(Z, X, Y)

    def H(self, X, Y, Z):
        X_xor_Y = self.add_xor_component_in_md5(X, Y)
        return self.add_xor_component_in_md5(X_xor_Y, Z)

    def I(self, X, Y, Z):
        notZ = self.add_not_component_in_md5(Z)
        X_or_notZ = self.add_or_component_in_md5(X, notZ)
        return self.add_xor_component_in_md5(Y, X_or_notZ)

    def add_and_component_in_md5(self, component_0, component_1):
        return self.add_AND_component([component_0.id, component_1.id],
                                      [list(range(self.word_size)), list(range(self.word_size))],
                                      self.word_size)

    def add_modadd_component_in_md5(self, component_0, component_1):
        return self.add_MODADD_component([component_0.id, component_1.id],
                                         [list(range(self.word_size)), list(range(self.word_size))],
                                         self.word_size)

    def add_modadd_component_in_md5_for_x(self, x, component):
        return self.add_MODADD_component([x.id, component.id],
                                         [x.input_bit_positions[0], list(range(self.word_size))],
                                         self.word_size)

    def add_rotate_component_in_md5(self, component, amount):
        return self.add_rotate_component([component.id],
                                         [list(range(self.word_size))],
                                         self.word_size,
                                         amount)

    def add_xor_component_in_md5(self, component_0, component_1):
        return self.add_XOR_component([component_0.id, component_1.id],
                                      [list(range(self.word_size)), list(range(self.word_size))],
                                      self.word_size)

    def add_or_component_in_md5(self, component_0, component_1):
        return self.add_OR_component([component_0.id, component_1.id],
                                     [list(range(self.word_size)), list(range(self.word_size))],
                                     self.word_size)

    def add_not_component_in_md5(self, component):
        return self.add_NOT_component([component.id],
                                      [list(range(self.word_size))],
                                      self.word_size)

    def add_round_output_component_in_md5(self, A, B, C, D):
        return self.add_round_output_component([A.id, B.id, C.id, D.id],
                                               [list(range(self.word_size)) for _ in range(4)],
                                               self.word_size * 4)
