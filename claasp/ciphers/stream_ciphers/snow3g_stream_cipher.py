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
from claasp.cipher import Cipher
from claasp.DTOs.component_state import ComponentState
from claasp.name_mappings import INPUT_KEY, INPUT_INITIALIZATION_VECTOR

SBoxA = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
         0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
         0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
         0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
         0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
         0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
         0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
         0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
         0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
         0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
         0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
         0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
         0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
         0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
         0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
         0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
         ]

SBoxQ = [0x25, 0x24, 0x73, 0x67, 0xD7, 0xAE, 0x5C, 0x30, 0xA4, 0xEE, 0x6E, 0xCB, 0x7D, 0xB5, 0x82, 0xDB,
         0xE4, 0x8E, 0x48, 0x49, 0x4F, 0x5D, 0x6A, 0x78, 0x70, 0x88, 0xE8, 0x5F, 0x5E, 0x84, 0x65, 0xE2,
         0xD8, 0xE9, 0xCC, 0xED, 0x40, 0x2F, 0x11, 0x28, 0x57, 0xD2, 0xAC, 0xE3, 0x4A, 0x15, 0x1B, 0xB9,
         0xB2, 0x80, 0x85, 0xA6, 0x2E, 0x02, 0x47, 0x29, 0x07, 0x4B, 0x0E, 0xC1, 0x51, 0xAA, 0x89, 0xD4,
         0xCA, 0x01, 0x46, 0xB3, 0xEF, 0xDD, 0x44, 0x7B, 0xC2, 0x7F, 0xBE, 0xC3, 0x9F, 0x20, 0x4C, 0x64,
         0x83, 0xA2, 0x68, 0x42, 0x13, 0xB4, 0x41, 0xCD, 0xBA, 0xC6, 0xBB, 0x6D, 0x4D, 0x71, 0x21, 0xF4,
         0x8D, 0xB0, 0xE5, 0x93, 0xFE, 0x8F, 0xE6, 0xCF, 0x43, 0x45, 0x31, 0x22, 0x37, 0x36, 0x96, 0xFA,
         0xBC, 0x0F, 0x08, 0x52, 0x1D, 0x55, 0x1A, 0xC5, 0x4E, 0x23, 0x69, 0x7A, 0x92, 0xFF, 0x5B, 0x5A,
         0xEB, 0x9A, 0x1C, 0xA9, 0xD1, 0x7E, 0x0D, 0xFC, 0x50, 0x8A, 0xB6, 0x62, 0xF5, 0x0A, 0xF8, 0xDC,
         0x03, 0x3C, 0x0C, 0x39, 0xF1, 0xB8, 0xF3, 0x3D, 0xF2, 0xD5, 0x97, 0x66, 0x81, 0x32, 0xA0, 0x00,
         0x06, 0xCE, 0xF6, 0xEA, 0xB7, 0x17, 0xF7, 0x8C, 0x79, 0xD6, 0xA7, 0xBF, 0x8B, 0x3F, 0x1F, 0x53,
         0x63, 0x75, 0x35, 0x2C, 0x60, 0xFD, 0x27, 0xD3, 0x94, 0xA5, 0x7C, 0xA1, 0x05, 0x58, 0x2D, 0xBD,
         0xD9, 0xC7, 0xAF, 0x6B, 0x54, 0x0B, 0xE0, 0x38, 0x04, 0xC8, 0x9D, 0xE7, 0x14, 0xB1, 0x87, 0x9C,
         0xDF, 0x6F, 0xF9, 0xDA, 0x2A, 0xC4, 0x59, 0x16, 0x74, 0x91, 0xAB, 0x26, 0x61, 0x76, 0x34, 0x2B,
         0xAD, 0x99, 0xFB, 0x72, 0xEC, 0x33, 0x12, 0xDE, 0x98, 0x3B, 0xC0, 0x9B, 0x3E, 0x18, 0x10, 0x3A,
         0x56, 0xE1, 0x77, 0xC9, 0x1E, 0x9E, 0x95, 0xA3, 0x90, 0x19, 0xA8, 0x6C, 0x09, 0xD0, 0xF0, 0x86
         ]

WORD_NUM = 16
WORD_SIZE = 32
LFSR_S = [None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None]
LFSR_P = [None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None]
FSM_R = []
FSM_P = []

LFSR_DESCR = [
    [
        [16, [[1, [0]], [1, [2]], [1, [11]]]]  # Register len =16, feedback poly=alpha*x0 + x2 + alpha^(-1)*x11
    ],
    32  # Registers' cell (word) size = 32-bit
]

PARAMETERS_CONFIGURATION_LIST = [{'iv_bit_size': 128, 'key_bit_size': 128, 'number_of_initialization_clocks': 32,
                                  'keystream_word_size': 2}]


class Snow3GStreamCipher(Cipher):
    """
        Return a cipher object of SNOW3G stream cipher.

            INPUT:

            EXAMPLES::

                sage: from claasp.ciphers.stream_ciphers.snow3g_stream_cipher import Snow3GStreamCipher
                sage: snow = Snow3GStreamCipher(number_of_initialization_clocks=2, keystream_word_size=2)
                sage: iv = 0xEA024714AD5C4D84DF1F9B251C0BF45F
                sage: key = 0x2BD6459F82C5B300952C49104881FF48
                sage: ks_32=0xABEE97047AC31373
                sage: ks2=10407660024169345926
                sage: snow.evaluate([key,iv])==ks2
                True
    """

    def __init__(self, iv_bit_size=128, key_bit_size=128, number_of_initialization_clocks=32, keystream_word_size=2):
        self.keystream_word_size = keystream_word_size
        self.key_bit_size = key_bit_size
        self.iv_bit_size = iv_bit_size
        self.number_of_initialization_clocks = number_of_initialization_clocks

        super().__init__(family_name="snow3g_stream_cipher",
                         cipher_type="stream_cipher",
                         cipher_inputs=[INPUT_KEY, INPUT_INITIALIZATION_VECTOR],
                         cipher_inputs_bit_size=[key_bit_size, iv_bit_size],
                         cipher_output_bit_size=keystream_word_size)

        iv = [INPUT_INITIALIZATION_VECTOR], [list(range(self.iv_bit_size))]
        key = ComponentState([INPUT_KEY], [list(range(self.key_bit_size))])

        const_0 = self.snow3g_state_initialization(key, iv)
        F = self.clock_fsm(const_0)
        self.clock_lfsr(const_0)
        keystream = []
        for clock_number in range(keystream_word_size):
            self.add_round()
            F = self.clock_fsm(const_0)
            keystream = self.snow3g_key_stream(F, keystream, clock_number)
            self.clock_lfsr(const_0)

        self.add_cipher_output_component([keystream], [list(range(keystream_word_size * WORD_SIZE))],
                                         keystream_word_size * WORD_SIZE)

    def snow3g_state_initialization(self, key, iv):

        self.add_round()
        self.add_constant_component(WORD_SIZE, 0)
        const_0 = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        self.initial_filling_lfsr_fsm(key, iv, const_0)
        for i in range(self.number_of_initialization_clocks):
            F = self.clock_fsm(const_0)
            self.clock_lfsr_initialization_mode(F, const_0)
            self.add_round()

        return const_0

    def initial_filling_lfsr_fsm(self, key, iv, const_0):
        self.add_constant_component(WORD_SIZE, 0xffffffff)
        const_1 = [ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))]).id[0]]
        # lfsr cells-1th to 4th:  k_0+1, k_1+1, k_2+1, k_3+1
        for i in range(4):
            self.add_XOR_component([key.id[0]] + const_1, [list(range(i * WORD_SIZE, (i + 1) * WORD_SIZE)),
                                                           list(range(WORD_SIZE))], WORD_SIZE)
            LFSR_S[i] = [ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))]).id[0]]
            LFSR_P[i] = [list(range(WORD_SIZE))]
        # lfsr cells-5th to 8th:  k_0, k_1, k_2, k_3
        for i in range(4):
            LFSR_S[i + 4] = [key.id[0]]
            LFSR_P[i + 4] = [list(range(i * WORD_SIZE, (i + 1) * WORD_SIZE))]

        # lfsr[8]: k0+1
        self.add_XOR_component([key.id[0]] + const_1, [list(range(WORD_SIZE)), list(range(WORD_SIZE))], WORD_SIZE)
        LFSR_S[8] = [ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))]).id[0]]
        LFSR_P[8] = [list(range(WORD_SIZE))]

        # lfsr[9]: k1+1+iv3
        self.add_XOR_component([key.id[0]] + const_1 + [iv[0][0]], [list(range(WORD_SIZE, 2 * WORD_SIZE)),
                                                                    list(range(WORD_SIZE)),
                                                                    list(range(3 * WORD_SIZE, 4 * WORD_SIZE))],
                               WORD_SIZE)
        LFSR_S[9] = [ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))]).id[0]]
        LFSR_P[9] = [list(range(WORD_SIZE))]

        # lfsr[10] :k2+1+iv2
        self.add_XOR_component([key.id[0]] + const_1 + [iv[0][0]], [list(range(2 * WORD_SIZE, 3 * WORD_SIZE)),
                                                                    list(range(WORD_SIZE)),
                                                                    list(range(2 * WORD_SIZE, 3 * WORD_SIZE))],
                               WORD_SIZE)
        LFSR_S[10] = [ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))]).id[0]]
        LFSR_P[10] = [list(range(WORD_SIZE))]

        # lfsr[11]: k3+1
        self.add_XOR_component([key.id[0]] + const_1, [list(range(3 * WORD_SIZE, 4 * WORD_SIZE)),
                                                       list(range(WORD_SIZE))], WORD_SIZE)
        LFSR_S[11] = [ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))]).id[0]]
        LFSR_P[11] = [list(range(WORD_SIZE))]

        # lfsr[12] : k0+iv1
        self.add_XOR_component([key.id[0], iv[0][0]], [list(range(WORD_SIZE)),
                                                       list(range(WORD_SIZE, 2 * WORD_SIZE))], WORD_SIZE)
        LFSR_S[12] = [ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))]).id[0]]
        LFSR_P[12] = [list(range(WORD_SIZE))]

        # lfsr[13, 14]: k1+0, k2+0
        for i in range(2):
            LFSR_S[12 + i + 1] = [key.id[0]]
            LFSR_P[12 + i + 1] = [list(range((i + 1) * WORD_SIZE, (i + 2) * WORD_SIZE))]

        # s15=k3+iv0
        self.add_XOR_component([key.id[0], iv[0][0]], [list(range(3 * WORD_SIZE, 4 * WORD_SIZE)),
                                                       list(range(WORD_SIZE))], WORD_SIZE)
        LFSR_S[15] = [ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))]).id[0]]
        LFSR_P[15] = [list(range(WORD_SIZE))]

        for i in range(3):
            FSM_R.append([const_0.id[0]])
            FSM_P.append([list(range(WORD_SIZE))])
        FSM_R[1] = FSM_R[1] + FSM_R[1] + FSM_R[1] + FSM_R[1]
        FSM_P[1] = [list(range(8))] * 4

    def clock_fsm(self, const_0):

        self.add_MODADD_component(LFSR_S[15] + FSM_R[0], LFSR_P[15] + FSM_P[0], WORD_SIZE)
        F = [ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))]).id[0]]

        self.add_XOR_component(F + FSM_R[1], [list(range(WORD_SIZE))] + FSM_P[1], WORD_SIZE)
        F = [ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))]).id[0]]

        self.add_XOR_component(FSM_R[2] + LFSR_S[5], FSM_P[2] + LFSR_P[5], WORD_SIZE)
        r = [ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))]).id[0]]

        self.add_MODADD_component(r + FSM_R[1], [list(range(WORD_SIZE))] + FSM_P[1], WORD_SIZE)
        r = [ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))]).id[0]]

        FSM_R[2], FSM_P[2] = self.S2(FSM_R[1], FSM_P[1], const_0)
        FSM_R[1], FSM_P[1] = self.S1(FSM_R[0], FSM_P[0], const_0)
        FSM_R[0] = r
        FSM_P[0] = [list(range(WORD_SIZE))]

        return F

    def S1(self, w_id, w_pos, const_0):
        sba = []
        for i in range(4):
            self.add_SBOX_component(w_id, [w_pos[0][i * 8:i * 8 + 8]], 8, SBoxA)
            sba.append([ComponentState([self.get_current_component_id()], [list(range(8))]).id[0]])

        id_0 = sba[0] + [const_0.id[0]] + sba[0] + sba[0] + [const_0.id[0]] + sba[0] + sba[0]
        id_1 = sba[1] + [const_0.id[0]] + sba[1] + sba[1] + [const_0.id[0]] + sba[1] + sba[1]
        id_2 = sba[2] + [const_0.id[0]] + sba[2] + sba[2] + [const_0.id[0]] + sba[2] + sba[2]
        id_3 = sba[3] + [const_0.id[0]] + sba[3] + sba[3] + [const_0.id[0]] + sba[3] + sba[3]
        pos_0 = [list(range(1, 8))] + [[0, 1, 2, 3]] + [[0]] + [[0]] + [[0]] + [[0]] + [[0]]

        ids = id_0 + sba[1] + sba[2] + id_3 + sba[3]
        pos = pos_0 + [list(range(8))] + [list(range(8))] + pos_0 + [list(range(8))]
        self.add_XOR_component(ids, pos, 8)
        r0 = [ComponentState([self.get_current_component_id()], [list(range(8))]).id[0]]

        ids = id_0 + sba[0] + id_1 + sba[2] + sba[3]
        pos = pos_0 + [list(range(8))] + pos_0 + [list(range(8))] + [list(range(8))]

        self.add_XOR_component(ids, pos, 8)
        r1 = [ComponentState([self.get_current_component_id()], [list(range(8))]).id[0]]

        ids = sba[0] + id_1 + sba[1] + id_2 + sba[3]
        pos = [list(range(8))] + pos_0 + [list(range(8))] + pos_0 + [list(range(8))]
        self.add_XOR_component(ids, pos, 8)
        r2 = [ComponentState([self.get_current_component_id()], [list(range(8))]).id[0]]

        ids = sba[0] + sba[1] + id_2 + sba[2] + id_3
        pos = [list(range(8))] + [list(range(8))] + pos_0 + [list(range(8))] + pos_0
        self.add_XOR_component(ids, pos, 8)
        r3 = [ComponentState([self.get_current_component_id()], [list(range(8))]).id[0]]

        S1_id = r0 + r1 + r2 + r3
        S1_pos = [list(range(8))] * 4
        return S1_id, S1_pos

    def S2(self, w_id, w_pos, const_0):
        sbq = []
        for i in range(4):
            self.add_SBOX_component([w_id[i]], [w_pos[i]], 8, SBoxQ)
            sbq.append([ComponentState([self.get_current_component_id()], [list(range(8))]).id[0]])

        id_0 = sbq[0] + [const_0.id[0]] + sbq[0] + sbq[0] + [const_0.id[0]] + sbq[0] + [const_0.id[0]] + sbq[0]
        id_1 = sbq[1] + [const_0.id[0]] + sbq[1] + sbq[1] + [const_0.id[0]] + sbq[1] + [const_0.id[0]] + sbq[1]
        id_2 = sbq[2] + [const_0.id[0]] + sbq[2] + sbq[2] + [const_0.id[0]] + sbq[2] + [const_0.id[0]] + sbq[2]
        id_3 = sbq[3] + [const_0.id[0]] + sbq[3] + sbq[3] + [const_0.id[0]] + sbq[3] + [const_0.id[0]] + sbq[3]
        pos_0 = [list(range(1, 8))] + [[0, 1]] + [[0]] + [[0]] + [[0]] + [[0]] + [[0, 1]] + [[0]]

        ids = id_0 + sbq[1] + sbq[2] + id_3 + sbq[3]
        pos = pos_0 + [list(range(8))] + [list(range(8))] + pos_0 + [list(range(8))]
        self.add_XOR_component(ids, pos, 8)
        r0 = [ComponentState([self.get_current_component_id()], [list(range(8))]).id[0]]

        ids = id_0 + sbq[0] + id_1 + sbq[2] + sbq[3]
        pos = pos_0 + [list(range(8))] + pos_0 + [list(range(8))] + [list(range(8))]

        self.add_XOR_component(ids, pos, 8)
        r1 = [ComponentState([self.get_current_component_id()], [list(range(8))]).id[0]]

        ids = sbq[0] + id_1 + sbq[1] + id_2 + sbq[3]
        pos = [list(range(8))] + pos_0 + [list(range(8))] + pos_0 + [list(range(8))]
        self.add_XOR_component(ids, pos, 8)
        r2 = [ComponentState([self.get_current_component_id()], [list(range(8))]).id[0]]

        ids = sbq[0] + sbq[1] + id_2 + sbq[2] + id_3
        pos = [list(range(8))] + [list(range(8))] + pos_0 + [list(range(8))] + pos_0
        self.add_XOR_component(ids, pos, 8)
        r3 = [ComponentState([self.get_current_component_id()], [list(range(8))]).id[0]]

        S2_id = r0 + r1 + r2 + r3
        S2_pos = [list(range(8))] * 4
        return S2_id, S2_pos

    def clock_lfsr_initialization_mode(self, F, const_0):
        self.clock_lfsr(const_0)
        self.add_XOR_component(LFSR_S[15] + F, LFSR_P[15] + [list(range(WORD_SIZE))], WORD_SIZE)
        LFSR_S[15] = [ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))]).id[0]]
        LFSR_P[15] = [list(range(WORD_SIZE))]

    def clock_lfsr(self, const_0):
        S0a, S11a = self.create_alpha_state(const_0)
        fsr_ids = S0a
        fsr_pos = [list(range(WORD_SIZE))]
        for i in range(1, 11):
            fsr_ids = fsr_ids + LFSR_S[i]
            fsr_pos = fsr_pos + LFSR_P[i]
        fsr_ids = fsr_ids + S11a
        fsr_pos = fsr_pos + [list(range(WORD_SIZE))]
        for i in range(12, WORD_NUM):
            fsr_ids = fsr_ids + LFSR_S[i]
            fsr_pos = fsr_pos + LFSR_P[i]

        self.add_FSR_component(fsr_ids, fsr_pos, WORD_SIZE * WORD_NUM, LFSR_DESCR)
        S15 = [ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE * WORD_NUM))]).id[0]]
        for i in range(WORD_NUM - 1):
            LFSR_S[i] = LFSR_S[i + 1]
            LFSR_P[i] = LFSR_P[i + 1]
        LFSR_S[WORD_NUM - 1] = S15
        LFSR_P[WORD_NUM - 1] = [list(range((WORD_NUM - 1) * WORD_SIZE, WORD_NUM * WORD_SIZE))]

    def create_alpha_state(self, const_0):
        S0 = LFSR_S[0]
        S0a_id, S0a_pos = self.MULalpha(S0, const_0)
        s0_id = S0 + [const_0.id[0]] + S0a_id
        s0_pos = [LFSR_P[0][0][8:WORD_SIZE], list(range(8))] + S0a_pos
        self.add_XOR_component(s0_id, s0_pos, WORD_SIZE)
        S0a = [ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))]).id[0]]

        S11a_id, S11a_pos = self.DIValpha(LFSR_S[11], const_0)
        s11_id = [const_0.id[0]] + LFSR_S[11] + S11a_id
        s11_pos = [list(range(8)), LFSR_P[11][0][0:24]] + S11a_pos
        self.add_XOR_component(s11_id, s11_pos, WORD_SIZE)
        S11a = [ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))]).id[0]]

        return S0a, S11a

    def MULalpha(self, S0, const_0):
        P = LFSR_P[0][0][:8]
        mulxpow1 = self.MULxPOW(S0, 23, const_0, P)
        mulxpow2 = self.MULxPOW(S0, 245, const_0, P)
        mulxpow3 = self.MULxPOW(S0, 48, const_0, P)
        mulxpow4 = self.MULxPOW(S0, 239, const_0, P)

        S0a_id = mulxpow1 + mulxpow2 + mulxpow3 + mulxpow4
        S0a_pos = [list(range(8))] * 4

        return S0a_id, S0a_pos

    def DIValpha(self, S11, const_0):
        P = LFSR_P[11][0][8 * 3:8 * 4]
        mulxpow1 = self.MULxPOW(S11, 16, const_0, P)
        mulxpow2 = self.MULxPOW(S11, 39, const_0, P)
        mulxpow3 = self.MULxPOW(S11, 6, const_0, P)
        mulxpow4 = self.MULxPOW(S11, 64, const_0, P)

        S11a_id = mulxpow1 + mulxpow2 + mulxpow3 + mulxpow4
        S11a_pos = [list(range(8))] * 4

        return S11a_id, S11a_pos

    def MULxPOW(self, V, i, const_0, P):
        if i >= 1:
            V = self.MULx(V, const_0, P)
            P = list(range(8))
            for _ in range(i - 1):
                V = self.MULx(V, const_0, P)
        return V

    def MULx(self, V, const_0, P):
        m_id1 = V + [const_0.id[0]]
        m_pos1 = [P[1:8]] + [[0]]
        m_id2 = V + [const_0.id[0]] + V + [const_0.id[0]] + V + [const_0.id[0]] + V
        m_pos2 = [[P[0]]] + [[0]] + [[P[0]]] + [[0]] + [[P[0]]] + [[0, 1]] + [[P[0]]]

        self.add_XOR_component(m_id1 + m_id2, m_pos1 + m_pos2, 8)
        V = [ComponentState([self.get_current_component_id()], [list(range(8))]).id[0]]
        return V

    def snow3g_key_stream(self, F, keystream, clock_number):
        key_word = self.add_XOR_component(F + LFSR_S[0], [list(range(WORD_SIZE))] + LFSR_P[0], WORD_SIZE).id
        if clock_number == 0:
            keystream = self.add_round_output_component([key_word], [list(range(WORD_SIZE))], WORD_SIZE).id
        else:
            keystream = self.add_round_output_component([keystream, key_word], [list(range(clock_number * WORD_SIZE)),
                                                                                list(range(WORD_SIZE))],
                                                        (clock_number + 1) * WORD_SIZE).id
        return keystream
