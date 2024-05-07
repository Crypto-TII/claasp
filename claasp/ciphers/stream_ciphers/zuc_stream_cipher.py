from claasp.cipher import Cipher
from claasp.DTOs.component_state import ComponentState
from claasp.name_mappings import INPUT_KEY, INPUT_INITIALIZATION_VECTOR

Sbox1 = [
    0x3e, 0x72, 0x5b, 0x47, 0xca, 0xe0, 0x00, 0x33, 0x04, 0xd1, 0x54, 0x98, 0x09, 0xb9, 0x6d, 0xcb,
    0x7b, 0x1b, 0xf9, 0x32, 0xaf, 0x9d, 0x6a, 0xa5, 0xb8, 0x2d, 0xfc, 0x1d, 0x08, 0x53, 0x03, 0x90,
    0x4d, 0x4e, 0x84, 0x99, 0xe4, 0xce, 0xd9, 0x91, 0xdd, 0xb6, 0x85, 0x48, 0x8b, 0x29, 0x6e, 0xac,
    0xcd, 0xc1, 0xf8, 0x1e, 0x73, 0x43, 0x69, 0xc6, 0xb5, 0xbd, 0xfd, 0x39, 0x63, 0x20, 0xd4, 0x38,
    0x76, 0x7d, 0xb2, 0xa7, 0xcf, 0xed, 0x57, 0xc5, 0xf3, 0x2c, 0xbb, 0x14, 0x21, 0x06, 0x55, 0x9b,
    0xe3, 0xef, 0x5e, 0x31, 0x4f, 0x7f, 0x5a, 0xa4, 0x0d, 0x82, 0x51, 0x49, 0x5f, 0xba, 0x58, 0x1c,
    0x4a, 0x16, 0xd5, 0x17, 0xa8, 0x92, 0x24, 0x1f, 0x8c, 0xff, 0xd8, 0xae, 0x2e, 0x01, 0xd3, 0xad,
    0x3b, 0x4b, 0xda, 0x46, 0xeb, 0xc9, 0xde, 0x9a, 0x8f, 0x87, 0xd7, 0x3a, 0x80, 0x6f, 0x2f, 0xc8,
    0xb1, 0xb4, 0x37, 0xf7, 0x0a, 0x22, 0x13, 0x28, 0x7c, 0xcc, 0x3c, 0x89, 0xc7, 0xc3, 0x96, 0x56,
    0x07, 0xbf, 0x7e, 0xf0, 0x0b, 0x2b, 0x97, 0x52, 0x35, 0x41, 0x79, 0x61, 0xa6, 0x4c, 0x10, 0xfe,
    0xbc, 0x26, 0x95, 0x88, 0x8a, 0xb0, 0xa3, 0xfb, 0xc0, 0x18, 0x94, 0xf2, 0xe1, 0xe5, 0xe9, 0x5d,
    0xd0, 0xdc, 0x11, 0x66, 0x64, 0x5c, 0xec, 0x59, 0x42, 0x75, 0x12, 0xf5, 0x74, 0x9c, 0xaa, 0x23,
    0x0e, 0x86, 0xab, 0xbe, 0x2a, 0x02, 0xe7, 0x67, 0xe6, 0x44, 0xa2, 0x6c, 0xc2, 0x93, 0x9f, 0xf1,
    0xf6, 0xfa, 0x36, 0xd2, 0x50, 0x68, 0x9e, 0x62, 0x71, 0x15, 0x3d, 0xd6, 0x40, 0xc4, 0xe2, 0x0f,
    0x8e, 0x83, 0x77, 0x6b, 0x25, 0x05, 0x3f, 0x0c, 0x30, 0xea, 0x70, 0xb7, 0xa1, 0xe8, 0xa9, 0x65,
    0x8d, 0x27, 0x1a, 0xdb, 0x81, 0xb3, 0xa0, 0xf4, 0x45, 0x7a, 0x19, 0xdf, 0xee, 0x78, 0x34, 0x60
]

Sbox2 = [
    0x55, 0xc2, 0x63, 0x71, 0x3b, 0xc8, 0x47, 0x86, 0x9f, 0x3c, 0xda, 0x5b, 0x29, 0xaa, 0xfd, 0x77,
    0x8c, 0xc5, 0x94, 0x0c, 0xa6, 0x1a, 0x13, 0x00, 0xe3, 0xa8, 0x16, 0x72, 0x40, 0xf9, 0xf8, 0x42,
    0x44, 0x26, 0x68, 0x96, 0x81, 0xd9, 0x45, 0x3e, 0x10, 0x76, 0xc6, 0xa7, 0x8b, 0x39, 0x43, 0xe1,
    0x3a, 0xb5, 0x56, 0x2a, 0xc0, 0x6d, 0xb3, 0x05, 0x22, 0x66, 0xbf, 0xdc, 0x0b, 0xfa, 0x62, 0x48,
    0xdd, 0x20, 0x11, 0x06, 0x36, 0xc9, 0xc1, 0xcf, 0xf6, 0x27, 0x52, 0xbb, 0x69, 0xf5, 0xd4, 0x87,
    0x7f, 0x84, 0x4c, 0xd2, 0x9c, 0x57, 0xa4, 0xbc, 0x4f, 0x9a, 0xdf, 0xfe, 0xd6, 0x8d, 0x7a, 0xeb,
    0x2b, 0x53, 0xd8, 0x5c, 0xa1, 0x14, 0x17, 0xfb, 0x23, 0xd5, 0x7d, 0x30, 0x67, 0x73, 0x08, 0x09,
    0xee, 0xb7, 0x70, 0x3f, 0x61, 0xb2, 0x19, 0x8e, 0x4e, 0xe5, 0x4b, 0x93, 0x8f, 0x5d, 0xdb, 0xa9,
    0xad, 0xf1, 0xae, 0x2e, 0xcb, 0x0d, 0xfc, 0xf4, 0x2d, 0x46, 0x6e, 0x1d, 0x97, 0xe8, 0xd1, 0xe9,
    0x4d, 0x37, 0xa5, 0x75, 0x5e, 0x83, 0x9e, 0xab, 0x82, 0x9d, 0xb9, 0x1c, 0xe0, 0xcd, 0x49, 0x89,
    0x01, 0xb6, 0xbd, 0x58, 0x24, 0xa2, 0x5f, 0x38, 0x78, 0x99, 0x15, 0x90, 0x50, 0xb8, 0x95, 0xe4,
    0xd0, 0x91, 0xc7, 0xce, 0xed, 0x0f, 0xb4, 0x6f, 0xa0, 0xcc, 0xf0, 0x02, 0x4a, 0x79, 0xc3, 0xde,
    0xa3, 0xef, 0xea, 0x51, 0xe6, 0x6b, 0x18, 0xec, 0x1b, 0x2c, 0x80, 0xf7, 0x74, 0xe7, 0xff, 0x21,
    0x5a, 0x6a, 0x54, 0x1e, 0x41, 0x31, 0x92, 0x35, 0xc4, 0x33, 0x07, 0x0a, 0xba, 0x7e, 0x0e, 0x34,
    0x88, 0xb1, 0x98, 0x7c, 0xf3, 0x3d, 0x60, 0x6c, 0x7b, 0xca, 0xd3, 0x1f, 0x32, 0x65, 0x04, 0x28,
    0x64, 0xbe, 0x85, 0x9b, 0x2f, 0x59, 0x8a, 0xd7, 0xb0, 0x25, 0xac, 0xaf, 0x12, 0x03, 0xe2, 0xf2
]
EK_d = [
    0b100010011010111, 0b010011010111100, 0b110001001101011, 0b001001101011110,
    0b101011110001001, 0b011010111100010, 0b111000100110101, 0b000100110101111,
    0b100110101111000, 0b010111100010011, 0b110101111000100, 0b001101011110001,
    0b101111000100110, 0b011110001001101, 0b111100010011010, 0b100011110101100
]
LFSR_S = [None, None, None, None, None, None,None, None,None, None, None, None, None, None,None, None]
LFSR_P = [None, None, None, None, None, None,None, None,None, None, None, None, None, None,None, None]
FSM_R = [None, None]
FSM_P = [None, None]

WORD_SIZE = 32
LFSR_W_SIZE = 31

PARAMETERS_CONFIGURATION_LIST = [{'iv_bit_size': 128, 'key_bit_size': 128, 'number_of_initialization_clocks': 32,
                                  'len_keystream_word': 1}]


class ZucStreamCipher(Cipher):
    """
           Return a cipher object of ZUC stream cipher.

           INPUT:

           EXAMPLES::

                sage: from claasp.ciphers.stream_ciphers.zuc_stream_cipher import ZucStreamCipher
                sage: zuc=ZucStreamCipher(len_keystream_word=2)
                sage: iv = 0xffffffffffffffffffffffffffffffff
                sage: key= 0xffffffffffffffffffffffffffffffff
                sage: ks = 0x657cfa07096398b
                sage: zuc.evaluate([key,iv], verbosity=False) == ks
                True
    """

    def __init__(self, iv_bit_size=128, key_bit_size=128, number_of_initialization_clocks=32, len_keystream_word=2):
        self.len_keystream_word = len_keystream_word
        self.key_bit_size = key_bit_size
        self.iv_bit_size = iv_bit_size
        self.number_of_initialization_clocks = number_of_initialization_clocks

        super().__init__(family_name="zuc_stream_cipher",
                         cipher_type="stream_cipher",
                         cipher_inputs=[INPUT_KEY, INPUT_INITIALIZATION_VECTOR],
                         cipher_inputs_bit_size=[key_bit_size, iv_bit_size],
                         cipher_output_bit_size=len_keystream_word)

        iv = ComponentState([INPUT_INITIALIZATION_VECTOR], [list(range(self.iv_bit_size))])
        key = ComponentState([INPUT_KEY], [list(range(self.key_bit_size))])

        self.state_initialization(key, iv)
        self.zuc_nonlinear_F()
        self.clocking_lfsr()
        key_st = []
        for clock_number in range(len_keystream_word):
            self.add_round()
            w = self.zuc_nonlinear_F()
            key_st = self.key_stream(w, clock_number, key_st)
            self.clocking_lfsr()

        self.add_cipher_output_component([key_st], [list(range(len_keystream_word * WORD_SIZE))],
                                         len_keystream_word * WORD_SIZE)

    def state_initialization(self, key, iv):
        self.add_round()
        self.key_loading_to_lfsr(key, iv)
        for i in range(2):
            self.add_constant_component(WORD_SIZE, 0)
            FSM_R[i] = [ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))]).id[0]]
            FSM_P[i] = [list(range(WORD_SIZE))]

        nCount = self.number_of_initialization_clocks
        while nCount > 0:
            w = self.zuc_nonlinear_F()
            self.lfsr_with_initialization_mode(w)
            nCount = nCount - 1

    def key_loading_to_lfsr(self, key, iv):
        D = []
        for i in range(16):
            D.append(self.add_constant_component(15, EK_d[i]))
            LFSR_S[i] = [key.id[0], D[i].id, iv.id[0]]
            LFSR_P[i] = [list(range(i * 8, (i + 1) * 8)), list(range(15)), list(range(i * 8, (i + 1) * 8))]

    def lfsr_with_initialization_mode(self, W):
        self.clocking_lfsr()
        self.add_SHIFT_component([W.id[0]], [list(range(WORD_SIZE))], WORD_SIZE, 1)
        W = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        self.add_MODADD_component(LFSR_S[15] + [W.id[0]], LFSR_P[15] + [list(range(1, WORD_SIZE))], LFSR_W_SIZE,
                                  (2 ** LFSR_W_SIZE) - 1)
        LFSR_S[15] = [ComponentState([self.get_current_component_id()], [list(range(LFSR_W_SIZE))]).id[0]]
        LFSR_P[15] = [list(range(LFSR_W_SIZE))]

    def clocking_lfsr(self):
        self.add_rotate_component(LFSR_S[15], LFSR_P[15], LFSR_W_SIZE, -15)
        pr1 = ComponentState([self.get_current_component_id()], [list(range(LFSR_W_SIZE))])

        self.add_rotate_component(LFSR_S[13], LFSR_P[13], LFSR_W_SIZE, -17)
        pr2 = ComponentState([self.get_current_component_id()], [list(range(LFSR_W_SIZE))])

        self.add_rotate_component(LFSR_S[10], LFSR_P[10], LFSR_W_SIZE, -21)
        pr3 = ComponentState([self.get_current_component_id()], [list(range(LFSR_W_SIZE))])
        self.add_rotate_component(LFSR_S[4], LFSR_P[4], LFSR_W_SIZE, -20)
        pr4 = ComponentState([self.get_current_component_id()], [list(range(LFSR_W_SIZE))])

        self.add_rotate_component(LFSR_S[0], LFSR_P[0], LFSR_W_SIZE, -8)
        pr5 = ComponentState([self.get_current_component_id()], [list(range(LFSR_W_SIZE))])

        ids = [pr1.id[0], pr2.id[0], pr3.id[0], pr4.id[0], pr5.id[0]] + LFSR_S[0]
        self.add_MODADD_component(ids, [list(range(LFSR_W_SIZE))] * 5 + LFSR_P[0], LFSR_W_SIZE, (2 ** LFSR_W_SIZE) - 1)
        s16 = ComponentState([self.get_current_component_id()], [list(range(LFSR_W_SIZE))])

        for i in range(15):
            LFSR_S[i] = LFSR_S[i + 1]
            LFSR_P[i] = LFSR_P[i + 1]
        LFSR_S[15] = [s16.id[0]]
        LFSR_P[15] = [list(range(LFSR_W_SIZE))]

    def zuc_nonlinear_F(self):
        s15h_id, s15h_ps = self.lfsr_S_high_16bits(LFSR_S[15], LFSR_P[15])
        s14l_id, s14l_ps = self.lfsr_S_low_16bits(LFSR_S[14], LFSR_P[14])

        self.add_XOR_component(s15h_id + s14l_id + FSM_R[0], s15h_ps + s14l_ps + FSM_P[0], WORD_SIZE)

        W = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        self.add_MODADD_component([W.id[0]] + FSM_R[1], [list(range(WORD_SIZE))] + FSM_P[1], WORD_SIZE)
        W = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        s11l_id, s11l_ps = self.lfsr_S_low_16bits(LFSR_S[11], LFSR_P[11])
        s9h_id, s9h_ps = self.lfsr_S_high_16bits(LFSR_S[9], LFSR_P[9])
        self.add_MODADD_component(FSM_R[0] + s11l_id + s9h_id, FSM_P[0] + s11l_ps + s9h_ps, WORD_SIZE)
        W1 = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        s7l_id, s7l_ps = self.lfsr_S_low_16bits(LFSR_S[7], LFSR_P[7])
        s5h_id, s5h_ps = self.lfsr_S_high_16bits(LFSR_S[5], LFSR_P[5])
        self.add_XOR_component(FSM_R[1] + s7l_id + s5h_id, FSM_P[1] + s7l_ps + s5h_ps, WORD_SIZE)
        W2 = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        l1 = self.linear_transform_L1(W1, W2)
        FSM_R[0], FSM_P[0] = self.s_box_layer(l1)
        l2 = self.linear_transform_L2(W2, W1)
        FSM_R[1], FSM_P[1] = self.s_box_layer(l2)

        return W

    def s_box_layer(self, lo):
        s_box_1 = self.add_SBOX_component([lo.id[0]], [list(range(8))], 8, Sbox1).id
        s_box_2 = self.add_SBOX_component([lo.id[0]], [list(range(8, 16))], 8, Sbox2).id
        s_box_3 = self.add_SBOX_component([lo.id[0]], [list(range(16, 24))], 8, Sbox1).id
        s_box_4 = self.add_SBOX_component([lo.id[0]], [list(range(24, 32))], 8, Sbox2).id
        s_box_id = [s_box_1, s_box_2, s_box_3, s_box_4]
        return s_box_id, [list(range(8))] * 4

    def linear_transform_L1(self, W1, W2):
        rot1 = self.linear_layer_rotation(W1, W2, -2)
        rot2 = self.linear_layer_rotation(W1, W2, -10)
        rot3 = self.linear_layer_rotation(W1, W2, -18)
        rot4 = self.linear_layer_rotation(W1, W2, -24)
        ids = [W1.id[0], W2.id[0], rot1.id[0], rot2.id[0], rot3.id[0], rot4.id[0]]
        pos = [list(range(16, WORD_SIZE)), list(range(0, 16))] + [list(range(WORD_SIZE))] * 4
        self.add_XOR_component(ids, pos, WORD_SIZE)
        l1 = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        return l1

    def linear_transform_L2(self, W1, W2):
        rot1 = self.linear_layer_rotation(W1, W2, -8)
        rot2 = self.linear_layer_rotation(W1, W2, -14)
        rot3 = self.linear_layer_rotation(W1, W2, -22)
        rot4 = self.linear_layer_rotation(W1, W2, -30)
        ids = [W1.id[0], W2.id[0], rot1.id[0], rot2.id[0], rot3.id[0], rot4.id[0]]
        pos = [list(range(16, WORD_SIZE)), list(range(0, 16))] + [list(range(WORD_SIZE))] * 4
        self.add_XOR_component(ids, pos, WORD_SIZE)
        l2 = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        return l2

    def key_stream(self, w, clock_number, key_st):
        s2l_id, s2l_ps = self.lfsr_S_low_16bits(LFSR_S[2], LFSR_P[2])
        s0h_id, s0h_ps = self.lfsr_S_high_16bits(LFSR_S[0], LFSR_P[0])
        key_word = self.add_XOR_component([w.id[0]] + s2l_id + s0h_id, [list(range(WORD_SIZE))] + s2l_ps + s0h_ps,
                                          WORD_SIZE).id
        if clock_number == 0:
            key_st = self.add_round_output_component([key_word], [list(range(WORD_SIZE))], WORD_SIZE).id
        else:
            key_st = self.add_round_output_component([key_st, key_word], [list(range(clock_number * WORD_SIZE)),
                                                                          list(range(WORD_SIZE))],
                                                     (clock_number + 1) * WORD_SIZE).id
        return key_st

    def lfsr_S_high_16bits(self, S, P):
        if len(S) == 3:
            s_h_id = S[:2]
            s_h_ps = [P[0], P[1][:8]]
        else:
            s_h_id = S
            s_h_ps = [P[0][:16]]
        return s_h_id, s_h_ps

    def lfsr_S_low_16bits(self, S, P):
        if len(S) == 3:
            s_l_id = S[1:3]
            s_l_ps = [P[1][7:15], P[2]]
        else:
            s_l_id = S
            s_l_ps = [P[0][15:LFSR_W_SIZE]]

        return s_l_id, s_l_ps

    def linear_layer_rotation(self, W1, W2, rot):
        self.add_rotate_component([W1.id[0], W2.id[0]], [list(range(16, WORD_SIZE)), list(range(0, 16))],
                                  WORD_SIZE, rot)
        rot_component = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        return rot_component
