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
from claasp.name_mappings import BLOCK_CIPHER, INPUT_KEY, INPUT_PLAINTEXT
from claasp.utils.utils import get_number_of_rounds_from


class MSXBlockCipher(Cipher):
    """
    Return a cipher object of the MSX block cipher family.

    The MSX family includes MSX-64 and MSX-128 configurations. This implementation
    models the cipher using CLAASP components (modular addition, modular
    multiplication, XOR, and rotations).

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `64`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `128`); cipher key bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `0`); number of rounds of the cipher. If 0, the official standard
      is automatically selected (14 for MSX-64, 18 for MSX-128)

    References:
    - Reference code: https://github.com/mrahman454/Block-Cipher-MSX/
    - Paper: https://cic.iacr.org/p/2/4/32

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.msx_block_cipher import MSXBlockCipher
        sage: msx64 = MSXBlockCipher(block_bit_size=64, key_bit_size=128)
        sage: msx64.n_rounds
        14

        sage: msx128 = MSXBlockCipher(block_bit_size=128, key_bit_size=256)
        sage: msx128.key_bit_size
        256
    """


    PARAMETERS_CONFIGURATION_LIST = [
        {"block_bit_size": 64, "key_bit_size": 128, "number_of_rounds": 14},
        {"block_bit_size": 128, "key_bit_size": 128, "number_of_rounds": 18},
        {"block_bit_size": 128, "key_bit_size": 256, "number_of_rounds": 18},
    ]

    def __init__(self, block_bit_size=64, key_bit_size=128, number_of_rounds=0):
        self.word_size = 32
        self.block_bit_size = block_bit_size
        self.key_bit_size = key_bit_size
        self.mod32 = 2 ** self.word_size
        self.CON = 0xA1CD0000

        n = get_number_of_rounds_from(
            block_bit_size, key_bit_size, number_of_rounds, self.PARAMETERS_CONFIGURATION_LIST
        )
        self.n_rounds = n

        super().__init__(
            family_name="msx",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[block_bit_size, key_bit_size],
            cipher_output_bit_size=block_bit_size,
        )

        if block_bit_size == 64:
            self._build_cipher_64()
        elif block_bit_size == 128:
            self._build_cipher_128()
        else:
            raise AssertionError("Unsupported block size for MSX")

    def _const32(self, value: int) -> ComponentState:
        self.add_constant_component(self.word_size, value & 0xFFFFFFFF)
        return ComponentState([self.get_current_component_id()], [list(range(self.word_size))])

    def _zero_bits(self, bit_size: int) -> ComponentState:
        self.add_constant_component(bit_size, 0)
        return ComponentState([self.get_current_component_id()], [list(range(bit_size))])

    def _load_le_word(self, start):
        b3 = list(range(start + 24, start + 32))
        b2 = list(range(start + 16, start + 24))
        b1 = list(range(start + 8, start + 16))
        b0 = list(range(start, start + 8))
        return b3 + b2 + b1 + b0

    def _store_le_word(self, w: ComponentState) -> ComponentState:
        b0 = ComponentState(w.id, [list(range(24, 32))])
        b1 = ComponentState(w.id, [list(range(16, 24))])
        b2 = ComponentState(w.id, [list(range(8, 16))])
        b3 = ComponentState(w.id, [list(range(8))])
        return ComponentState(
            b0.id + b1.id + b2.id + b3.id,
            b0.input_bit_positions + b1.input_bit_positions + b2.input_bit_positions + b3.input_bit_positions,
        )

    def _key_words_from_input(self, num_words):
        words = []
        total_bits = self.key_bit_size
        assert num_words * 32 <= total_bits
        for w in range(num_words):
            start = 32 * w
            k_bits = self._load_le_word(start)
            self.add_intermediate_output_component(
                [INPUT_KEY] * len(k_bits),
                [[b] for b in k_bits],
                self.word_size,
                "key_word",
            )
            words.append(ComponentState([self.get_current_component_id()], [list(range(self.word_size))]))
        return words

    def _key_schedule_initialization_64(self):
        k = self._key_words_from_input(4)

        C = [
            732050807, 568877293, 527446341, 505872366, 942805254, 634010619,
            1296924710, 3826869025, 515107230, 1130980195, 2149511253, 539907735,
        ]
        Cc = [self._const32(v) for v in C]

        self.add_modadd_component(k[1].id + k[0].id, k[1].input_bit_positions + k[0].input_bit_positions, self.word_size, self.mod32)
        t = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
        self.add_modadd_component(t.id + k[3].id, t.input_bit_positions + k[3].input_bit_positions, self.word_size, self.mod32)
        t = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
        self.add_xor_component(t.id + Cc[0].id, t.input_bit_positions + Cc[0].input_bit_positions, self.word_size)
        st0 = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])

        st = [None] * 12
        st[0] = st0
        assign = [
            (1, k[2], 1), (2, k[0], 2), (3, k[3], 3), (4, k[0], 4), (5, k[1], 5), (6, k[3], 6),
            (7, k[0], 7), (8, k[2], 8), (9, k[1], 9), (10, k[2], 10), (11, k[3], 11)
        ]
        for idx, kw, ci in assign:
            self.add_xor_component(kw.id + Cc[ci].id, kw.input_bit_positions + Cc[ci].input_bit_positions, self.word_size)
            st[idx] = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
        return st

    def _update_key_state_64(self, st, step):
        steps = [
            (0, 1, 3, 5, 7, 10),
            (1, 2, 4, 6, 8, 11),
            (2, 3, 5, 7, 9, 0),
            (3, 4, 6, 8, 10, 1),
            (4, 5, 7, 9, 11, 2),
            (5, 6, 8, 10, 0, 3)
        ]
        params = steps[step % 6]
        src = params[0]
        dsts = params[1:]

        tmp = st[src]
        new_st = list(st)
        for rot, dst in zip([1, 2, 3, 4, 5], dsts):
            self.add_rotate_component(new_st[dst].id, new_st[dst].input_bit_positions, self.word_size, -rot)
            r = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
            self.add_modadd_component(r.id + tmp.id, r.input_bit_positions + tmp.input_bit_positions, self.word_size, self.mod32)
            new_st[dst] = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
        return new_st

    def _key_schedule_initialization_128(self):
        C = [
            732050807, 568877293, 527446341, 505872366, 942805254, 634010619,
            1296924710, 3826869025, 515107230, 1130980195, 2149511253, 539907735,
            244569516, 920961429, 2743527186, 2947265473, 645454543, 3960268375,
            2795036687, 563113322, 2690074390, 722202776, 833026909, 2035301852,
        ]
        Cc = [self._const32(v) for v in C]
        st = [None] * 24

        if self.key_bit_size == 128:
            k = self._key_words_from_input(4)
            self.add_modadd_component(k[2].id + k[3].id, k[2].input_bit_positions + k[3].input_bit_positions, self.word_size, self.mod32)
            t = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
            self.add_modadd_component(t.id + k[0].id, t.input_bit_positions + k[0].input_bit_positions, self.word_size, self.mod32)
            t = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
            self.add_xor_component(t.id + Cc[0].id, t.input_bit_positions + Cc[0].input_bit_positions, self.word_size)
            st[0] = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
            assign = [
                (1, k[1], 1), (2, k[0], 2), (3, k[3], 3), (4, k[0], 4), (5, k[2], 5), (6, k[3], 6),
                (7, k[2], 7), (8, k[1], 8), (9, k[0], 9), (10, k[1], 10), (11, k[3], 11),
                (12, k[0], 12), (13, k[3], 13), (14, k[2], 14), (15, k[1], 15), (16, k[2], 16),
                (17, k[0], 17), (18, k[1], 18), (19, k[0], 19), (20, k[3], 20), (21, k[2], 21),
                (22, k[3], 22), (23, k[1], 23),
            ]
            for idx, kw, ci in assign:
                self.add_xor_component(kw.id + Cc[ci].id, kw.input_bit_positions + Cc[ci].input_bit_positions, self.word_size)
                st[idx] = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
        elif self.key_bit_size == 256:
            k = self._key_words_from_input(8)
            self.add_modadd_component(k[2].id + k[1].id, k[2].input_bit_positions + k[1].input_bit_positions, self.word_size, self.mod32)
            t = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
            self.add_modadd_component(t.id + k[5].id, t.input_bit_positions + k[5].input_bit_positions, self.word_size, self.mod32)
            t = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
            self.add_modadd_component(t.id + k[4].id, t.input_bit_positions + k[4].input_bit_positions, self.word_size, self.mod32)
            t = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
            self.add_xor_component(t.id + Cc[0].id, t.input_bit_positions + Cc[0].input_bit_positions, self.word_size)
            st[0] = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
            self.add_modadd_component(k[3].id + k[7].id, k[3].input_bit_positions + k[7].input_bit_positions, self.word_size, self.mod32)
            t = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
            self.add_modadd_component(t.id + k[6].id, t.input_bit_positions + k[6].input_bit_positions, self.word_size, self.mod32)
            t = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
            self.add_modadd_component(t.id + k[0].id, t.input_bit_positions + k[0].input_bit_positions, self.word_size, self.mod32)
            t = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
            self.add_xor_component(t.id + Cc[1].id, t.input_bit_positions + Cc[1].input_bit_positions, self.word_size)
            st[1] = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
            assign = [
                (2, k[0], 2), (3, k[6], 3), (4, k[7], 4), (5, k[4], 5), (6, k[2], 6), (7, k[3], 7),
                (8, k[1], 8), (9, k[6], 9), (10, k[7], 10), (11, k[5], 11), (12, k[0], 12), (13, k[1], 13),
                (14, k[2], 14), (15, k[4], 15), (16, k[5], 16), (17, k[6], 17), (18, k[0], 18), (19, k[1], 19),
                (20, k[3], 20), (21, k[4], 21), (22, k[5], 22), (23, k[7], 23),
            ]
            for idx, kw, ci in assign:
                self.add_xor_component(kw.id + Cc[ci].id, kw.input_bit_positions + Cc[ci].input_bit_positions, self.word_size)
                st[idx] = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
        else:
            raise AssertionError("Unsupported key size for MSX-128")
        return st

    def _update_key_state_128(self, st, step):
        steps = [
            (0, [1, 3, 6, 9, 12, 14, 17, 20, 23]),
            (1, [2, 4, 7, 10, 13, 15, 18, 21, 0]),
            (2, [3, 5, 8, 11, 14, 16, 19, 22, 1]),
            (3, [4, 6, 9, 12, 15, 17, 20, 23, 2]),
            (4, [5, 7, 10, 13, 16, 18, 21, 0, 3]),
            (5, [6, 8, 11, 14, 17, 19, 22, 1, 4]),
            (6, [7, 9, 12, 15, 18, 20, 23, 2, 5]),
            (7, [8, 10, 13, 16, 19, 21, 0, 3, 6])
        ]
        params = steps[step % 8]
        src = params[0]
        dsts = params[1]

        tmp = st[src]
        new_st = list(st)
        for rot, dst in zip(range(1, 10), dsts):
            self.add_rotate_component(new_st[dst].id, new_st[dst].input_bit_positions, self.word_size, -rot)
            r = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
            self.add_modadd_component(r.id + tmp.id, r.input_bit_positions + tmp.input_bit_positions, self.word_size, self.mod32)
            new_st[dst] = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
        return new_st

    def _build_cipher_64(self):
        rk_buffer = []
        key_state = None
        key_update_step = 0
        def next_rk_group():
            nonlocal rk_buffer, key_state, key_update_step
            if len(rk_buffer) < 6:
                key_state = self._update_key_state_64(key_state, key_update_step)
                key_update_step += 1
                rk_buffer.extend(key_state)
            grp = rk_buffer[:6]
            rk_buffer = rk_buffer[6:]
            return grp

        for i in range(self.n_rounds):
            self.add_round()
            if i == 0:
                key_state = self._key_schedule_initialization_64()
                rk_buffer.extend(key_state)
                W0, W1 = self.round_initialization_64()

            c_i = self._const32(self.CON + ((i & 0xFFFF) << 16))
            rk_group = next_rk_group()
            # MSX-64 Feistel applies F to W1 (offset 32) exactly as the original code applied F to L.
            F_out = self.round_function(W1, rk_group, c_i)
            self.add_xor_component(W0.id + F_out.id, W0.input_bit_positions + F_out.input_bit_positions, self.word_size)
            W0_next = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])

            W0_new = W1
            W1_new = W0_next
            W0, W1 = W0_new, W1_new

        if i == self.n_rounds - 1:
            W0_out = self._store_le_word(W0)
            W1_out = self._store_le_word(W1)
            self.add_cipher_output_component(
                W1_out.id + W0_out.id,
                W1_out.input_bit_positions + W0_out.input_bit_positions,
                2 * self.word_size,
            )
        else:
            W0_out = self._store_le_word(W0)
            W1_out = self._store_le_word(W1)
            self.add_round_output_component(
                W1_out.id + W0_out.id,
                W1_out.input_bit_positions + W0_out.input_bit_positions,
                2 * self.word_size,
            )

    def _build_cipher_128(self):
        rk_buffer = []
        key_state = None
        key_update_step = 0
        def next_rk_group():
            nonlocal rk_buffer, key_state, key_update_step
            if len(rk_buffer) < 6:
                key_state = self._update_key_state_128(key_state, key_update_step)
                key_update_step += 1
                rk_buffer.extend(key_state)
            grp = rk_buffer[:6]
            rk_buffer = rk_buffer[6:]
            return grp

        call_counter = 0
        W0 = W1 = W2 = W3 = None
        for i in range(self.n_rounds):
            self.add_round()
            if i == 0:
                key_state = self._key_schedule_initialization_128()
                rk_buffer.extend(key_state)
                W0, W1, W2, W3 = self.round_initialization_128()

            c_i = self._const32(self.CON + ((call_counter & 0xFFFF) << 16))
            call_counter += 1

            rk_group1 = next_rk_group()
            rk_group2 = next_rk_group()

            # F takes W1 XORs into W0, and then F takes W3 XORs into W2
            F1 = self.round_function(W1, rk_group1, c_i)
            self.add_xor_component(W0.id + F1.id, W0.input_bit_positions + F1.input_bit_positions, self.word_size)
            W0_next = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])

            F2 = self.round_function(W3, rk_group2, c_i)
            self.add_xor_component(W2.id + F2.id, W2.input_bit_positions + F2.input_bit_positions, self.word_size)
            W2_next = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])

            W0_new = W3
            W1_new = W0_next
            W2_new = W1
            W3_new = W2_next

            W0, W1, W2, W3 = W0_new, W1_new, W2_new, W3_new

        # shifted_blocks = [W0, W1, W2, W3]
        # total_shifts = self.n_rounds % 4

        # aligned_blocks = shifted_blocks[-total_shifts:] + shifted_blocks[:-total_shifts] if total_shifts > 0 else shifted_blocks
        # O0, O1, O2, O3 = aligned_blocks

        if i == self.n_rounds - 1:
            W0_out = self._store_le_word(W0)
            W1_out = self._store_le_word(W1)
            W2_out = self._store_le_word(W2)
            W3_out = self._store_le_word(W3)
            # Output order W1+W2+W3+W0 matches the original alignment for 18 rounds
            # (aligned_blocks with 2-shift: [W2,W3,W0,W1], output O3+O0+O1+O2 = W1+W2+W3+W0)
            self.add_cipher_output_component(
                W1_out.id + W2_out.id + W3_out.id + W0_out.id,
                W1_out.input_bit_positions + W2_out.input_bit_positions + W3_out.input_bit_positions + W0_out.input_bit_positions,
                4 * self.word_size,
            )
        else:
            W0_out = self._store_le_word(W0)
            W1_out = self._store_le_word(W1)
            W2_out = self._store_le_word(W2)
            W3_out = self._store_le_word(W3)
            self.add_round_output_component(
                W1_out.id + W2_out.id + W3_out.id + W0_out.id,
                W1_out.input_bit_positions + W2_out.input_bit_positions + W3_out.input_bit_positions + W0_out.input_bit_positions,
                4 * self.word_size,
            )

    def round_function(self, x: ComponentState, rk_group, c: ComponentState) -> ComponentState:
        n = self.word_size
        x_low16 = ComponentState(x.id, [list(range(16, 32))])
        x_high16 = ComponentState(x.id, [list(range(16))])
        zero16 = self._zero_bits(16)
        x0_32 = ComponentState(
            zero16.id + x_low16.id,
            zero16.input_bit_positions + x_low16.input_bit_positions,
        )
        x1_32 = ComponentState(
            zero16.id + x_high16.id,
            zero16.input_bit_positions + x_high16.input_bit_positions,
        )

        self.add_modadd_component(x0_32.id + rk_group[0].id, x0_32.input_bit_positions + rk_group[0].input_bit_positions, n, self.mod32)
        t0 = ComponentState([self.get_current_component_id()], [list(range(n))])
        self.add_modadd_component(x1_32.id + rk_group[1].id, x1_32.input_bit_positions + rk_group[1].input_bit_positions, n, self.mod32)
        t1 = ComponentState([self.get_current_component_id()], [list(range(n))])

        self.add_modmul_component(t0.id + t1.id, t0.input_bit_positions + t1.input_bit_positions, n, self.mod32)
        w0 = ComponentState([self.get_current_component_id()], [list(range(n))])
        self.add_modadd_component(w0.id + rk_group[2].id, w0.input_bit_positions + rk_group[2].input_bit_positions, n, self.mod32)
        w0 = ComponentState([self.get_current_component_id()], [list(range(n))])

        self.add_modadd_component(x0_32.id + rk_group[3].id, x0_32.input_bit_positions + rk_group[3].input_bit_positions, n, self.mod32)
        u0 = ComponentState([self.get_current_component_id()], [list(range(n))])
        self.add_modadd_component(x1_32.id + rk_group[4].id, x1_32.input_bit_positions + rk_group[4].input_bit_positions, n, self.mod32)
        u1 = ComponentState([self.get_current_component_id()], [list(range(n))])
        self.add_modmul_component(u0.id + u1.id, u0.input_bit_positions + u1.input_bit_positions, n, self.mod32)
        w1 = ComponentState([self.get_current_component_id()], [list(range(n))])
        self.add_modadd_component(w1.id + rk_group[5].id, w1.input_bit_positions + rk_group[5].input_bit_positions, n, self.mod32)
        w1 = ComponentState([self.get_current_component_id()], [list(range(n))])
        self.add_xor_component(w1.id + c.id, w1.input_bit_positions + c.input_bit_positions, n)
        w1 = ComponentState([self.get_current_component_id()], [list(range(n))])

        hi16_w0 = ComponentState(w0.id, [list(range(16))])
        hi16_w1 = ComponentState(w1.id, [list(range(16))])
        y = ComponentState(
            hi16_w1.id + hi16_w0.id,
            hi16_w1.input_bit_positions + hi16_w0.input_bit_positions,
        )

        y_orig = y
        self.add_rotate_component(y_orig.id, y_orig.input_bit_positions, n, -13)
        ry13 = ComponentState([self.get_current_component_id()], [list(range(n))])
        self.add_rotate_component(y_orig.id, y_orig.input_bit_positions, n, -21)
        ry21 = ComponentState([self.get_current_component_id()], [list(range(n))])

        self.add_xor_component(y_orig.id + ry13.id, y_orig.input_bit_positions + ry13.input_bit_positions, n)
        y_step1 = ComponentState([self.get_current_component_id()], [list(range(n))])
        self.add_xor_component(y_step1.id + ry21.id, y_step1.input_bit_positions + ry21.input_bit_positions, n)
        y = ComponentState([self.get_current_component_id()], [list(range(n))])
        return y

    def round_initialization_64(self):
        W0_bits = self._load_le_word(0)
        self.add_intermediate_output_component(
            [INPUT_PLAINTEXT] * len(W0_bits),
            [[b] for b in W0_bits],
            self.word_size,
            "w0",
        )
        W0 = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
        W1_bits = self._load_le_word(32)
        self.add_intermediate_output_component(
            [INPUT_PLAINTEXT] * len(W1_bits),
            [[b] for b in W1_bits],
            self.word_size,
            "w1",
        )
        W1 = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
        return W0, W1

    def round_initialization_128(self):
        W0_bits = self._load_le_word(0)
        self.add_intermediate_output_component(
            [INPUT_PLAINTEXT] * len(W0_bits),
            [[b] for b in W0_bits],
            self.word_size,
            "w0",
        )
        W0 = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
        W1_bits = self._load_le_word(32)
        self.add_intermediate_output_component(
            [INPUT_PLAINTEXT] * len(W1_bits),
            [[b] for b in W1_bits],
            self.word_size,
            "w1",
        )
        W1 = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
        W2_bits = self._load_le_word(64)
        self.add_intermediate_output_component(
            [INPUT_PLAINTEXT] * len(W2_bits),
            [[b] for b in W2_bits],
            self.word_size,
            "w2",
        )
        W2 = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
        W3_bits = self._load_le_word(96)
        self.add_intermediate_output_component(
            [INPUT_PLAINTEXT] * len(W3_bits),
            [[b] for b in W3_bits],
            self.word_size,
            "w3",
        )
        W3 = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
        return W0, W1, W2, W3
