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
from claasp.name_mappings import INPUT_KEY, INPUT_PLAINTEXT, INPUT_TWEAK, TWEAKABLE_BLOCK_CIPHER

PARAMETERS_CONFIGURATION_LIST = [
    {"number_of_shell_rounds_1": 3, "number_of_core_rounds": 5, "number_of_shell_rounds_2": 3}
]

class BipBipBlockCipher(Cipher):
    """
        Return a cipher object of BipBip Block Cipher.

        Reference:
        Implementation based on [BDDGR23]_.

        INPUT:
        - ``number_of_shell_round_1`` -- **integer** (default: `3`); number of the first shell rounds
        - ``number_of_core_round`` -- **integer** (default: `5`); number of the core rounds
        - ``number_of_shell_round_2`` -- **integer** (default: `3`); number of the last shell rounds

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.bipbip_block_cipher import BipBipBlockCipher
            sage: bipbip = BipBipBlockCipher()
            sage: key = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
            sage: plaintext = 0xffffff
            sage: tweak = 0xffffffffff
            sage: ciphertext = 0x7f15bc
            sage: bipbip.evaluate([plaintext, key, tweak]) == ciphertext
            True
        """

    def __init__(
            self,
            number_of_shell_rounds_1: int = 3,
            number_of_core_rounds: int = 5,
            number_of_shell_rounds_2: int = 3
    ):
        self.block_bit_size = 24
        self.key_bit_size = 256
        self.tweak_bit_size = 40
        self.nrounds = number_of_shell_rounds_1 + number_of_core_rounds + number_of_shell_rounds_2
        self.sh1 = number_of_shell_rounds_1
        self.cr = number_of_core_rounds
        self.sh2 = number_of_shell_rounds_2

        super().__init__(
            family_name="bipbip_block_cipher",
            cipher_type=TWEAKABLE_BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY, INPUT_TWEAK],
            cipher_inputs_bit_size=[self.block_bit_size, self.key_bit_size, self.tweak_bit_size],
            cipher_output_bit_size=self.block_bit_size,
        )

        self.sbox = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x31, 0x05, 0x3A, 0x08, 0x12, 0x35, 0x26, 0x13, 0x36, 0x0A, 0x2C,
            0x2E, 0x09, 0x38, 0x15, 0x33, 0x14, 0x3E, 0x0B, 0x2B, 0x10, 0x25, 0x3C, 0x11, 0x21, 0x23, 0x29,
            0x2F, 0x27, 0x3F, 0x37, 0x34, 0x1A, 0x1D, 0x39, 0x30, 0x2A, 0x1F, 0x0C, 0x19, 0x0F, 0x28, 0x3D,
            0x24, 0x18, 0x3B, 0x0D, 0x20, 0x0E, 0x1E, 0x22, 0x1B, 0x32, 0x1C, 0x17, 0x07, 0x16, 0x06, 0x2D
        ]

        self.permutation_1 = [1, 7, 6, 0, 2, 8, 12, 18, 19, 13, 14, 20, 21, 15, 16, 22, 23, 17, 9, 3, 4, 10, 11, 5]
        self.permutation_2 = [0, 1, 4, 5, 8, 9, 2, 3, 6, 7, 10, 11, 16, 12, 13, 17, 20, 21, 15, 14, 18, 19, 22, 23]
        self.permutation_3 = [16, 22, 11, 5, 2, 8, 0, 6, 19, 13, 12, 18, 14, 15, 1, 7, 21, 20, 4, 3, 17, 23, 10, 9]

        self.add_round()

        round_keys = self.tweak_key_schedule()

        rnd = self.sh1 + self.cr + self.sh2

        state = None
        for i in range(rnd, rnd - self.sh2, -1):
            self.add_round()
            state = self.shell_round(INPUT_PLAINTEXT if state is None else state.id, round_keys[i].id)
        rnd -= self.sh2

        for i in range(rnd, rnd - self.cr, -1):
            self.add_round()
            state = self.core_round(INPUT_PLAINTEXT if state is None else state.id, round_keys[i].id)
        rnd -= self.cr

        for i in range(rnd, rnd - self.sh1, -1):
            self.add_round()
            state = self.shell_round(INPUT_PLAINTEXT if state is None else state.id, round_keys[i].id)
        rnd -= self.sh1

        output = self.add_xor_component(
            [INPUT_PLAINTEXT if state is None else state.id, round_keys[0].id],
            [list(range(24)), list(range(24))],
            24
        )

        self.add_cipher_output_component(
            [output.id],
            [list(range(24))],
            24
        )

    def mixing_layer(self, state_id):
        return self.add_xor_component(
            [state_id, state_id, state_id],
            [
                [(i + 8) % 24 for i in range(24)],
                [(i + 20) % 24 for i in range(24)],
                [(i + 22) % 24 for i in range(24)]
            ],
            24
        )

    def core_round(self, state_id, round_key_id):
        xored = self.add_xor_component(
            [state_id, round_key_id],
            [list(range(24)), list(range(24))],
            24
        )

        permutation2 = self.add_permutation_component(
            [xored.id],
            [list(range(24))],
            24,
            self.permutation_2
        )

        mixed_state = self.mixing_layer(permutation2.id)

        permutation1 = self.add_permutation_component(
            [mixed_state.id],
            [list(range(24))],
            24,
            self.permutation_1
        )

        sbox_outputs = []
        for i in range(4):
            sbox_out = self.add_sbox_component(
                [permutation1.id],
                [[i * 6 + j for j in range(5, -1, -1)]],
                6,
                self.sbox
            )
            sbox_outputs.append(sbox_out.id)

        zero_pad = self.add_constant_component(24, 0)

        round_out = self.add_xor_component(
            sbox_outputs + [zero_pad.id],
            [list(range(5, -1, -1))] * 4 + [list(range(24))],
            24
        )
        return round_out

    def shell_round(self, state_id, round_key_id):
        xored = self.add_xor_component(
            [state_id, round_key_id],
            [list(range(24)), list(range(24))],
            24
        )

        permutation3 = self.add_permutation_component(
            [xored.id],
            [list(range(24))],
            24,
            self.permutation_3
        )

        sbox_outputs = []
        for i in range(4):
            sbox_out = self.add_sbox_component(
                [permutation3.id],
                [[i * 6 + j for j in range(5, -1, -1)]],
                6,
                self.sbox
            )
            sbox_outputs.append(sbox_out.id)

        zero_pad = self.add_constant_component(24, 0)

        round_out = self.add_xor_component(
            sbox_outputs + [zero_pad.id],
            [list(range(5, -1, -1))] * 4 + [list(range(24))],
            24
        )
        return round_out

    def tweak_key_schedule(self):
        k0 = self.compute_k0()
        round_keys = [k0]

        tweak_1 = self.compute_ki(1)
        state = self.initialize_tweak_state(tweak_1.id)
        state = self.chi(state.id)
        round_keys.append(self.extract(state.id, 0))
        round_keys.append(self.extract(state.id, 1))

        tweak_2 = self.compute_ki(2)
        state = self.add_xor_component(
            [state.id, tweak_2.id],
            [list(range(53)), list(range(53))],
            53
        )
        state = self.function_g(state.id, False)
        round_keys.append(self.extract(state.id, 0))
        round_keys.append(self.extract(state.id, 1))

        tweak_3 = self.compute_ki(3)
        state = self.add_xor_component(
            [state.id, tweak_3.id],
            [list(range(53)), list(range(53))],
            53
        )
        state = self.function_g(state.id, False)
        state = self.function_g(state.id, True)
        round_keys.append(self.extract(state.id, 0))

        tweak_4 = self.compute_ki(4)
        state = self.add_xor_component(
            [state.id, tweak_4.id],
            [list(range(53)), list(range(53))],
            53
        )
        state = self.function_g(state.id, False)
        round_keys.append(self.extract(state.id, 0))
        state = self.function_g(state.id, True)
        round_keys.append(self.extract(state.id, 0))

        tweak_5 = self.compute_ki(5)
        state = self.add_xor_component(
            [state.id, tweak_5.id],
            [list(range(53)), list(range(53))],
            53
        )
        state = self.function_g(state.id, False)
        round_keys.append(self.extract(state.id, 0))
        state = self.function_g(state.id, True)
        round_keys.append(self.extract(state.id, 0))

        tweak_6 = self.compute_ki(6)
        state = self.add_xor_component(
            [state.id, tweak_6.id],
            [list(range(53)), list(range(53))],
            53
        )
        state = self.function_g(state.id, False)
        round_keys.append(self.extract(state.id, 0))
        round_keys.append(self.extract(state.id, 1))

        return round_keys

    def compute_k0(self):
        indices = [(3 ** (i + 1)) % 256 for i in range(24)]
        return self.add_permutation_component(
            [INPUT_KEY],
            [indices],
            24,
            list(range(24))
        )

    def compute_ki(self, i):
        indices = [(53 * i + j) % 256 for j in range(53)]
        return self.add_permutation_component(
            [INPUT_KEY],
            [indices],
            53,
            list(range(53))
        )

    def initialize_tweak_state(self, k1_id):
        const_1 = self.add_constant_component(1, 1)
        const_0 = self.add_constant_component(12, 0)

        tweak_state = self.add_xor_component(
            [INPUT_TWEAK, const_1.id, const_0.id, k1_id],
            [list(range(40)), [0], list(range(12)), list(range(53))],
            53
        )
        return tweak_state

    def extract(self, state_id, mode=0):
        if mode != 0 and mode != 1:
            raise ValueError("function E must be of type 0 or 1.")
        indices = [i * 2 + mode for i in range(24)]
        return self.add_permutation_component(
            [state_id],
            [indices],
            24,
            list(range(24))
        )

    def permutation_4(self, state_id):
        indices = [(49 * i) % 53 for i in range(53)]
        return self.add_permutation_component(
            [state_id],
            [list(range(53))],
            53,
            indices
        )

    def permutation_5(self, state_id):
        indices = [(29 * i) % 53 for i in range(53)]
        return self.add_permutation_component(
            [state_id],
            [list(range(53))],
            53,
            indices
        )

    def theta_t(self, state_id):
        return self.add_xor_component(
            [state_id, state_id, state_id],
            [
                list(range(53)),
                [(i+1) % 53 for i in range(53)],
                [(i+8) % 53 for i in range(53)]
            ],
            53
        )

    def theta_prime(self, state_id):
        const = self.add_constant_component(1, 0)
        return self.add_xor_component(
            [state_id, state_id, const.id],
            [
                list(range(53)),
                list(range(1, 53)),
                [0]
            ],
            53
        )

    def chi(self, state_id):
        not_b = self.add_not_component(
            [state_id],
            [[(i+1) % 53 for i in range(53)]],
            53
        )
        and_out = self.add_and_component(
            [not_b.id, state_id],
            [
                list(range(53)),
                [(i+2) % 53 for i in range(53)],
            ],
            53
        )
        chi_out = self.add_xor_component(
            [state_id, and_out.id],
            [list(range(53)), list(range(53))],
            53
        )
        return chi_out

    def function_g(self, state_id, prime = False):
        s1 = self.permutation_4(state_id)
        if prime:
            s2 = self.theta_prime(s1.id)
        else:
            s2 = self.theta_t(s1.id)
        s3 = self.permutation_5(s2.id)
        out = self.chi(s3.id)
        return out