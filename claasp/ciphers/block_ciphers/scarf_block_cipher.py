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
from claasp.name_mappings import BLOCK_CIPHER, INPUT_PLAINTEXT, INPUT_KEY, INPUT_TWEAK
from claasp.DTOs.component_state import ComponentState

# fmt: off
scarf_sbox = [
    0x00, 0x02, 0x04, 0x0C, 0x08, 0x0E, 0x18, 0x15, 0x10, 0x13, 0x1C, 0x05, 0x11, 0x14, 0x0B, 0x17,
    0x01, 0x06, 0x07, 0x1A, 0x19, 0x12, 0x0A, 0x1B, 0x03, 0x0D, 0x09, 0x1D, 0x16, 0x1E, 0x0F, 0x1F,
]
permutation = [
    0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 1, 6, 11, 16, 21, 26, 31, 36, 41, 46, 51, 56, 2,
    7, 12, 17, 22, 27, 32, 37, 42, 47, 52, 57, 3, 8, 13, 18, 23, 28, 33, 38, 43, 48, 53, 58, 4, 9,
    14, 19, 24, 29, 34, 39, 44, 49, 54, 59
]
# fmt: on


class SCARFBlockCipher(Cipher):
    """
    Construct an instance of the SCARFBlockCipher class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `10`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `240`); cipher key bit size of the cipher
    - ``tweak_bit_size`` -- **integer** (default: `48`); cipher tweak bit size of the cipher

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.scarf_block_cipher import SCARFBlockCipher
        sage: scarf = SCARFBlockCipher()
        sage: scarf.number_of_rounds
        8

        sage: scarf.component_from(0, 0).id
        'constant_0_0'
    """

    def __init__(self, number_of_rounds=8):
        self.block_bit_size = 10
        self.key_bit_size = 240
        self.tweak_bit_size = 48

        super().__init__(
            family_name="scarf",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY, INPUT_TWEAK],
            cipher_inputs_bit_size=[self.block_bit_size, self.key_bit_size, self.tweak_bit_size],
            cipher_output_bit_size=self.block_bit_size,
        )

        data = ComponentState([INPUT_PLAINTEXT, INPUT_PLAINTEXT], [[0, 1, 2, 3, 4]] * 2)
        key = [INPUT_KEY], [list(range(self.key_bit_size))]
        tweak = [INPUT_TWEAK], [list(range(self.tweak_bit_size))]

        self.add_round()
        constant = self.add_constant_component(1, 0)
        L = self.tweakey_schedule(tweak, key, constant)
        Ti = [L[0], L[0], L[1], L[1], L[2], L[2], L[3], L[3]]

        for r in range(number_of_rounds - 1):
            F_component = self.F_function(data, Ti[r], r)
            xor_component = self.add_subkey(data, Ti[r], r)
            sbox_component = self.add_SBOX_component([xor_component.id], [[0, 1, 2, 3, 4]], 5, scarf_sbox)
            F_component_xored = self.add_XOR_component([F_component.id, data.id[1]], [[0, 1, 2, 3, 4]] * 2, 5)
            data = ComponentState([F_component_xored.id, sbox_component.id], [[0, 1, 2, 3, 4]] * 2)
            self.add_round_output_component(data.id, data.input_bit_positions, self.block_bit_size)
            self.add_round()

        # Last round is different:
        F_component = self.F_function(data, Ti[7], 7)
        F_component_xored = self.add_XOR_component([F_component.id, data.id[1]], [[0, 1, 2, 3, 4]] * 2, 5)
        sbox_component = self.add_SBOX_component([data.id[0]], [[0, 1, 2, 3, 4]], 5, scarf_sbox)
        last_xor = self.add_XOR_component([sbox_component.id, Ti[7].id], [[0, 1, 2, 3, 4], [0, 1, 2, 3, 4]], 5)

        self.add_cipher_output_component(
            [last_xor.id, F_component_xored.id], [[0, 1, 2, 3, 4]] * 2, self.block_bit_size
        )

    def add_subkey(self, data, Ti, current_round):
        if current_round % 2 == 0:
            xor = self.add_XOR_component([data.id[0], Ti.id], [[0, 1, 2, 3, 4], [30, 31, 32, 33, 34]], 5)
        else:
            xor = self.add_XOR_component([data.id[0], Ti.id], [[0, 1, 2, 3, 4], [0, 1, 2, 3, 4]], 5)
        return xor

    def F_function(self, data, Ti, current_round):
        rot_components = []
        self.create_rot_components(data, rot_components)
        and_components = []
        self.create_and_components(rot_components, and_components, Ti, current_round)
        extra_and_component = self.add_AND_component(
            [rot_components[1].id, rot_components[2].id], [[0, 1, 2, 3, 4]] * 2, 5
        )
        input_ids = [xor.id for xor in and_components] + [extra_and_component.id]
        input_bit_pos = [[0, 1, 2, 3, 4]] * 6
        xor_component = self.add_XOR_component(input_ids, input_bit_pos, 5)
        return xor_component

    def create_rot_components(self, data, rot_components):
        for i in range(5):
            rot = self.add_rotate_component([data.id[0]], [list(range(5))], 5, -i)
            rot_components.append(rot)

    def create_and_components(self, rot_components, and_components, Ti, current_round):
        for i in range(5):
            if current_round % 2 == 0:
                l = [list(range(30 + 5 * j, 30 + 5 * j + 5)) for j in range(6)]
                and_comp = self.add_AND_component([rot_components[i].id] + [Ti.id], [[0, 1, 2, 3, 4]] + [l[5 - i]], 5)
            else:
                l = [list(range(5 * j, 5 * j + 5)) for j in range(6)]
                and_comp = self.add_AND_component([rot_components[i].id] + [Ti.id], [[0, 1, 2, 3, 4]] + [l[5 - i]], 5)
            and_components.append(and_comp)

    def tweakey_schedule(self, tweak, key, constant):
        expansion = [list(range(j, j + 4)) for j in range(0, 48, 4)]
        for i in range(0, 24, 2):
            expansion.insert(i, [0])
        T1 = self.add_XOR_component([constant.id, tweak[0][0]] * 12 + key[0], expansion + [list(range(180, 240))], 60)
        self.add_round_key_output_component([T1.id], [list(range(60))], 60)

        sboxes_components = []
        self.create_sbox_components(T1, sboxes_components)
        sigma = self.create_sigma_components(sboxes_components)
        T2 = self.add_XOR_component([sigma.id] + key[0], [list(range(60)), list(range(120, 180))], 60)
        self.add_round_key_output_component([T2.id], [list(range(60))], 60)

        sboxes_components = []
        self.create_sbox_components(T2, sboxes_components)
        input_ids = [sbox_component.id for sbox_component in sboxes_components]
        input_bit_pos = [list(range(5)) for _ in range(12)]
        Sl_xored = self.add_XOR_component(input_ids + key[0], input_bit_pos + [list(range(60, 120))], 60)

        Pi = self.add_permutation_component([Sl_xored.id], [list(range(60))], 60, permutation)
        sboxes_components = []
        self.create_sbox_components(Pi, sboxes_components)
        input_ids = [sbox_component.id for sbox_component in sboxes_components]
        input_bit_pos = [list(range(5)) for _ in range(12)]
        T3 = self.add_round_key_output_component(input_ids, input_bit_pos, 60)

        sigma = self.create_sigma_components(sboxes_components)
        sigma_xored = self.add_XOR_component([sigma.id] + key[0], [list(range(60)), list(range(60))], 60)
        sboxes_components = []
        self.create_sbox_components(sigma_xored, sboxes_components)
        input_ids = [sbox_component.id for sbox_component in sboxes_components]
        input_bit_pos = [list(range(5)) for _ in range(12)]
        T4 = self.add_round_key_output_component(input_ids, input_bit_pos, 60)

        return T1, T2, T3, T4

    def create_sbox_components(self, Ti, sboxes_components):
        for j in range(12):
            sbox = self.add_SBOX_component([Ti.id], [list(range(j * 5, (j + 1) * 5))], 5, scarf_sbox)
            sboxes_components.append(sbox)

    def create_sigma_components(self, sboxes_components):
        input_ids = [sbox_component.id for sbox_component in sboxes_components]
        input_bit_pos = [list(range(5)) for _ in range(12)]
        rot6 = self.add_rotate_component(input_ids, input_bit_pos, 60, -6).id
        rot12 = self.add_rotate_component(input_ids, input_bit_pos, 60, -12).id
        rot19 = self.add_rotate_component(input_ids, input_bit_pos, 60, -19).id
        rot29 = self.add_rotate_component(input_ids, input_bit_pos, 60, -29).id
        rot43 = self.add_rotate_component(input_ids, input_bit_pos, 60, -43).id
        rot51 = self.add_rotate_component(input_ids, input_bit_pos, 60, -51).id
        sigma_xor = self.add_XOR_component(
            [rot6, rot12, rot19, rot29, rot43, rot51] + input_ids,
            [list(range(60)) for _ in range(6)] + input_bit_pos,
            60,
        )
        return sigma_xor
