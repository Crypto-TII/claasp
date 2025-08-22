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
from claasp.name_mappings import BLOCK_CIPHER, INPUT_PLAINTEXT, INPUT_KEY
from claasp.utils.utils import extract_inputs

# fmt: off
SBox9 = [
    167, 239, 161, 379, 391, 334, 9, 338, 38, 226, 48, 358, 452, 385, 90, 397,
    183, 253, 147, 331, 415, 340, 51, 362, 306, 500, 262, 82, 216, 159, 356, 177,
    175, 241, 489, 37, 206, 17, 0, 333, 44, 254, 378, 58, 143, 220, 81, 400,
    95, 3, 315, 245, 54, 235, 218, 405, 472, 264, 172, 494, 371, 290, 399, 76,
    165, 197, 395, 121, 257, 480, 423, 212, 240, 28, 462, 176, 406, 507, 288, 223,
    501, 407, 249, 265, 89, 186, 221, 428, 164, 74, 440, 196, 458, 421, 350, 163,
    232, 158, 134, 354, 13, 250, 491, 142, 191, 69, 193, 425, 152, 227, 366, 135,
    344, 300, 276, 242, 437, 320, 113, 278, 11, 243, 87, 317, 36, 93, 496, 27,

    487, 446, 482, 41, 68, 156, 457, 131, 326, 403, 339, 20, 39, 115, 442, 124,
    475, 384, 508, 53, 112, 170, 479, 151, 126, 169, 73, 268, 279, 321, 168, 364,
    363, 292, 46, 499, 393, 327, 324, 24, 456, 267, 157, 460, 488, 426, 309, 229,
    439, 506, 208, 271, 349, 401, 434, 236, 16, 209, 359, 52, 56, 120, 199, 277,
    465, 416, 252, 287, 246, 6, 83, 305, 420, 345, 153, 502, 65, 61, 244, 282,
    173, 222, 418, 67, 386, 368, 261, 101, 476, 291, 195, 430, 49, 79, 166, 330,
    280, 383, 373, 128, 382, 408, 155, 495, 367, 388, 274, 107, 459, 417, 62, 454,
    132, 225, 203, 316, 234, 14, 301, 91, 503, 286, 424, 211, 347, 307, 140, 374,

    35, 103, 125, 427, 19, 214, 453, 146, 498, 314, 444, 230, 256, 329, 198, 285,
    50, 116, 78, 410, 10, 205, 510, 171, 231, 45, 139, 467, 29, 86, 505, 32,
    72, 26, 342, 150, 313, 490, 431, 238, 411, 325, 149, 473, 40, 119, 174, 355,
    185, 233, 389, 71, 448, 273, 372, 55, 110, 178, 322, 12, 469, 392, 369, 190,
    1, 109, 375, 137, 181, 88, 75, 308, 260, 484, 98, 272, 370, 275, 412, 111,
    336, 318, 4, 504, 492, 259, 304, 77, 337, 435, 21, 357, 303, 332, 483, 18,
    47, 85, 25, 497, 474, 289, 100, 269, 296, 478, 270, 106, 31, 104, 433, 84,
    414, 486, 394, 96, 99, 154, 511, 148, 413, 361, 409, 255, 162, 215, 302, 201,

    266, 351, 343, 144, 441, 365, 108, 298, 251, 34, 182, 509, 138, 210, 335, 133,
    311, 352, 328, 141, 396, 346, 123, 319, 450, 281, 429, 228, 443, 481, 92, 404,
    485, 422, 248, 297, 23, 213, 130, 466, 22, 217, 283, 70, 294, 360, 419, 127,
    312, 377, 7, 468, 194, 2, 117, 295, 463, 258, 224, 447, 247, 187, 80, 398,
    284, 353, 105, 390, 299, 471, 470, 184, 57, 200, 348, 63, 204, 188, 33, 451,
    97, 30, 310, 219, 94, 160, 129, 493, 64, 179, 263, 102, 189, 207, 114, 402,
    438, 477, 387, 122, 192, 42, 381, 5, 145, 118, 180, 449, 293, 323, 136, 380,
    43, 66, 60, 455, 341, 445, 202, 432, 8, 237, 15, 376, 436, 464, 59, 461
]
SBox7 = [
    54, 50, 62, 56, 22, 34, 94, 96, 38, 6, 63, 93, 2, 18, 123, 33,
    55, 113, 39, 114, 21, 67, 65, 12, 47, 73, 46, 27, 25, 111, 124, 81,
    53, 9, 121, 79, 52, 60, 58, 48, 101, 127, 40, 120, 104, 70, 71, 43,
    20, 122, 72, 61, 23, 109, 13, 100, 77, 1, 16, 7, 82, 10, 105, 98,
    117, 116, 76, 11, 89, 106, 0, 125, 118, 99, 86, 69, 30, 57, 126, 87,
    112, 51, 17, 5, 95, 14, 90, 84, 91, 8, 35, 103, 32, 97, 28, 66,
    102, 31, 26, 45, 75, 4, 85, 92, 37, 74, 80, 49, 68, 29, 115, 44,
    64, 107, 108, 24, 110, 83, 36, 78, 42, 19, 15, 41, 88, 119, 59, 3
]
# fmt: on

PARAMETERS_CONFIGURATION_LIST = [{"block_bit_size": 64, "key_bit_size": 128, "number_of_rounds": 8}]
half_half_word_distribution = [7, 2, 7]
half_word_distribution = half_half_word_distribution + half_half_word_distribution


class KasumiBlockCipher(Cipher):
    """
    Return a cipher object of Kasumi Block Cipher.

    INPUT:

    - ``number_of_rounds`` -- **integer** (default: `8`); number of rounds of the cipher.
       Must be less or equal to 8

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.kasumi_block_cipher import KasumiBlockCipher
        sage: kasumi = KasumiBlockCipher()
        sage: key = 0x9900aabbccddeeff1122334455667788
        sage: plaintext = 0xfedcba0987654321
        sage: ciphertext= 0x514896226caa4f20
        sage: kasumi.evaluate([key, plaintext]) == ciphertext
        True
    """

    def __init__(self, block_bit_size=64, key_bit_size=128, number_of_rounds=8):
        self.block_bit_size = block_bit_size
        self.key_bit_size = key_bit_size
        self.word_size = int(key_bit_size / 8)
        super().__init__(
            family_name="kasumi_block_cipher",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_KEY, INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[key_bit_size, block_bit_size],
            cipher_output_bit_size=block_bit_size,
        )

        left_half_ids, left_half_positions, right_half_ids, right_half_positions = KasumiBlockCipher.init_halves()

        key = [INPUT_KEY], [list(range(self.key_bit_size))]
        for round_number in range(self._get_number_of_rounds(number_of_rounds)):
            self.add_round()
            if round_number == 0:
                key_derived = self.derived_key(key)
            sub_key = self.round_key(key, key_derived, round_number + 1)
            if round_number % 2 == 0:
                right_half_ids, right_half_positions = self._even_round(
                    left_half_ids, left_half_positions, sub_key, right_half_ids, right_half_positions
                )

            else:
                left_half_ids, left_half_positions = self._odd_round(
                    left_half_ids, left_half_positions, sub_key, right_half_ids, right_half_positions
                )

            self.add_round_output_component(
                left_half_ids + right_half_ids,
                [list(range(size)) for size in half_word_distribution * 2],
                self.block_bit_size,
            )

        self.add_cipher_output_component(
            left_half_ids + right_half_ids,
            [list(range(size)) for size in half_word_distribution * 2],
            self.block_bit_size,
        )

    @staticmethod
    def init_halves():
        left_half_ids = ["plaintext" for _ in range(6)]
        left_half_positions = [
            list(range(sum(half_word_distribution[:i]), sum(half_word_distribution[: i + 1])))
            for i in range(len(half_word_distribution))
        ]
        right_half_ids = ["plaintext" for _ in range(6)]
        offset = 32
        right_half_positions = [
            list(range(sum(half_word_distribution[:i]) + offset, sum(half_word_distribution[: i + 1]) + offset))
            for i in range(len(half_word_distribution))
        ]
        return left_half_ids, left_half_positions, right_half_ids, right_half_positions

    def _even_round(self, left_half_ids, left_positions, sub_key, right_half_ids, right_positions):
        temp_positions = []
        for i in range(6):
            temp_positions.append(list(range(half_word_distribution[i])))

        fls = self.fl_function(left_half_ids, left_positions, sub_key)
        fos = self.fo_function(fls, temp_positions, sub_key)

        new_right_half_ids = []
        for i in range(6):
            xor = self.add_XOR_component(
                [fos[i], right_half_ids[i]],
                [list(range(half_word_distribution[i])), right_positions[i]],
                half_word_distribution[i],
            )
            new_right_half_ids.append(xor.id)

        return new_right_half_ids, temp_positions

    def _odd_round(self, left_half_ids, left_positions, sub_key, right_half_ids, right_positions):
        temp_positions = []
        for i in range(6):
            temp_positions.append(list(range(half_word_distribution[i])))

        fos = self.fo_function(right_half_ids, right_positions, sub_key)

        fls = self.fl_function(fos, temp_positions, sub_key)

        new_left_half_ids = []
        for i in range(6):
            xor = self.add_XOR_component(
                [fls[i], left_half_ids[i]],
                [list(range(half_word_distribution[i])), left_positions[i]],
                half_word_distribution[i],
            )
            new_left_half_ids.append(xor.id)

        return new_left_half_ids, temp_positions

    def _get_number_of_rounds(self, number_of_rounds):
        if number_of_rounds is not None:
            return number_of_rounds

        configuration_number_of_rounds = None
        for parameters in PARAMETERS_CONFIGURATION_LIST:
            if parameters["block_bit_size"] == self.block_bit_size and parameters["key_bit_size"] == self.key_bit_size:
                configuration_number_of_rounds = parameters["number_of_rounds"]
                break
        if configuration_number_of_rounds is None:
            raise ValueError("No available number of rounds for the given parameters.")
        return configuration_number_of_rounds

    def fi_function1(self, ids, ki_id, ki_positions):
        s9_1 = self.add_SBOX_component([ids[0], ids[1]], [list(range(7)), list(range(2))], 9, SBox9).id

        cst1 = self.add_constant_component(2, 0b00).id

        xor1_1 = self.add_XOR_component([s9_1, cst1], [list(range(2)), list(range(2))], 2).id
        xor1_2 = self.add_XOR_component([s9_1, ids[2]], [list(range(2, 9)), list(range(7))], 7).id

        s7_1 = self.add_SBOX_component([ids[2]], [list(range(7))], 7, SBox7).id

        xor2 = self.add_XOR_component([s7_1, xor1_2], [list(range(7)), list(range(7))], 7).id

        xor3_1 = self.add_XOR_component([xor1_1, ki_id], [list(range(2)), ki_positions[7:9]], 2).id
        xor3_2 = self.add_XOR_component([xor1_2, ki_id], [list(range(7)), ki_positions[9:16]], 7).id

        xor4 = self.add_XOR_component([xor2, ki_id], [list(range(7)), ki_positions[:7]], 7).id

        s9_2 = self.add_SBOX_component([xor3_1, xor3_2], [list(range(2)), list(range(7))], 9, SBox9).id

        xor5_1 = self.add_XOR_component([s9_2, cst1], [list(range(2)), list(range(2))], 2)
        xor5_2 = self.add_XOR_component([s9_2, xor4], [list(range(2, 9)), list(range(7))], 7)
        xor5_2_id = xor5_2.id

        s7_2 = self.add_SBOX_component([xor4], [list(range(7))], 7, SBox7).id
        xor6 = self.add_XOR_component([s7_2, xor5_2_id], [list(range(7)), list(range(7))], 7)

        return [xor6, xor5_1, xor5_2]

    def fo_function(self, ids, positions, sub_key):
        start = 32
        xor1s = []
        for i, length in enumerate(half_half_word_distribution):
            end = start + length
            xor1_temp = self.add_XOR_component([ids[i], sub_key], [positions[i], list(range(start, end))], length)
            xor1s.append(xor1_temp.id)
            start = end

        ki_id, ki_positions = extract_inputs(
            [sub_key], [list(range(8 * self.word_size))], [i + 5 * self.word_size for i in range(self.word_size)]
        )

        fis1 = self.fi_function1([xor1s[0], xor1s[1], xor1s[2]], ki_id[0], ki_positions[0])

        xor2s = []
        for i, length in enumerate(half_half_word_distribution):
            xor2_temp = self.add_XOR_component(
                [fis1[i].id, ids[i + 3]], [list(range(length)), positions[i + 3]], length
            )
            xor2s.append(xor2_temp.id)

        subkey_size = [i + 3 * self.word_size for i in range(self.word_size)]

        start = 0
        xor3s = []
        for i, length in enumerate(half_half_word_distribution):
            end = start + length
            xor3_temp = self.add_XOR_component(
                [ids[i + 3], sub_key], [positions[i + 3], subkey_size[start:end]], length
            )
            xor3s.append(xor3_temp.id)
            start = end

        ki2_id, ki2_positions = extract_inputs(
            [sub_key], [list(range(8 * self.word_size))], [i + 6 * self.word_size for i in range(self.word_size)]
        )

        fis2 = self.fi_function1([xor3s[0], xor3s[1], xor3s[2]], ki2_id[0], ki2_positions[0])

        xor4s = []
        for i, length in enumerate(half_half_word_distribution):
            xor4_temp = self.add_XOR_component(
                [fis2[i].id, xor2s[i]], [list(range(length)), list(range(length))], length
            )
            xor4s.append(xor4_temp.id)

        sub_key_positions = [i + 4 * self.word_size for i in range(self.word_size)]

        xor5s = []
        start = 0
        for i, length in enumerate(half_half_word_distribution):
            end = start + length
            xor5_temp = self.add_XOR_component(
                [xor2s[i], sub_key], [list(range(length)), sub_key_positions[start:end]], length
            )
            xor5s.append(xor5_temp.id)
            start = end

        ki3_id, ki3_positions = extract_inputs(
            [sub_key], [list(range(8 * self.word_size))], [i + 7 * self.word_size for i in range(self.word_size)]
        )
        fis3 = self.fi_function1([xor5s[0], xor5s[1], xor5s[2]], ki3_id[0], ki3_positions[0])

        xor6s = []
        for i, length in enumerate(half_half_word_distribution):
            xor6_temp = self.add_XOR_component(
                [fis3[i].id, xor4s[i]], [list(range(length)), list(range(length))], length
            )
            xor6s.append(xor6_temp.id)

        return xor4s + xor6s

    def fl_function(self, ids, positions, sub_key):
        word_size = list(range(self.word_size))
        and1s = []
        start = 0
        for i, length in enumerate(half_half_word_distribution):
            end = start + length
            and1_temp = self.add_AND_component([ids[i], sub_key], [positions[i], word_size[start:end]], length)
            and1s.append(and1_temp.id)
            start = end

        rot1 = self.add_rotate_component(
            [and1s[0], and1s[1], and1s[2]], [list(range(7)), list(range(2)), list(range(7))], self.word_size, -1
        ).id

        rot_size = list(range(self.word_size))

        xor1s = []
        start = 0
        for i, length in enumerate(half_half_word_distribution):
            end = start + length
            xor1_temp = self.add_XOR_component([rot1, ids[i + 3]], [rot_size[start:end], positions[i + 3]], length)
            xor1s.append(xor1_temp.id)
            start = end

        subkey_size = [(i + self.word_size) for i in range(self.word_size)]

        or1s = []
        start = 0
        for i, length in enumerate(half_half_word_distribution):
            end = start + length
            or1_temp = self.add_OR_component([xor1s[i], sub_key], [list(range(length)), subkey_size[start:end]], length)
            or1s.append(or1_temp.id)
            start = end

        rot2 = self.add_rotate_component(or1s, [list(range(7)), list(range(2)), list(range(7))], self.word_size, -1).id

        rot_size = list(range(self.word_size))
        xor2s = []
        start = 0
        for i, length in enumerate(half_half_word_distribution):
            end = start + length
            xor2_temp = self.add_XOR_component([rot2, ids[i]], [rot_size[start:end], positions[i]], length)
            xor2s.append(xor2_temp.id)
            start = end

        return xor2s + xor1s

    def derived_key(self, key):
        cst = self.add_constant_component(128, 0x123456789ABCDEFFEDCBA9876543210).id
        key_der = self.add_XOR_component(
            key[0] + [cst], [list(range(self.key_bit_size))] + [list(range(self.key_bit_size))], self.key_bit_size
        )
        return key_der.id

    def round_key(self, key, key_der, r):
        kl1 = self.add_rotate_component(
            key[0], [[i + (r - 1) * self.word_size for i in range(self.word_size)]], self.word_size, -1
        ).id
        kl2_id, kl2_positions = extract_inputs(
            [key_der],
            [list(range(self.key_bit_size))],
            [i + ((r + 1) % 8) * self.word_size for i in range(self.word_size)],
        )

        ko1 = self.add_rotate_component(
            key[0], [[i + (r % 8) * self.word_size for i in range(self.word_size)]], self.word_size, -5
        ).id
        ko2 = self.add_rotate_component(
            key[0], [[i + ((r + 4) % 8) * self.word_size for i in range(self.word_size)]], self.word_size, -8
        ).id
        ko3 = self.add_rotate_component(
            key[0], [[i + ((r + 5) % 8) * self.word_size for i in range(self.word_size)]], self.word_size, -13
        ).id
        ki1_id, ki1_positions = extract_inputs(
            [key_der],
            [list(range(self.key_bit_size))],
            [i + ((r + 3) % 8) * self.word_size for i in range(self.word_size)],
        )
        ki2_id, ki2_positions = extract_inputs(
            [key_der],
            [list(range(self.key_bit_size))],
            [i + ((r + 2) % 8) * self.word_size for i in range(self.word_size)],
        )
        ki3_id, ki3_positions = extract_inputs(
            [key_der],
            [list(range(self.key_bit_size))],
            [i + ((r + 6) % 8) * self.word_size for i in range(self.word_size)],
        )

        sub_key = self.add_round_key_output_component(
            [kl1, kl2_id[0], ko1, ko2, ko3, ki1_id[0], ki2_id[0], ki3_id[0]],
            [
                list(range(self.word_size)),
                kl2_positions[0],
                list(range(self.word_size)),
                list(range(self.word_size)),
                list(range(self.word_size)),
                ki1_positions[0],
                ki2_positions[0],
                ki3_positions[0],
            ],
            self.key_bit_size,
        ).id
        return sub_key
