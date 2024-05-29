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
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY

SBOX = [0x08, 0x00, 0x09, 0x03, 0x38, 0x10, 0x29, 0x13,
        0x0c, 0x0d, 0x04, 0x07, 0x30, 0x01, 0x20, 0x23,
        0x1a, 0x12, 0x18, 0x32, 0x3e, 0x16, 0x2c, 0x36,
        0x1c, 0x1d, 0x14, 0x37, 0x34, 0x05, 0x24, 0x27,
        0x02, 0x06, 0x0b, 0x0f, 0x33, 0x17, 0x21, 0x15,
        0x0a, 0x1b, 0x0e, 0x1f, 0x31, 0x11, 0x25, 0x35,
        0x22, 0x26, 0x2a, 0x2e, 0x3a, 0x1e, 0x28, 0x3c,
        0x2b, 0x3b, 0x2f, 0x3f, 0x39, 0x19, 0x2d, 0x3d]
CONSTANTS = [0x243, 0xf6a, 0x888, 0x5a3, 0x08d, 0x313, 0x198, 0xa2e, 0x037, 0x073, 0x44a, 0x409,
             0x382, 0x229, 0x9f3, 0x1d0, 0x082, 0xefa, 0x98e, 0xc4e, 0x6c8, 0x945, 0x282, 0x1e6,
             0x38d, 0x013, 0x77b, 0xe54, 0x66c, 0xf34, 0xe90, 0xc6c, 0xc0a, 0xc29, 0xb7c, 0x97c,
             0x50d, 0xd3f, 0x84d, 0x5b5, 0xb54, 0x709, 0x179, 0x216, 0xd5d, 0x989, 0x79f, 0xb1b,
             0xd13, 0x10b, 0xa69, 0x8df, 0xb5a, 0xc2f, 0xfd7, 0x2db, 0xd01, 0xadf, 0xb7b, 0x8e1,
             0xafe, 0xd6a, 0x267, 0xe96, 0xba7, 0xc90, 0x45f, 0x12c, 0x7f9, 0x924, 0xa19, 0x947,
             0xb39, 0x16c, 0xf70, 0x801, 0xf2e, 0x285, 0x8ef, 0xc16, 0x636, 0x920, 0xd87, 0x157,
             0x4e6, 0x9a4, 0x58f, 0xea3, 0xf49, 0x33d, 0x7e0, 0xd95, 0x748, 0xf72, 0x8eb, 0x658,
             0x718, 0xbcd, 0x588, 0x215, 0x4ae, 0xe7b, 0x54a, 0x41d, 0xc25, 0xa59, 0xb59, 0xc30,
             0xd53, 0x92a, 0xf26, 0x013, 0xc5d, 0x1b0, 0x232, 0x860, 0x85f, 0x0ca, 0x417, 0x918,
             0xb8d, 0xb38, 0xef8, 0xe79, 0xdcb, 0x060, 0x3a1, 0x80e, 0x6c9, 0xe0e, 0x8bb, 0x01e,
             0x8a3, 0xed7, 0x157, 0x7c1, 0xbd3, 0x14b, 0x277, 0x8af, 0x2fd, 0xa55, 0x605, 0xc60,
             0xe65, 0x525, 0xf3a, 0xa55, 0xab9, 0x457, 0x489, 0x862, 0x63e, 0x814, 0x405, 0x5ca,
             0x396, 0xa2a, 0xab1, 0x0b6, 0xb4c, 0xc5c, 0x341, 0x141, 0xe8c, 0xea1, 0x548, 0x6af,
             0x7c7, 0x2e9, 0x93b, 0x3ee, 0x141, 0x163, 0x6fb, 0xc2a, 0x2ba, 0x9c5, 0x5d7, 0x418,
             0x31f, 0x6ce, 0x5c3, 0xe16, 0x9b8, 0x793, 0x1ea, 0xfd6, 0xba3, 0x36c, 0x24c, 0xf5c,
             0x7a3, 0x253, 0x812, 0x895, 0x867, 0x73b, 0x8f4, 0x898, 0x6b4, 0xbb9, 0xafc, 0x4bf,
             0xe81, 0xb66, 0x282, 0x193, 0x61d, 0x809, 0xccf, 0xb21, 0xa99, 0x148, 0x7ca, 0xc60,
             0x5de, 0xc80, 0x32e, 0xf84, 0x5d5, 0xde9, 0x857, 0x5b1, 0xdc2, 0x623, 0x02e, 0xb65,
             0x1b8, 0x823, 0x893, 0xe81, 0xd39, 0x6ac, 0xc50, 0xf6d, 0x6ff, 0x383, 0xf44, 0x239,
             0x2e0, 0xb44, 0x82a, 0x484, 0x200, 0x469, 0xc8f, 0x04a, 0x9e1, 0xf9b, 0x5e2, 0x1c6,
             0x684, 0x2f6, 0xe96, 0xc9a, 0x670, 0xc9c, 0x61a, 0xbd3, 0x88f, 0x06a, 0x51a, 0x0d2,
             0xd85, 0x42f, 0x689, 0x60f, 0xa72, 0x8ab, 0x513, 0x3a3, 0x6ee, 0xf0b, 0x6c1, 0x37a,
             0x3be, 0x4ba, 0x3bf, 0x050, 0x7ef, 0xb2a, 0x98a, 0x1f1, 0x651, 0xd39, 0xaf0, 0x176,
             0x66c, 0xa59, 0x3e8, 0x243, 0x0e8, 0x88c, 0xee8, 0x619, 0x456, 0xf9f, 0xb47, 0xd84,
             0xa5c, 0x33b, 0x8b5, 0xebe, 0xe06, 0xf75, 0xd88, 0x5c1, 0x207, 0x340, 0x1a4, 0x49f,
             0x56c, 0x16a, 0xa64, 0xed3, 0xaa6, 0x236, 0x3f7, 0x706, 0x1bf, 0xedf, 0x724, 0x29b,
             0x023, 0xd37, 0xd0d, 0x724, 0xd00, 0xa12, 0x48d, 0xb0f, 0xead, 0x349, 0xf1c, 0x09b,
             0x075, 0x372, 0xc98, 0x099, 0x1b7, 0xb25, 0xd47, 0x9d8, 0xf6e, 0x8de, 0xf7e, 0x3fe,
             0x501, 0xab6, 0x794, 0xc3b, 0x976, 0xce0, 0xbd0, 0x4c0, 0x06b, 0xac1, 0xa94, 0xfb6,
             0x409, 0xf60, 0xc45, 0xe5c, 0x9ec, 0x219, 0x6a2, 0x463, 0x68f, 0xb6f, 0xaf3, 0xe6c,
             0x53b, 0x513, 0x39b, 0x2eb, 0x3b5, 0x2ec, 0x6f6, 0xdfc, 0x511, 0xf9b, 0x309, 0x52c,
             0xcc8, 0x145, 0x44a, 0xf5e, 0xbd0, 0x9be, 0xe3d, 0x004, 0xde3, 0x34a, 0xfd6, 0x60f,
             0x280, 0x719, 0x2e4, 0xbb3, 0xc0c, 0xba8, 0x574, 0x5c8, 0x740, 0xfd2, 0x0b5, 0xf39,
             0xb9d, 0x3fb, 0xdb5, 0x579, 0xc0b, 0xd1a, 0x603, 0x20a, 0xd6a, 0x100, 0xc64, 0x02c,
             0x727, 0x967, 0x9f2, 0x5fe, 0xfb1, 0xfa3, 0xcc8, 0xea5, 0xe9f, 0x8db, 0x322, 0x2f8,
             0x3c7, 0x516, 0xdff, 0xd61, 0x6b1, 0x52f, 0x501, 0xec8, 0xad0, 0x552, 0xab3, 0x23d,
             0xb5f, 0xafd, 0x238, 0x760, 0x533, 0x17b, 0x483, 0xe00, 0xdf8, 0x29e, 0x5c5, 0x7bb,
             0xca6, 0xf8c, 0xa01, 0xa87, 0x562, 0xedf, 0x176, 0x9db, 0xd54, 0x2a8, 0xf62, 0x87e,
             0xffc, 0x3ac, 0x673, 0x2c6, 0x8c4, 0xf55, 0x736, 0x95b, 0x27b, 0x0bb, 0xca5, 0x8c8,
             0xe1f, 0xfa3, 0x5db, 0x8f0, 0x11a, 0x010, 0xfa3, 0xd98, 0xfd2, 0x183, 0xb84, 0xafc,
             0xb56, 0xc2d, 0xd1d, 0x35b, 0x9a5, 0x3e4, 0x79b, 0x6f8, 0x456, 0x5d2, 0x8e4, 0x9bc,
             0x4bf, 0xb97, 0x90e, 0x1dd, 0xf2d, 0xaa4, 0xcb7, 0xe33, 0x62f, 0xb13, 0x41c, 0xee4,
             0xc6e, 0x8ef, 0x20c, 0xada, 0x367, 0x74c, 0x01d, 0x07e, 0x9ef, 0xe2b, 0xf11, 0xfb4,
             0x95d, 0xbda, 0x4da, 0xe90, 0x919]
PARAMETERS_CONFIGURATION_LIST = [
    {'block_bit_size': 192, 'key_bit_size': 192, 'number_of_rounds': 5}
]


class SpeedyBlockCipher(Cipher):
    """
    Construct an instance of the SpeedyBlockCipher class.

    The implementation follows the specifics in [LMM+2021]_.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    Note that the ``l`` parameter of the cipher is automatically determined by ``block_bit_size`` and
    ``key_bit_size``. Please use the same value, multiple of 12, for both variables.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `192`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `192`); cipher key bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `1`); number of rounds of the cipher.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speedy_block_cipher import SpeedyBlockCipher
        sage: speedy = SpeedyBlockCipher(number_of_rounds=5)
        sage: plaintext = 0xa13a632451070e4382a27f26a40682f3fe9ff68028d24fdb
        sage: key = 0x764c4f6254e1bff208e95862428faed01584f4207a7e8477
        sage: ciphertext = 0x01da25a93d1cfc5e4c0b74f677eb746c281a260193b7755a
        sage: speedy.evaluate([plaintext, key]) == ciphertext
        True

    """

    def __init__(self, block_bit_size=192, key_bit_size=192, number_of_rounds=1, alpha=(0, 1, 5, 9, 15, 21, 26),
                 beta=7, gamma=1):
        if block_bit_size != key_bit_size:
            raise Exception(f"block_bit_size (={block_bit_size}) and key_bit_size (={key_bit_size}) differs."
                            "No cipher created")
        if block_bit_size % 6 != 0:
            raise Exception(f"block_bit_size (={block_bit_size}) is NOT a multiple of 6."
                            "It MUST be a multiple of 6.")
        self.l = block_bit_size // 6
        self.constants_per_block = self.l // 2

        self.permutation = [0] * 192
        for i in range(self.l):
            for j in range(6):
                parameter = (beta * (6*i+j) + gamma) % (6 * self.l)
                new_i, new_j = parameter // 6, parameter % 6
                self.permutation[6*new_i + new_j] = 6*i + j

        super().__init__(family_name="speedy",
                         cipher_type="block_cipher",
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                         cipher_inputs_bit_size=[block_bit_size, key_bit_size],
                         cipher_output_bit_size=block_bit_size)
        
        block = ComponentState(INPUT_PLAINTEXT, [list(range(block_bit_size))])
        key = ComponentState(INPUT_KEY, [list(range(key_bit_size))])

        for round_number in range(number_of_rounds - 1):
            self.add_round()

            # the comments describe the point of view of the state
            # state is a whole of 6*l bits
            block = self.add_XOR_component([block.id, key.id], block.input_bit_positions + key.input_bit_positions,
                                           block_bit_size)
            # state is l components corresponding to the l sboxes
            block = [self.add_SBOX_component([block.id], [list(range(6*i, 6*(i+1)))], 6, SBOX) for i in range(self.l)]
            # state is 6 columns
            new_block = []
            input_ids = [block[_].id for _ in range(self.l)]
            for i in range(6):
                input_bit_positions = [[i] for _ in range(self.l)] 
                new_block.append(self.add_rotate_component(input_ids, input_bit_positions, self.l, -i))
            block = new_block
            # state is l components corresponding to the l sboxes
            new_block = []
            input_ids = [block[_].id for _ in range(6)]
            for i in range(self.l):
                input_bit_positions = [[i] for _ in range(6)] 
                new_block.append(self.add_SBOX_component(input_ids, input_bit_positions, 6, SBOX))
            block = new_block
            # state is 6 columns
            new_block = []
            input_ids = [block[_].id for _ in range(self.l)]
            for i in range(6):
                input_bit_positions = [[i] for _ in range(self.l)] 
                new_block.append(self.add_rotate_component(input_ids, input_bit_positions, self.l, -i))
            block = new_block
            # state is l components corresponding to the l rows of the block
            new_block = []
            input_ids = [block[_].id for _ in range(6)] * len(alpha)
            for i in range(self.l):
                input_bit_positions = [[(i+a) % self.l] for a in alpha for _ in range(6)]
                new_block.append(self.add_XOR_component(input_ids, input_bit_positions, 6))
            block = new_block
            # state is a whole of 6*l bits
            constant = 0
            for i in range(self.constants_per_block*round_number, self.constants_per_block*(round_number+1)):
                constant <<= 12
                constant ^= CONSTANTS[i]
            constant_component = self.add_constant_component(192, constant)
            input_ids = [nb.id for nb in block] + [constant_component.id]
            input_bit_positions = [list(range(6)) for _ in range(self.l)] + [list(range(6*self.l))]
            block = self.add_XOR_component(input_ids, input_bit_positions, block_bit_size)
            block = ComponentState(block.id, [list(range(block_bit_size))])
            # key schedule
            key = self.add_permutation_component([key.id], [list(range(6*self.l))], 6*self.l, self.permutation)
            key = ComponentState(key.id, [list(range(key_bit_size))])

            self.add_round_key_output_component([key.id], [list(range(6*self.l))], 6*self.l)
            self.add_round_output_component([block.id], [list(range(6*self.l))], 6*self.l)
    
        self.add_round()
        
        # state is a whole of 6*l bits
        block = self.add_XOR_component([block.id, key.id], block.input_bit_positions + key.input_bit_positions,
                                       block_bit_size)
        # state is l components corresponding to the l sboxes
        block = [self.add_SBOX_component([block.id], [list(range(6*i, 6*(i+1)))], 6, SBOX) for i in range(self.l)]
        # state is 6 columns
        new_block = []
        input_ids = [block[_].id for _ in range(self.l)]
        for i in range(6):
            input_bit_positions = [[i] for _ in range(self.l)] 
            new_block.append(self.add_rotate_component(input_ids, input_bit_positions, self.l, -i))
        block = new_block
        # state is l components corresponding to the l sboxes
        new_block = []
        input_ids = [block[_].id for _ in range(6)]
        for i in range(self.l):
            input_bit_positions = [[i] for _ in range(6)] 
            new_block.append(self.add_SBOX_component(input_ids, input_bit_positions, 6, SBOX))
        block = new_block
        # key schedule
        key = self.add_permutation_component([key.id], [list(range(6*self.l))], 6*self.l, self.permutation)
        # state is a whole of 6*l bits
        input_ids = [nb.id for nb in new_block] + [key.id]
        input_bit_positions = [list(range(6)) for _ in range(self.l)] + [list(range(6*self.l))]
        block = self.add_XOR_component(input_ids, input_bit_positions, block_bit_size)

        self.add_round_key_output_component([key.id], [list(range(6*self.l))], 6*self.l)
        self.add_cipher_output_component([block.id], [list(range(6*self.l))], 6*self.l)
