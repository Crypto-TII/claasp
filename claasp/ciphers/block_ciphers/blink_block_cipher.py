# ****************************************************************************
# Copyright 2026 Technology Innovation Institute
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
from claasp.name_mappings import (
    BLOCK_CIPHER,
    INPUT_KEY,
    INPUT_PLAINTEXT,
    INPUT_TWEAK,
)

PARAMETERS_CONFIGURATION_LIST = [
    {
        "block_bit_size": 64,
        "tweak_bit_size": 64,
        "key_bit_size": 448,
        "a": 2,
        "b": 3,
    },
    {
        "block_bit_size": 64,
        "tweak_bit_size": 128,
        "key_bit_size": 448,
        "a": 2,
        "b": 3,
    },
    {
        "block_bit_size": 128,
        "tweak_bit_size": 128,
        "key_bit_size": 1024,
        "a": 3,
        "b": 3,
    },
    {
        "block_bit_size": 128,
        "tweak_bit_size": 256,
        "key_bit_size": 1024,
        "a": 3,
        "b": 3,
    },
    {
        "block_bit_size": 128,
        "tweak_bit_size": 128,
        "key_bit_size": 1280,
        "a": 3,
        "b": 5,
    },
    {
        "block_bit_size": 128,
        "tweak_bit_size": 256,
        "key_bit_size": 1280,
        "a": 3,
        "b": 5,
    },
]

PERMUTATION_64 = [
    0, 5, 11, 10,
    1, 6, 4, 13,
    2, 12, 9, 15,
    3, 7, 14, 8,
]

PERMUTATION_128 = [
    5, 12, 4, 1,
    17, 9, 10, 16,
    28, 14, 21, 22,
    11, 27, 8, 13,
    2, 25, 18, 3,
    30, 6, 19, 20,
    0, 23, 24, 31,
    7, 15, 29, 26,
]

MIX_COLUMN_MATRIX = [
    [0, 1, 1, 1],
    [1, 0, 1, 1],
    [1, 1, 0, 1],
    [1, 1, 1, 0],
]

SBOX = [
    0x1, 0x0, 0x9, 0x3,
    0x8, 0x5, 0xE, 0x7,
    0x4, 0x2, 0xC, 0xB,
    0xA, 0xF, 0x6, 0xD,
]

ROUND_CONSTANTS_64 = [
    0x13198A2E03707344,
    0x082EFA98EC4E6C89,
    0xBE5466CF34E90C6C,
    0x3F84D5B5B5470917,
    0xD1310BA698DFB5AC,
]

ROUND_CONSTANTS_PRIME_64 = [
    0x0D95748F728EB658,
    0x7B54A41DC25A59B5,
    0xC5D1B023286085F0,
    0x8E79DCB0603A180E,
    0xD71577C1BD314B27,
]

ROUND_CONSTANTS_128 = [
    0x243F6A8885A308D313198A2E03707344,
    0xA4093822299F31D0082EFA98EC4E6C89,
    0x452821E638D01377BE5466CF34E90C6C,
    0xC0AC29B7C97C50DD3F84D5B5B5470917,
    0x9216D5D98979FB1BD1310BA698DFB5AC,
    0x2FFD72DBD01ADFB7B8E1AFED6A267E96,
    0xBA7C9045F12C7F9924A19947B3916CF7,
    0x0801F2E2858EFC16636920D871574E69,
]

ROUND_CONSTANTS_PRIME_128 = [
    0xA458FEA3F4933D7E0D95748F728EB658,
    0x718BCD5882154AEE7B54A41DC25A59B5,
    0x9C30D5392AF26013C5D1B023286085F0,
    0xCA417918B8DB38EF8E79DCB0603A180E,
    0x6C9E0E8BB01E8A3ED71577C1BD314B27,
    0x78AF2FDA55605C60E65525F3AA55AB94,
    0x5748986263E8144055CA396A2AAB10B6,
    0xB4CC5C341141E8CEA15486AF7C72E993,
]


class BlinkBlockCipher(Cipher):
    """
    Return a cipher object of the BLINK tweakable block cipher.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `128`);
      size of the plaintext and ciphertext blocks in bits.
    - ``tweak_bit_size`` -- **integer** (default: `128`);
      size of the tweak in bits.
    - ``key_bit_size`` -- **integer** (default: `1024`);
      size of the master key in bits.
    - ``a`` -- **integer** (default: `3`);
      number of rounds in the first part of the BLINK construction.
    - ``b`` -- **integer** (default: `3`);
      number of rounds in the second part of the BLINK construction.
    """

    def __init__(
        self,
        block_bit_size=128,
        tweak_bit_size=128,
        key_bit_size=1024,
        a=3,
        b=3,
    ):
        configuration = {
            "block_bit_size": block_bit_size,
            "tweak_bit_size": tweak_bit_size,
            "key_bit_size": key_bit_size,
            "a": a,
            "b": b,
        }

        if configuration not in PARAMETERS_CONFIGURATION_LIST:
            raise ValueError("Invalid BLINK parameter configuration")

        self.block_bit_size = block_bit_size
        self.tweak_bit_size = tweak_bit_size
        self.key_bit_size = key_bit_size
        self.a = a
        self.b = b
        self.word_size = 4
        self.number_of_cells = block_bit_size // self.word_size

        if block_bit_size == 64:
            self.permutation = PERMUTATION_64
            self.round_constants = ROUND_CONSTANTS_64
            self.round_constants_prime = ROUND_CONSTANTS_PRIME_64
        else:
            self.permutation = PERMUTATION_128
            self.round_constants = ROUND_CONSTANTS_128
            self.round_constants_prime = ROUND_CONSTANTS_PRIME_128

        self.inverse_permutation = [
            self.permutation.index(i)
            for i in range(self.number_of_cells)
        ]

        self.mix_column_matrix = MIX_COLUMN_MATRIX
        self.sbox = SBOX

        super().__init__(
            family_name="blink",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_KEY, INPUT_PLAINTEXT, INPUT_TWEAK],
            cipher_inputs_bit_size=[
                key_bit_size,
                block_bit_size,
                tweak_bit_size,
            ],
            cipher_output_bit_size=block_bit_size,
        )
    
        self.add_round()

        round_keys = self._get_round_keys()
        h1, h2, h = self._add_tweak_hashes()

        state = self._add_pi1(INPUT_PLAINTEXT, round_keys)
        state = self._xor_state_with_hash(state, h1)

        state = self._add_pi2(state, round_keys)
        state = self._xor_state_with_hash(state, h)

        state = self._add_pi3(state, round_keys)
        state = self._xor_state_with_hash(state, h2)

        state = self._add_pi4(state, round_keys)

        self.add_cipher_output_component(
        list(reversed(state)),
        [
            list(range(self.word_size))
            for _ in range(self.number_of_cells)
        ],
        self.block_bit_size,
    )

    def _get_key_slice(self, index_from_lsb):
        """
        Return one block-sized slice of the master key.

        The index is counted from the least significant block.
        """
        start = self.key_bit_size - self.block_bit_size * (index_from_lsb + 1)

        return (
            INPUT_KEY,
            list(range(start, start + self.block_bit_size)),
        )

    def _get_whitening_keys(self):
        """
        Return the whitening keys w1 and w2.
        """
        w1 = self._get_key_slice(0)
        w2 = self._get_key_slice(1)
    
        return w1, w2

    def _get_round_keys(self):
        """
        Return rk1, ..., rk_(a+b).
        """
        return [
            self._get_key_slice(i + 2)
            for i in range(self.a + self.b)
        ]

    def _add_sbox_layer(self, state):
        """
        Apply the BLINK S-box to every 4-bit cell of the state.
        """
        sbox_outputs = []
    
        for i in range(self.number_of_cells):
            if isinstance(state, list):
                input_id = state[i]
                input_bit_positions = list(range(self.word_size))
            else:
                input_id = state
                start = self.block_bit_size - (i + 1) * self.word_size
                input_bit_positions = list(
                    range(start, start + self.word_size)
                )
    
            sbox_output = self.add_sbox_component(
                [input_id],
                [input_bit_positions],
                self.word_size,
                self.sbox,
            ).id
    
            sbox_outputs.append(sbox_output)
    
        return sbox_outputs

    def _permute_cells(self, state):
        """
        Apply the BLINK cell permutation to the state.
        """
        return [state[i] for i in self.permutation]

    def _inverse_permute_cells(self, state):
        """
        Apply the inverse BLINK cell permutation to the state.
        """
        return [state[i] for i in self.inverse_permutation]

    def _add_mix_column_layer(self, state):
        """
        Apply the BLINK MixColumn layer to the state.
        """
        number_of_layers = self.block_bit_size // 64
        mixed_state = [None] * self.number_of_cells
    
        for layer in range(number_of_layers):
            layer_start = layer * 16
    
            for column_index in range(4):
                column = [
                    state[layer_start + column_index + row * 4]
                    for row in range(4)
                ]
    
                for output_row in range(4):
                    input_cells = [
                        column[input_row]
                        for input_row in range(4)
                        if self.mix_column_matrix[output_row][input_row]
                    ]
    
                    mixed_cell = self.add_xor_component(
                        input_cells,
                        [
                            list(range(self.word_size))
                            for _ in input_cells
                        ],
                        self.word_size,
                    ).id
    
                    mixed_state[
                        layer_start + column_index + output_row * 4
                    ] = mixed_cell
    
        return mixed_state
    def _add_round_key(self, state, round_key):
        """
        XOR the round key with the state.
        """
        key_id, key_bit_positions = round_key
        output_state = []

        for i in range(self.number_of_cells):
            start = self.block_bit_size - (i + 1) * self.word_size

            output_cell = self.add_xor_component(
                [state[i], key_id],
                [
                    list(range(self.word_size)),
                    key_bit_positions[start:start + self.word_size],
                ],
                self.word_size,
            ).id

            output_state.append(output_cell)

        return output_state

    def _add_round_constant(self, state, round_constant):
        """
        XOR a round constant with the state.
        """
        constant = self.add_constant_component(
            self.block_bit_size,
            round_constant,
        ).id

        output_state = []

        for i in range(self.number_of_cells):
            start = self.block_bit_size - (i + 1) * self.word_size

            output_cell = self.add_xor_component(
                [state[i], constant],
                [
                    list(range(self.word_size)),
                    list(range(start, start + self.word_size)),
                ],
                self.word_size,
            ).id

            output_state.append(output_cell)

        return output_state

    def _add_forward_round(self, state, round_key, round_constant):
        """
        Apply one forward BLINK round.
        """
        state = self._add_sbox_layer(state)
        state = self._add_mix_column_layer(state)
        state = self._add_round_key(state, round_key)
        state = self._add_round_constant(state, round_constant)
        state = self._permute_cells(state)
    
        return state

    def _add_inverse_round(self, state, round_key, round_constant):
        """
        Apply one inverse BLINK round.
        """
        state = self._inverse_permute_cells(state)
        state = self._add_round_key(state, round_key)
        state = self._add_round_constant(state, round_constant)
        state = self._add_mix_column_layer(state)
        state = self._add_sbox_layer(state)
    
        return state

    def _get_hash_keys(self):
        """
        Return the Toeplitz hash keys k1 and k2.
        """
        hash_key_size = self.block_bit_size + self.tweak_bit_size - 1
        total_hash_key_size = 2 * hash_key_size
    
        least_significant_positions = [
            self.key_bit_size - 1 - ((11 * i) % self.key_bit_size)
            for i in range(total_hash_key_size)
        ]
    
        k1_positions = list(
            reversed(
                least_significant_positions[:hash_key_size]
            )
        )
        
        k2_positions = list(
            reversed(
                least_significant_positions[hash_key_size:]
            )
        )
    
        k1 = (INPUT_KEY, k1_positions)
        k2 = (INPUT_KEY, k2_positions)
    
        return k1, k2

    def _add_toeplitz_hash(self, hash_key):
        """
        Compute the BLINK Toeplitz hash of the tweak.
        """
        key_id, key_positions = hash_key
        hash_output = []

        for row in range(self.block_bit_size):
            toeplitz_key_positions = [
                key_positions[self.block_bit_size - 1 - row + column]
                for column in range(self.tweak_bit_size)
            ]

            products = self.add_and_component(
                [key_id, INPUT_TWEAK],
                [
                    toeplitz_key_positions,
                    list(range(self.tweak_bit_size)),
                ],
                self.tweak_bit_size,
            ).id

            output_bit = self.add_xor_component(
                [products],
                [list(range(self.tweak_bit_size))],
                1,
            ).id

            hash_output.append(output_bit)

        return hash_output

    def _add_tweak_hashes(self):
        """
        Compute h1(t), h2(t), and h(t) = h1(t) XOR h2(t).
        """
        k1, k2 = self._get_hash_keys()

        h1 = self._add_toeplitz_hash(k1)
        h2 = self._add_toeplitz_hash(k2)

        h = []

        for i in range(self.block_bit_size):
            output_bit = self.add_xor_component(
                [h1[i], h2[i]],
                [[0], [0]],
                1,
            ).id

            h.append(output_bit)

        return h1, h2, h

    def _xor_state_with_hash(self, state, hash_value):
        """
        XOR the state with a tweak hash value.
        """
        output_state = []
    
        for i in range(self.number_of_cells):
            start = self.block_bit_size - (i + 1) * self.word_size
    
            hash_bits = hash_value[
                start:start + self.word_size
            ]
    
            output_cell = self.add_xor_component(
                [state[i]] + hash_bits,
                [list(range(self.word_size))]
                + [[0] for _ in range(self.word_size)],
                self.word_size,
            ).id
    
            output_state.append(output_cell)
    
        return output_state

    def _xor_state_with_key(self, state, key):
        """
        XOR a state with a block-sized key.
        """
        key_id, key_bit_positions = key
        output_state = []

        for i in range(self.number_of_cells):
            start = self.block_bit_size - (i + 1) * self.word_size

            if isinstance(state, list):
                state_id = state[i]
                state_bit_positions = list(range(self.word_size))
            else:
                state_id = state
                state_bit_positions = list(
                    range(start, start + self.word_size)
                )

            output_cell = self.add_xor_component(
                [state_id, key_id],
                [
                    state_bit_positions,
                    key_bit_positions[start:start + self.word_size],
                ],
                self.word_size,
            ).id

            output_state.append(output_cell)

        return output_state

    def _add_pi1(self, state, round_keys):
        """
        Apply the BLINK permutation pi1.
        """
        w1, _ = self._get_whitening_keys()

        state = self._xor_state_with_key(state, w1)

        for i in range(self.a):
            state = self._add_forward_round(
                state,
                round_keys[i],
                self.round_constants[i],
            )

        state = self._add_sbox_layer(state)
        state = self._add_mix_column_layer(state)

        return state

    def _add_pi2(self, state, round_keys):
        """
        Apply the BLINK permutation pi2.
        """
        state = self._permute_cells(state)
    
        for i in range(self.b):
            round_index = self.a + i
    
            state = self._add_forward_round(
                state,
                round_keys[round_index],
                self.round_constants[round_index],
            )
    
        state = self._add_sbox_layer(state)
        state = self._add_mix_column_layer(state)
    
        return state

    def _add_pi3(self, state, round_keys):
        """
        Apply the BLINK permutation pi3.
        """
        state = self._add_sbox_layer(state)
    
        for i in range(self.b):
            state = self._add_inverse_round(
                state,
                round_keys[i],
                self.round_constants_prime[i],
            )

        state = self._inverse_permute_cells(state)

        return state

    def _add_pi4(self, state, round_keys):
        """
        Apply the BLINK permutation pi4.
        """
        _, w2 = self._get_whitening_keys()

        state = self._add_mix_column_layer(state)
        state = self._add_sbox_layer(state)

        for i in range(self.a):
            round_index = self.b + i
    
            state = self._add_inverse_round(
                state,
                round_keys[round_index],
                self.round_constants_prime[round_index],
            )

        state = self._xor_state_with_key(state, w2)

        return state
