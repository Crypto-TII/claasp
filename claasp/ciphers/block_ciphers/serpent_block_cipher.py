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
from claasp.name_mappings import BLOCK_CIPHER, INPUT_KEY, INPUT_PLAINTEXT


BLOCK_BIT_SIZE = 128
WORD_BIT_SIZE = 32
NUMBER_OF_KEY_WORDS = 8
NUMBER_OF_PREKEY_WORDS = 132
DEFAULT_KEY_BIT_SIZE = 256
DEFAULT_NUMBER_OF_ROUNDS = 32

VALID_KEY_BIT_SIZES = (128, 192, 256)

# Fractional part of the golden ratio, used by the key schedule.
PHI = 0x9E3779B9


PARAMETERS_CONFIGURATION_LIST = [
    {
        "key_bit_size": 128,
        "number_of_rounds": 32,
    },
    {
        "key_bit_size": 192,
        "number_of_rounds": 32,
    },
    {
        "key_bit_size": 256,
        "number_of_rounds": 32,
    },
]


# Serpent S-boxes S0, ..., S7.
SBOXES = [
    [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],
    [15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4],
    [8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2],
    [0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14],
    [1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13],
    [15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1],
    [7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0],
    [1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6],
]

def get_reversed_byte_positions(bit_size):
    """Return the bit positions that reverse the byte order."""
    return [
        bit_index
        for byte_index in reversed(range(bit_size // 8))
        for bit_index in range(
            byte_index * 8,
            (byte_index + 1) * 8,
        )
    ]


class SerpentBlockCipher(Cipher):
    """
    Return a cipher object of the Serpent Block Cipher.

    Serpent is a 128-bit block cipher supporting 128-bit, 192-bit and
    256-bit keys. The standard cipher uses 32 rounds, while this
    implementation also supports reduced-round variants from 1 to 32 rounds.

    The implementation follows the bitslice description of Serpent. The
    128-bit state is represented as four 32-bit words. Each round applies
    key mixing, 32 parallel copies of a 4-bit S-box and, except for the final
    round, the Serpent linear transformation.

    The key schedule expands the user key into 132 32-bit prekey words and
    generates 33 round keys. Keys shorter than 256 bits are extended by
    appending one bit equal to 1 followed by zero bits.

    REFERENCES:

    Anderson, R., Biham, E., & Knudsen, L. (1998). *Serpent: A Proposal for
    the Advanced Encryption Standard*. [ABK1998]_

    INPUT:

    - ``key_bit_size`` -- **integer** (default: `256`); key size in bits
    (128, 192, or 256)
    - ``number_of_rounds`` -- **integer** (default: `32`); number of rounds
    from 1 to 32

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.serpent_block_cipher import SerpentBlockCipher
        sage: serpent = SerpentBlockCipher(key_bit_size=256)
        sage: key = 0x8000000000000000000000000000000000000000000000000000000000000000
        sage: plaintext = 0x00000000000000000000000000000000
        sage: ciphertext = 0xA223AA1288463C0E2BE38EBD825616C0
        sage: serpent.evaluate([key, plaintext]) == ciphertext
        True
    """

    def __init__(
        self,
        key_bit_size=DEFAULT_KEY_BIT_SIZE,
        number_of_rounds=DEFAULT_NUMBER_OF_ROUNDS,
    ):
        if key_bit_size not in VALID_KEY_BIT_SIZES:
            raise ValueError(
                "Incorrect key_bit_size: expected 128, 192 or 256."
            )

        if not 1 <= number_of_rounds <= DEFAULT_NUMBER_OF_ROUNDS:
            raise ValueError(
                "Incorrect number_of_rounds: expected a value from 1 to 32."
            )

        self.block_bit_size = BLOCK_BIT_SIZE
        self.key_bit_size = key_bit_size
        self.number_of_requested_rounds = number_of_rounds

        super().__init__(
            family_name="serpent",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_KEY, INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[
                self.key_bit_size,
                self.block_bit_size,
            ],
            cipher_output_bit_size=self.block_bit_size,
        )

        # Open the first CLAASP round.
        # The complete key schedule and encryption round 0 are represented here.
        self.add_round()

        internal_key = self.add_intermediate_output_component(
            [INPUT_KEY],
            [get_reversed_byte_positions(self.key_bit_size)],
            self.key_bit_size,
            "internal_key",
        ).id

        prekeys = self._get_initial_key_words(internal_key)

        for index in range(NUMBER_OF_PREKEY_WORDS):
            prekeys.append(self._add_prekey_word(prekeys, index))

        round_keys = []

        for round_index in range(self.number_of_requested_rounds + 1):
            round_keys.append(
                self._add_round_key(prekeys, round_index)
            )

        state = self.add_intermediate_output_component(
            [INPUT_PLAINTEXT],
            [get_reversed_byte_positions(BLOCK_BIT_SIZE)],
            BLOCK_BIT_SIZE,
            "internal_plaintext",
        ).id

        for round_index in range(self.number_of_requested_rounds):
            # Round 0 has already been opened before the key schedule.
            if round_index > 0:
                self.add_round()

            # Key mixing: state XOR Ki.
            state = self.add_xor_component(
                [state, round_keys[round_index]],
                [
                    list(range(BLOCK_BIT_SIZE)),
                    list(range(BLOCK_BIT_SIZE)),
                ],
                BLOCK_BIT_SIZE,
            ).id

            # Round i uses S(i mod 8).
            state = self._add_sbox_layer(
                state,
                sbox_index=round_index % 8,
                round_index=round_index,
            )

            if round_index == self.number_of_requested_rounds - 1:
                # In the final round, replace the linear transformation
                # with the last key-mixing operation.
                state = self.add_xor_component(
                    [state, round_keys[round_index + 1]],
                    [
                        list(range(BLOCK_BIT_SIZE)),
                        list(range(BLOCK_BIT_SIZE)),
                    ],
                    BLOCK_BIT_SIZE,
                ).id

                self.add_cipher_output_component(
                    [state],
                    [get_reversed_byte_positions(BLOCK_BIT_SIZE)],
                    BLOCK_BIT_SIZE,
                )

            else:
                state = self._add_linear_transformation(state)

    def _get_initial_key_words(self, key_id):
        """
        Return the eight initial 32-bit words w[-8], ..., w[-1].

        Short keys are extended by appending one bit equal to 1,
        followed by zero bits up to 256 bits.
        """
        user_key_word_count = self.key_bit_size // WORD_BIT_SIZE
        key_words = []

        for word_index in range(NUMBER_OF_KEY_WORDS):
            if word_index < user_key_word_count:
                # Read user-key words starting from the least significant word.
                start = (
                    self.key_bit_size
                    - WORD_BIT_SIZE * (word_index + 1)
                )

                key_words.append(
                    (
                        key_id,
                        list(range(start, start + WORD_BIT_SIZE)),
                    )
                )
            else:
                # The first word after the user key contains the padding bit 1.
                value = 1 if word_index == user_key_word_count else 0

                constant = self.add_constant_component(
                    WORD_BIT_SIZE,
                    value,
                )

                key_words.append(
                    (
                        constant.id,
                        list(range(WORD_BIT_SIZE)),
                    )
                )

        return key_words

    def _add_prekey_word(self, prekeys, index):
        """
        Add one 32-bit Serpent prekey word.

        wi = ROTL11(
            wi-8 XOR wi-5 XOR wi-3 XOR wi-1 XOR PHI XOR i
        )
        """
        source_words = [
            prekeys[index],
            prekeys[index + 3],
            prekeys[index + 5],
            prekeys[index + 7],
        ]

        phi_component = self.add_constant_component(
            WORD_BIT_SIZE,
            PHI,
        )

        index_component = self.add_constant_component(
            WORD_BIT_SIZE,
            index,
        )

        xor_component = self.add_xor_component(
            [word[0] for word in source_words]
            + [phi_component.id, index_component.id],
            [word[1] for word in source_words]
            + [
                list(range(WORD_BIT_SIZE)),
                list(range(WORD_BIT_SIZE)),
            ],
            WORD_BIT_SIZE,
        )

        rotated_component = self.add_rotate_component(
            [xor_component.id],
            [list(range(WORD_BIT_SIZE))],
            WORD_BIT_SIZE,
            -11,
        )

        return rotated_component.id, list(range(WORD_BIT_SIZE))

    def _add_round_key(self, prekeys, round_index):
        """
        Generate one 128-bit Serpent round key from four prekey words.
        """
        first_word_index = NUMBER_OF_KEY_WORDS + 4 * round_index

        source_words = prekeys[
            first_word_index:first_word_index + 4
        ]

        sbox_index = (3 - round_index) % 8
        sbox_outputs = []

        # CLAASP interprets the first selected bit as the most significant
        # S-box input bit, while Serpent's first word provides the least
        # significant input bit.
        reversed_source_words = list(reversed(source_words))

        for bit_index in range(WORD_BIT_SIZE):
            sbox_component = self.add_sbox_component(
                [word[0] for word in reversed_source_words],
                [[bit_index] for _ in reversed_source_words],
                4,
                SBOXES[sbox_index],
            )

            sbox_outputs.append(sbox_component.id)

        round_key = self.add_round_key_output_component(
            sbox_outputs * 4,
            [
                [output_bit]
                for output_bit in range(4)
                for _ in range(WORD_BIT_SIZE)
            ],
            BLOCK_BIT_SIZE,
        )

        return round_key.id

    def _add_sbox_layer(self, state_id, sbox_index, round_index):
        """
        Apply 32 parallel copies of one Serpent S-box.
        """
        sbox_outputs = []

        for bit_index in range(WORD_BIT_SIZE):
            sbox_component = self.add_sbox_component(
                [state_id, state_id, state_id, state_id],
                [
                    [bit_index],
                    [WORD_BIT_SIZE + bit_index],
                    [2 * WORD_BIT_SIZE + bit_index],
                    [3 * WORD_BIT_SIZE + bit_index],
                ],
                4,
                SBOXES[sbox_index],
            )

            sbox_outputs.append(sbox_component.id)

        sbox_output = self.add_intermediate_output_component(
            sbox_outputs * 4,
            [
                [output_bit]
                for output_bit in range(4)
                for _ in range(WORD_BIT_SIZE)
            ],
            BLOCK_BIT_SIZE,
            f"sbox_output_{round_index}",
        )

        return sbox_output.id

    def _add_linear_transformation(self, state_id):
        """
        Apply the Serpent linear transformation.

        The 128-bit state is stored as:

            X3 | X2 | X1 | X0

        where X0 is the least significant 32-bit word.
        """

        def get_word(word_index):
            start = WORD_BIT_SIZE * (3 - word_index)

            return (
                state_id,
                list(range(start, start + WORD_BIT_SIZE)),
            )

        def rotate_left(word, amount):
            component = self.add_rotate_component(
                [word[0]],
                [word[1]],
                WORD_BIT_SIZE,
                -amount,
            )

            return component.id, list(range(WORD_BIT_SIZE))

        def shift_left(word, amount):
            component = self.add_shift_component(
                [word[0]],
                [word[1]],
                WORD_BIT_SIZE,
                -amount,
            )

            return component.id, list(range(WORD_BIT_SIZE))

        def xor_words(*words):
            component = self.add_xor_component(
                [word[0] for word in words],
                [word[1] for word in words],
                WORD_BIT_SIZE,
            )

            return component.id, list(range(WORD_BIT_SIZE))

        x0 = get_word(0)
        x1 = get_word(1)
        x2 = get_word(2)
        x3 = get_word(3)

        x0 = rotate_left(x0, 13)
        x2 = rotate_left(x2, 3)

        x1 = xor_words(x1, x0, x2)

        x0_shift_3 = shift_left(x0, 3)
        x3 = xor_words(x3, x2, x0_shift_3)

        x1 = rotate_left(x1, 1)
        x3 = rotate_left(x3, 7)

        x0 = xor_words(x0, x1, x3)

        x1_shift_7 = shift_left(x1, 7)
        x2 = xor_words(x2, x3, x1_shift_7)

        x0 = rotate_left(x0, 5)
        x2 = rotate_left(x2, 22)

        round_output = self.add_round_output_component(
            [x3[0], x2[0], x1[0], x0[0]],
            [x3[1], x2[1], x1[1], x0[1]],
            BLOCK_BIT_SIZE,
        )

        return round_output.id