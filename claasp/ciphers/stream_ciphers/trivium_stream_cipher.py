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
from claasp.name_mappings import INPUT_KEY, INPUT_INITIALIZATION_VECTOR

PARAMETERS_CONFIGURATION_LIST = [
    {
        "iv_bit_size": 80,
        "key_bit_size": 80,
        "state_bit_size": 288,
        "number_of_initialization_clocks": 1152,
        "keystream_bit_len": 2**9,
    }
]

NLFSR_DESCR = [
    [
        [93, [[177], [24], [222], [178, 179]]],  # Register_1: len=93, feedback poly = s_177+ s_24 + s_222 + s_178*s_179
        [84, [[0], [99], [27], [1, 2]]],  # Register_2: len=84, feedback poly = s_0+ s_99 + s_27 + s_1*s_2
        [111, [[93], [108], [201], [94, 95]]],  # Register_3: len=111, feedback poly = s_93+ s_108 + s_201 + s_94*s_95
    ],
    1,  # Registers' cell size = 1-bit
]


class TriviumStreamCipher(Cipher):
    """
    Return a cipher object of Trivium Stream Cipher.

    INPUT:
        - ``keystream_bit_len`` -- **integer** (default: `512`); number of keystream clocks of the cipher.
        - ``initialization_vector_bit_size`` --   fix 80-bit;
        - ``key_bit_size`` --  fix 80-bit;


    EXAMPLES::

        sage: from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher
        sage: triv = TriviumStreamCipher(keystream_bit_len=2**8)
        sage: key = 0x00000000000000000000
        sage: iv = 0x00000000000000000000
        sage: ks=0xdf07fd641a9aa0d88a5e7472c4f993fe6a4cc06898e0f3b4e7159ef0854d97b3
        sage: triv.evaluate([key, iv]) == ks
        True
    """

    def __init__(
        self,
        iv_bit_size=80,
        key_bit_size=80,
        state_bit_size=288,
        number_of_initialization_clocks=1152,
        keystream_bit_len=512,
    ):
        self.iv_bit_size = iv_bit_size
        self.key_bit_size = key_bit_size
        self.state_bit_size = state_bit_size
        self.number_of_initialization_clocks = number_of_initialization_clocks

        super().__init__(
            family_name="trivium_stream_cipher",
            cipher_type="stream_cipher",
            cipher_inputs=[INPUT_KEY, INPUT_INITIALIZATION_VECTOR],
            cipher_inputs_bit_size=[key_bit_size, iv_bit_size],
            cipher_output_bit_size=keystream_bit_len,
        )

        iv = [INPUT_INITIALIZATION_VECTOR], [list(range(self.iv_bit_size))]
        key = [INPUT_KEY], [list(range(self.key_bit_size))]
        key_stream = []
        self.add_round()
        triv_state = self.trivium_state_initialization(key, iv)

        for clock_number in range(self.get_keystream_bit_len(keystream_bit_len)):
            self.add_round()
            key_stream = self.trivium_key_stream(triv_state, clock_number, key_stream)
            triv_state = self.add_FSR_component(
                [triv_state], [list(range(self.state_bit_size))], state_bit_size, NLFSR_DESCR
            ).id

        self.add_cipher_output_component(
            [key_stream],
            [list(range(self.get_keystream_bit_len(keystream_bit_len)))],
            self.get_keystream_bit_len(keystream_bit_len),
        )

    def get_keystream_bit_len(self, keystream_bit_len):
        if keystream_bit_len is not None:
            return keystream_bit_len
        len_keystream = None
        for items in PARAMETERS_CONFIGURATION_LIST:
            if (
                items["iv_bit_size"] == self.iv_bit_size
                and items["key_bit_len"] == self.key_bit_size
                and items["state_bit_size"] == self.state_bit_size
            ):
                len_keystream = items["keystream_bit_len"]
                break
        if len_keystream is None:
            raise ValueError("No available length of keystream .")
        return len_keystream

    def trivium_state_initialization(self, key, iv):
        cst0 = self.add_constant_component(13, 0x0).id
        cst1 = self.add_constant_component(111, 0xE000000000000000000000000000).id

        state0_id = [cst0] + key[0] + [cst0] + iv[0] + [cst1]
        state0_pos = [
            list(range(13)),
            list(range(self.key_bit_size)),
            list(range(4)),
            list(range(self.iv_bit_size)),
            list(range(111)),
        ]
        triv_state = self.add_FSR_component(state0_id, state0_pos, self.state_bit_size, NLFSR_DESCR).id
        triv_state = self.add_FSR_component(
            [triv_state],
            [list(range(self.state_bit_size))],
            self.state_bit_size,
            NLFSR_DESCR + [self.number_of_initialization_clocks - 1],
        ).id
        return triv_state

    def trivium_key_stream(self, state, clock_number, key_stream):
        k_bits_id = [state, state, state, state, state, state]
        k_bits_pos = [[0], [27], [93], [108], [177], [222]]
        key_stream_bit = self.add_XOR_component(k_bits_id, k_bits_pos, 1).id
        if clock_number == 0:
            key_stream = self.add_round_output_component([key_stream_bit], [[0]], 1).id
        else:
            key_stream = self.add_round_output_component(
                [key_stream, key_stream_bit], [list(range(clock_number)), [0]], clock_number + 1
            ).id
        return key_stream
