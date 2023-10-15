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

PARAMETERS_CONFIGURATION_LIST = [{'iv_bit_size': 80, 'key_bit_size': 80, 'state_bit_size': 177,
                                  'number_of_initialization_clocks': 4*177, 'keystream_bit_len': 2 ** 8}]

NLFSR_DESCR = [
    [
        [93, [[93], [108], [24], [94, 95]]],  # Register_1: len=93, feedback poly = s_93+ s_108 + s_24 + s_94*s_95
        [84, [[0], [99], [27], [1, 2]]],  # Register_2: len=84, feedback poly = s_0+ s_99 + s_27 + s_1*s_2
    ],
    1  # Registers' cell size = 1-bit
]


class BiviumStreamCipher(Cipher):
    """
         Return a cipher object of Bivium Stream Cipher.

        INPUT:
        - ``keystream_bit_len`` -- **integer** (default: `256`); number of clocks of the cipher.
        - ``key_bit_size`` --  fix 80-bit;
        - ``iv_bit_size`` --   fix 80-bit;

        EXAMPLES::

        sage: from claasp.ciphers.stream_ciphers.bivium_stream_cipher import BiviumStreamCipher
        sage: biv = BiviumStreamCipher(keystream_bit_len = 2**8)
        sage: key = 0xffffffffffffffffffff
        sage: iv = 0xffffffffffffffffffff
        sage: ks = 0x30d0e5ede563dee67884718977510a4c22661cf128d8f75af4a2708276014d83
        sage: biv.evaluate([key, iv]) == ks
        True

        sage: key = 0xffffffffff0000000000
        sage: iv = 0xffffffffff
        sage: ks = 0xdebe55784f853606399af3f6f4b8d0a706963a91f2ba4c687baea16da074f3c3
        sage: biv.evaluate([key, iv]) == ks
        True

    """
    def __init__(self, iv_bit_size=80, key_bit_size=80, state_bit_size=177, number_of_initialization_clocks=4*177,
                 keystream_bit_len=2 ** 8):
        self.state_bit_size = state_bit_size
        self.key_bit_size = key_bit_size
        self.iv_bit_size = iv_bit_size
        self.number_of_initialization_clocks = number_of_initialization_clocks

        super().__init__(family_name="bivium_stream_cipher",
                         cipher_type="stream_cipher",
                         cipher_inputs=[INPUT_KEY, INPUT_INITIALIZATION_VECTOR],
                         cipher_inputs_bit_size=[key_bit_size, iv_bit_size],
                         cipher_output_bit_size=keystream_bit_len)

        iv = [INPUT_INITIALIZATION_VECTOR], [list(range(self.iv_bit_size))]
        key = [INPUT_KEY], [list(range(self.key_bit_size))]

        biv_state = self.bivium_state_initialization(key, iv)
        key_stream = []
        for clock_number in range(self._get_len_of_keystream(keystream_bit_len)):
            self.add_round()
            key_stream = self.bivium_key_stream(biv_state, clock_number, key_stream)
            biv_state = self.add_FSR_component([biv_state], [list(range(self.state_bit_size))],
                                               self.state_bit_size, NLFSR_DESCR).id

        self.add_cipher_output_component([key_stream], [list(range(self._get_len_of_keystream(keystream_bit_len)))],
                                         self._get_len_of_keystream(keystream_bit_len))

    def _get_len_of_keystream(self, keystream_bit_len):
        if keystream_bit_len is not None:
            return keystream_bit_len
        configuration_keystream_bit_len = None
        for parameters in PARAMETERS_CONFIGURATION_LIST:
            if parameters['iv_bit_size'] == self.iv_bit_size and parameters['key_bit_size'] == self.key_bit_size \
                    and parameters['state_bit_size'] == self.state_bit_size:
                configuration_keystream_bit_len = parameters['keystream_bit_len']
                break
        if configuration_keystream_bit_len is None:
            raise ValueError("No available number of clock for the given parameters.")
        return configuration_keystream_bit_len

    def bivium_state_initialization(self, key, iv):
        self.add_round()
        cst0 = self.add_constant_component(13, 0x00000).id
        state0_id = [cst0] + key[0] + [cst0] + iv[0]
        state0_pos = [list(range(13)), list(range(self.key_bit_size)), list(range(4)), list(range(self.iv_bit_size))]
        biv_state = self.add_FSR_component(state0_id, state0_pos, self.state_bit_size, NLFSR_DESCR).id
        biv_state = self.add_FSR_component([biv_state], [list(range(self.state_bit_size))],
                                           self.state_bit_size,
                                           NLFSR_DESCR + [self.number_of_initialization_clocks - 1]).id

        return biv_state

    def bivium_key_stream(self, state, clock_number, ks):
        z = self.add_XOR_component([state, state, state, state], [[0], [27], [93], [108]], 1).id
        if clock_number == 0:
            ks = self.add_round_output_component([z], [list(range(1))], 1).id
        else:
            ks = self.add_round_output_component([ks, z], [list(range(clock_number)), [0]], clock_number + 1).id
        return ks
