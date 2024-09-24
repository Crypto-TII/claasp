
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
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY

PARAMETERS_CONFIGURATION_LIST = [
    {'block_bit_size': 128, 'key_bit_size': 128, 'r': 46},
    {'block_bit_size': 128, 'key_bit_size': 256, 'r': 48},
    {'block_bit_size': 256, 'key_bit_size': 256, 'r': 74},
]

class BalletBlockCipher(Cipher):
    """
    Construct an instance of the BalletBlockCipher class.
    Reference: http://www.jcr.cacrnet.org.cn/EN/10.13868/j.cnki.jcr.000335

    Following are some testing vectors:
    1. Ballet 128/128
    plaintext = 0xe60e830ca56ec84814fbd2579993d435
    key = 0xcd52c514213c9632514fb60a64840881
    ciphertext = 0xc1c2e89c1581d166f3c87b5999f87a9f

    2. Ballet 128/256
    plaintext = 0xc419afdd747886b9f8e6890a3db19fa3
    key = 0x8e1d7bede15b5fae9e67b09c734829149b5e7f8d02f49fccaa1437574d9f792b
    ciphertext = 0x636f07e9df66d2ec34d0ad3bb87e0f79

    3. Ballet 256/256
    plaintext = 0xfdc0bf9c6bfeb2ffd160128e5190af6cdad291114d953986de472ad8be6ea8c7
    key = 0x19f29ab90c31da41d2013ed7128338ad7eacb494fae0572801c30948454cb1ca
    ciphertext = 0x2d07ee91d634c27f3155f9e575bdc634acaa611e3654c4ce06ea130e9bc394ee

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `128`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `128`); cipher round_key bit size of the cipher
    - ``r`` -- **integer** (default: `0`); number of rounds of the cipher. The cipher uses the
      corresponding amount given the other parameters (if available) when r is 0

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.ballet_block_cipher import BalletBlockCipher
        sage: ballet = BalletBlockCipher()
        sage: ballet.number_of_rounds
        46

        sage: ballet.component_from(0, 0).id
        'xor_0_0'
    """

    def __init__(self, block_bit_size=128, key_bit_size=128, number_of_rounds=0):
        self.block_bit_size = block_bit_size
        self.key_bit_size = key_bit_size
        self.quater_block_bit_size = int(self.block_bit_size / 4)
        self.round_key_bit_size = int(self.block_bit_size / 2)
        self.r = number_of_rounds

        error = self.check_parameters()
        if error == 1:
            return

        super().__init__(family_name="ublock",
                         cipher_type="block_cipher",
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                         cipher_inputs_bit_size=[self.block_bit_size, self.key_bit_size],
                         cipher_output_bit_size=self.block_bit_size)

        if self.block_bit_size == self.key_bit_size:
            state_0, state_1, state_2, state_3, key_0, key_1 = self.round_initialization()
        else:
            state_0, state_1, state_2, state_3, key_0, key_1, t_0, t_1 = self.round_initialization()

        for round_number in range(self.r):
            self.add_round()

            if round_number == self.r-1:
                # encryption
                state_0, state_1, state_2, state_3 = self.round_function(state_0, state_1, state_2, state_3, key_0,
                                                                         last_round=True)
                # round output
                self.add_round_key_output_component(key_0.id, key_0.input_bit_positions, int(self.block_bit_size / 2))
                self.add_cipher_output_component(state_0.id + state_1.id + state_2.id + state_3.id,
                                                state_0.input_bit_positions + state_1.input_bit_positions + state_2.input_bit_positions + state_3.input_bit_positions,
                                                self.block_bit_size)
            else:
                # encryption
                state_0, state_1, state_2, state_3 = self.round_function(state_0, state_1, state_2, state_3, key_0, last_round=False)
                # round output
                self.add_round_key_output_component(key_0.id, key_0.input_bit_positions, int(self.block_bit_size/2))
                self.add_round_output_component(state_0.id + state_1.id + state_2.id + state_3.id,
                                                state_0.input_bit_positions + state_1.input_bit_positions + state_2.input_bit_positions + state_3.input_bit_positions,
                                                self.block_bit_size)
                # round_key schedule
                if self.block_bit_size == self.key_bit_size:
                    key_0, key_1 = self.key_schedule_nn(key_0, key_1, round_number)
                else:
                    key_0, key_1, t_0, t_1 = self.key_schedule_n2n(key_0, key_1, t_0, t_1, round_number)

    def check_parameters(self):
        if self.block_bit_size == 128:
            if self.key_bit_size == 128:
                if self.r == 0:
                    self.r = 46
            elif self.key_bit_size == 256:
                if self.r == 0:
                    self.r = 48
            else:
                print("The round_key size of block size 128 should be 128 or 256.")
                return 1
        elif self.block_bit_size == 256:
            if self.key_bit_size == 256:
                if self.r == 0:
                    self.r = 74
            else:
                print("The round_key size of block size 256 should be 256.")
                return 1
        else:
            print("The block size should be 128 or 256.")
            return 1
        return 0

    def round_initialization(self):
        state_0 = ComponentState([INPUT_PLAINTEXT], [list(range(self.quater_block_bit_size))])
        state_1 = ComponentState([INPUT_PLAINTEXT], [list(range(self.quater_block_bit_size, self.quater_block_bit_size*2))])
        state_2 = ComponentState([INPUT_PLAINTEXT], [list(range(self.quater_block_bit_size*2, self.quater_block_bit_size*3))])
        state_3 = ComponentState([INPUT_PLAINTEXT], [list(range(self.quater_block_bit_size*3, self.block_bit_size))])

        if self.block_bit_size == self.key_bit_size:
            key_0 = ComponentState([INPUT_KEY], [list(range(self.round_key_bit_size))])
            key_1 = ComponentState([INPUT_KEY], [list(range(self.round_key_bit_size, self.key_bit_size))])
            return state_0, state_1, state_2, state_3, key_0, key_1
        else:
            key_0 = ComponentState([INPUT_KEY], [list(range(self.round_key_bit_size))])
            key_1 = ComponentState([INPUT_KEY], [list(range(self.round_key_bit_size, self.round_key_bit_size*2))])
            t_0 = ComponentState([INPUT_KEY], [list(range(self.round_key_bit_size*2, self.round_key_bit_size*3))])
            t_1 = ComponentState([INPUT_KEY], [list(range(self.round_key_bit_size*3, self.key_bit_size))])
            return state_0, state_1, state_2, state_3, key_0, key_1, t_0, t_1

    def round_function(self, state_0, state_1, state_2, state_3, round_key, last_round=False):

        # state' = state_1 xor state_2
        self.add_XOR_component(state_1.id + state_2.id,
                               state_1.input_bit_positions + state_2.input_bit_positions,
                               self.quater_block_bit_size)
        state_temp = ComponentState([self.get_current_component_id()], [list(range(self.quater_block_bit_size))])

        # state_0_new = state_1 xor round_key_left
        self.add_XOR_component(state_1.id + round_key.id,
                               state_1.input_bit_positions + [list(range(self.quater_block_bit_size))],
                               self.quater_block_bit_size)
        state_0_new = ComponentState([self.get_current_component_id()], [list(range(self.quater_block_bit_size))])

        # state_1_new = (state_0 <<< 6) modadd (state' <<< 9)
        self.add_rotate_component(state_0.id, state_0.input_bit_positions, self.quater_block_bit_size, -6)
        state_temp_1 = ComponentState([self.get_current_component_id()], [list(range(self.quater_block_bit_size))])
        self.add_rotate_component(state_temp.id, state_temp.input_bit_positions, self.quater_block_bit_size, -9)
        state_temp_2 = ComponentState([self.get_current_component_id()], [list(range(self.quater_block_bit_size))])
        self.add_MODADD_component(state_temp_1.id+state_temp_2.id,
                                  state_temp_1.input_bit_positions+state_temp_2.input_bit_positions,
                                  self.quater_block_bit_size)
        state_1_new = ComponentState([self.get_current_component_id()], [list(range(self.quater_block_bit_size))])

        # state_2_new = (state_3 <<< 15) modadd (state' <<< 14)
        self.add_rotate_component(state_3.id, state_3.input_bit_positions, self.quater_block_bit_size, -15)
        state_temp_1 = ComponentState([self.get_current_component_id()], [list(range(self.quater_block_bit_size))])
        self.add_rotate_component(state_temp.id, state_temp.input_bit_positions, self.quater_block_bit_size, -14)
        state_temp_2 = ComponentState([self.get_current_component_id()], [list(range(self.quater_block_bit_size))])
        self.add_MODADD_component(state_temp_1.id + state_temp_2.id,
                                  state_temp_1.input_bit_positions + state_temp_2.input_bit_positions,
                                  self.quater_block_bit_size)
        state_2_new = ComponentState([self.get_current_component_id()], [list(range(self.quater_block_bit_size))])

        # state_3_new = state_2 xor round_key_right
        self.add_XOR_component(state_2.id + round_key.id,
                               state_2.input_bit_positions + [list(range(self.quater_block_bit_size, self.round_key_bit_size))],
                               self.quater_block_bit_size)
        state_3_new = ComponentState([self.get_current_component_id()], [list(range(self.quater_block_bit_size))])


        if last_round:
            return state_1_new, state_0_new, state_3_new, state_2_new
        else:
            return state_0_new, state_1_new, state_2_new, state_3_new

    def key_schedule_nn(self, key_0, key_1, RC):
        # key_1_new = key_0 xor (key_1 <<< 3) xor (key_1 <<< 5) xor RC
        # key_0_new = key_1
        self.add_rotate_component(key_1.id, key_1.input_bit_positions, self.round_key_bit_size, -3)
        key_temp_1 = ComponentState([self.get_current_component_id()], [list(range(self.round_key_bit_size))])
        self.add_rotate_component(key_1.id, key_1.input_bit_positions, self.round_key_bit_size, -5)
        key_temp_2 = ComponentState([self.get_current_component_id()], [list(range(self.round_key_bit_size))])
        self.add_constant_component(self.round_key_bit_size, RC)
        round_constant = ComponentState([self.get_current_component_id()], [list(range(self.round_key_bit_size))])
        self.add_XOR_component(key_0.id + key_temp_1.id + key_temp_2.id + round_constant.id,
                               key_0.input_bit_positions + key_temp_1.input_bit_positions + key_temp_2.input_bit_positions + round_constant.input_bit_positions,
                               self.round_key_bit_size)
        key_1_new = ComponentState([self.get_current_component_id()], [list(range(self.round_key_bit_size))])

        return key_1, key_1_new

    def key_schedule_n2n(self, key_0, key_1, t_0, t_1, RC):
        # t_1_new = t_0 xor (t_1 <<< 7) xor (t_1 <<< 17)
        # t_0_new = t_1
        self.add_rotate_component(t_1.id, t_1.input_bit_positions, self.round_key_bit_size, -7)
        t_temp_1 = ComponentState([self.get_current_component_id()], [list(range(self.round_key_bit_size))])
        self.add_rotate_component(t_1.id, t_1.input_bit_positions, self.round_key_bit_size, -17)
        t_temp_2 = ComponentState([self.get_current_component_id()], [list(range(self.round_key_bit_size))])
        self.add_XOR_component(t_0.id + t_temp_1.id + t_temp_2.id,
                               t_0.input_bit_positions + t_temp_1.input_bit_positions + t_temp_2.input_bit_positions,
                               self.round_key_bit_size)
        t_1_new = ComponentState([self.get_current_component_id()], [list(range(self.round_key_bit_size))])

        # key_1_new = key_0 xor (key_1 <<< 3) xor (key_1 <<< 5)
        # key_0_new = key_1
        self.add_rotate_component(key_1.id, key_1.input_bit_positions, self.round_key_bit_size, -3)
        key_temp_1 = ComponentState([self.get_current_component_id()], [list(range(self.round_key_bit_size))])
        self.add_rotate_component(key_1.id, key_1.input_bit_positions, self.round_key_bit_size, -5)
        key_temp_2 = ComponentState([self.get_current_component_id()], [list(range(self.round_key_bit_size))])
        self.add_XOR_component(key_0.id + key_temp_1.id + key_temp_2.id,
                               key_0.input_bit_positions + key_temp_1.input_bit_positions + key_temp_2.input_bit_positions,
                               self.round_key_bit_size)
        key_1_new = ComponentState([self.get_current_component_id()], [list(range(self.round_key_bit_size))])

        # key_1_new = key_1_new xor t_1_new xor RC
        self.add_constant_component(self.round_key_bit_size, RC)
        round_constant = ComponentState([self.get_current_component_id()], [list(range(self.round_key_bit_size))])
        self.add_XOR_component(key_1_new.id + t_1_new.id + round_constant.id,
                               key_1_new.input_bit_positions + t_1_new.input_bit_positions + round_constant.input_bit_positions,
                               self.round_key_bit_size)
        key_1_new = ComponentState([self.get_current_component_id()], [list(range(self.round_key_bit_size))])

        return key_1, key_1_new, t_1, t_1_new