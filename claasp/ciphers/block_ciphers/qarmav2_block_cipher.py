
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
from claasp.name_mappings import INPUT_KEY, INPUT_PLAINTEXT, INPUT_TWEAK

PARAMETERS_CONFIGURATION_LIST = [{'number_of_rounds': 10, 'number_of_layers': 1, 'key_bit_size': 128, 'tweak_bit_size': 0}]


class QARMAV2BlockCipher(Cipher):
    """
    Return a cipher object of Qarma v2 Block Cipher.

    INPUT:

    - ``number_of_rounds`` -- **integer** (default: `10`); number of rounds of the cipher. Must be greater or equal than 1.
    - ``number_of_layers`` -- **integer** (default: `1`); number of layers of the state represented as matrices. Must be equal to 1 or 2.
    - ``key_bit_size``     -- **integer** (default: `128`); length of the key in bits. If number_of_layers=1 it must be equal to 128, otherwise it must be equal to 128, 192 or 256.
    - ``tweak_bit_size``   -- **integer** (default: `0`); length of the tweak in bits.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.qarmav2_block_cipher import QARMAV2BlockCipher
        sage: qarmav2 = QARMAV2BlockCipher()
        sage: key = 0x2b7e151628aed2a6abf7158809cf4f3c
        sage: plaintext = 0x6bc1bee22e409f96e93d7e117393172a
        sage: ciphertext = 0x3ad77bb40d7a3660a89ecaf32466ef97
        sage: qarmav2.evaluate([key, plaintext]) == ciphertext
        True
    """

    def __init__(self, number_of_rounds=10, number_of_layers=1, key_bit_size=128, tweak_bit_size=0):

        if number_of_layers not in [1, 2]:
            raise ValueError("number_of_layers incorrect (should be in [1,2])")
        if number_of_rounds < 1:
            raise ValueError("number_of_rounds incorrect (should be at least 1)")
        if key_bit_size != 128 and number_of_layers==1 or key_bit_size not in [128, 192, 256] and number_of_layers==2:
            raise ValueError("key_bit_size incorrect (should be 128 with 1 layer and 128, 192 or 256 with 2 layers)")
        if tweak_bit_size < 0:
            raise ValueError("tweak_bit_size incorrect (should be at least 0)")

        # cipher dictionary initialize
        self.CIPHER_BLOCK_SIZE = 64 * number_of_layers
        self.LAYER_BLOCK_SIZE = 64
        self.KEY_BLOCK_SIZE = self.CIPHER_BLOCK_SIZE
        self.TWEAK_BLOCK_SIZE = self.CIPHER_BLOCK_SIZE
        self.NROUNDS = number_of_rounds
        self.WORD_SIZE = 4
        self.SBOX_BIT_SIZE = self.WORD_SIZE
        self.NUM_SBOXES = 16 * number_of_layers
        self.NUM_ROWS = 4
        self.ROW_SIZE = 4

        super().__init__(family_name="qarmav2_block_cipher",
                         cipher_type="block_cipher",
                         cipher_inputs=[INPUT_KEY, INPUT_PLAINTEXT, INPUT_TWEAK],
                         cipher_inputs_bit_size=[key_bit_size, self.CIPHER_BLOCK_SIZE, tweak_bit_size],
                         cipher_output_bit_size=self.CIPHER_BLOCK_SIZE)
                         
        self.state_shuffle = [
                              0, 11, 6, 13, 
                              10, 1, 12, 7, 
                              5, 14, 3, 8, 
                              15, 4, 9, 2,
                             ]
                             
        self.sbox = [
                     4, 7, 9, 11, 
                     12, 6, 14, 15, 
                     0, 5, 1, 13, 
                     8, 3, 2, 10,
                    ]
                    
        self.inverse_sbox = [self.sbox.index(i) for i in range(16)]
                    
        self.rotations_matrix = [
                            0, 1, 2, 3,
                            3, 0, 1, 2,
                            2, 3, 0, 1,
                            1, 2, 3, 0,
                           ]
                           
        self.tweak_permutations = {
                             1: [
                                 1, 10, 14, 6, 
                                 2, 9, 13, 5, 
                                 0, 8, 12, 4, 
                                 3, 11, 15, 7,
                                ],
                             2: [
                                 1, 10, 14, 22, 
                                 18, 25, 29, 21, 
                                 0, 8, 12, 4, 
                                 19, 27, 31, 23, 
                                 17, 26, 30, 6, 
                                 2, 9, 13, 5, 
                                 16, 24, 28, 20, 
                                 3, 11, 15, 7,
                                ]
                            }
                            
        lfsr_matrix = [[0 for i in range(64)] for j in range(64)]
        for i in range(63):
            lfsr_matrix[i][i+1] = 1
        lfsr_matrix[13][0] = 1
        lfsr_matrix[30][0] = 1
        lfsr_matrix[44][0] = 1
        lfsr_matrix[63][0] = 1
                            
        state_permutation = []
        for i in self.state_shuffle:
            state_permutation += list(range(4*i, 4*i + 4))
        inverse_state_permutation = [state_permutation.index(i) for i in range(self.LAYER_BLOCK_SIZE)]
            
        tweak_permutation = []
        direct_permutation=[]
        for i in self.tweak_permutations[number_of_layers]:
            direct_permutation += list(range(4*i, 4*i + 4))
        inverse_permutation = [direct_permutation.index(i) for i in range(number_of_layers*self.TWEAK_BLOCK_SIZE)]
        tweak_permutation = [inverse_permutation, direct_permutation]
        
        exchange_rows_permutation = list(range(64,96)) + list(range(32, 64)) + list(range(32)) + list(range(96, 128))
                                              
        #First round different from others
        self.add_round()
        
        #Tweak initialization
        tweak_0 = self.add_permutation_component([INPUT_TWEAK],
                                                 [[i for i in range(self.TWEAK_BLOCK_SIZE)]],
                                                 self.TWEAK_BLOCK_SIZE,
                                                 tweak_permutation[1])
        for i in range(1, number_of_rounds-1):
            perm_tweak = self.add_permutation_component([tweak_0.id],
                                                     [[i for i in range(self.TWEAK_BLOCK_SIZE)]],
                                                     self.TWEAK_BLOCK_SIZE,
                                                     tweak_permutation[1])
            tweak_0 = perm_tweak
        tweak_1 = self.add_permutation_component([INPUT_TWEAK],
                                                 [[i for i in range(self.TWEAK_BLOCK_SIZE, 2*self.TWEAK_BLOCK_SIZE)]],
                                                 self.TWEAK_BLOCK_SIZE,
                                                 [i for i in range(self.TWEAK_BLOCK_SIZE)])
        tweak_state = [tweak_0, tweak_1]
        
        #Key initialization
        key_0 = self.add_permutation_component([INPUT_KEY],
                                               [[i for i in range(self.KEY_BLOCK_SIZE)]],
                                               self.KEY_BLOCK_SIZE,
                                               [i for i in range(self.KEY_BLOCK_SIZE)])
        key_1 = self.add_permutation_component([INPUT_KEY],
                                               [[i for i in range(self.KEY_BLOCK_SIZE, 2*self.KEY_BLOCK_SIZE)]],
                                               self.KEY_BLOCK_SIZE,
                                               [i for i in range(self.KEY_BLOCK_SIZE)])
        key_state = [key_0, key_1]
        
        #Round constants initialization
        round_constant = [self.add_constant_component(self.LAYER_BLOCK_SIZE, 0)]
        if number_of_layers == 2:
            round_constant.append(self.add_constant_component(self.LAYER_BLOCK_SIZE, 0))
        round_constant_0 = self.add_constant_component(self.LAYER_BLOCK_SIZE, 0x243F6A8885A308D3)
        round_constant.append(round_constant_0)
        if number_of_layers == 2:
            round_constant_1 = self.update_constants(round_constant_0)
            round_constant.append(round_constant_1)
        for i in range(2, number_of_rounds):
            round_constant_0 = self.update_constants(round_constant[-1])
            round_constant.append(round_constant_0)
            if number_of_layers == 2:
                round_constant_1 = self.update_constants(round_constant_0)
                round_constant.append(round_constant_1)
                       
        input_bits=[]
        #for i in list(range(self.CIPHER_BLOCK_SIZE/self.WORD_SIZE))[::-1]:
        #    input_bits+=list(range(4*i, 4*i+4))
        first_round_add_round_key = self.add_XOR_component([key_state[0].id, INPUT_PLAINTEXT],
                                                           [[i for i in range(self.KEY_BLOCK_SIZE)],
                                                           list(range(self.CIPHER_BLOCK_SIZE))[::-1]],
                                                           self.CIPHER_BLOCK_SIZE)
                                                     
        first_round_sboxes = []
        for sb in range(self.NUM_SBOXES):
            sbox = self.add_SBOX_component([first_round_add_round_key.id],
                                           [[i for i in range(4*sb, 4*sb + 4)]],
                                           self.SBOX_BIT_SIZE, 
                                           self.sbox)
            first_round_sboxes.append(sbox)
            
        round_output = self.add_round_output_component([first_round_sboxes[i].id for i in range(self.NUM_SBOXES)],
                                                       [[i for i in range(self.SBOX_BIT_SIZE)] for j in range(self.NUM_SBOXES)],
                                                       self.CIPHER_BLOCK_SIZE)
               
        #Direct encryption 
        for round_number in range(1, number_of_rounds+1):
            self.add_round()
            
            round_key_shuffle = []
            for l in range(number_of_layers):
                xor = self.add_XOR_component([round_output.id, 
                                              key_state[round_number%2].id, 
                                              tweak_state[round_number%2].id, 
                                              round_constant[(round_number - 1)*number_of_layers + l].id],
                                             [[i for i in range(64*l, 64*l + 64)], 
                                              [i for i in range(64*l, 64*l + 64)], 
                                              [i for i in range(64*l, 64*l + 64)], 
                                              [i for i in range(64*l, 64*l + 64)]],
                                             self.LAYER_BLOCK_SIZE)
                round_key_shuffle.append(xor)
                
            tweak_state[round_number%2] = self.add_permutation_component([tweak_state[round_number%2].id],
                                                                         [[i for i in range(self.TWEAK_BLOCK_SIZE)]],
                                                                         self.TWEAK_BLOCK_SIZE,
                                                                         tweak_permutation[round_number%2])
                                  
            round_state_shuffle = []
            for l in range(number_of_layers):
                shuffled_state = self.add_permutation_component([round_key_shuffle[l].id],
                                                                [[i for i in range(self.LAYER_BLOCK_SIZE)]],
                                                                self.LAYER_BLOCK_SIZE,
                                                                state_permutation)
                round_state_shuffle.append(shuffled_state)
                
            round_state_rotate = []
            for l in range(number_of_layers):
                for w in range(16):
                    if self.rotations_matrix[w] == 0:
                        rotate = self.add_constant_component(4, 0)
                    else:
                        rotate = self.add_rotate_component([round_state_shuffle[l].id],
                                                           [[i for i in range(4*w, 4*w + 4)]],
                                                           self.WORD_SIZE,
                                                           -self.rotations_matrix[w])
                    round_state_rotate.append(rotate)
            
            round_sboxes = []
            for sb in range(self.NUM_SBOXES):
                sbox = self.add_SBOX_component([round_state_rotate[sb].id],
                                               [[i for i in range(4)]],
                                               self.SBOX_BIT_SIZE, 
                                               self.sbox)
                round_sboxes.append(sbox)
                                                            
            if number_of_layers == 2 and (number_of_rounds - round_numbers)%2 == 0:
                exchanging_rows = self.add_permutation_component([round_sboxes[i].id for i in range(self.NUM_SBOXES * number_of_layers)],
                                                                 [[i for i in range(self.SBOX_BIT_SIZE)] for j in range(self.NUM_SBOXES * number_of_layers)],
                                                                 self.CIPHER_BLOCK_SIZE,
                                                                 exchange_rows_permutation)
                                                 
                round_output = self.add_round_output_component([exchanging_rows.id],
                                                               [[i for i in range(self.CIPHER_BLOCK_SIZE)]],
                                                               self.CIPHER_BLOCK_SIZE)
            else:
                round_output = self.add_round_output_component([round_sboxes[i].id for i in range(self.NUM_SBOXES * number_of_layers)],
                                                               [[i for i in range(self.SBOX_BIT_SIZE)] for j in range(self.NUM_SBOXES * number_of_layers)],
                                                               self.CIPHER_BLOCK_SIZE)                              
            
        #Reflector 
        self.add_round()
        
        new_keys = self.o_function(key_state)
        key_state = new_keys
        W = self.o_function(new_keys)
        
        alpha_0 = self.add_constant_component(self.LAYER_BLOCK_SIZE, 0x13198A2E03707344)
        alpha = [alpha_0]
        if number_of_layers == 2:
            alpha_1 = self.update_constants(alpha[0])
            alpha.append(alpha_1)
        beta_0 = self.update_constants(alpha[-1])
        beta = [beta_0]
        if number_of_layers == 2:
            beta_1 = self.update_constants(beta_0)
            beta.append(beta_1)
        if number_of_layers == 2:
            key_state[0] = self.add_XOR_component([key_state[0].id, alpha[0].id, alpha[1].id],
                                                  [[i for i in range(self.KEY_BLOCK_SIZE)], [i for i in range(self.LAYER_BLOCK_SIZE)], [i for i in range(self.LAYER_BLOCK_SIZE)]],
                                                  self.KEY_BLOCK_SIZE)
            key_state[1] = self.add_XOR_component([key_state[1].id, beta[0].id, beta[1]],
                                                  [[i for i in range(self.KEY_BLOCK_SIZE)], [i for i in range(self.LAYER_BLOCK_SIZE)], [i for i in range(self.LAYER_BLOCK_SIZE)]],
                                                  self.KEY_BLOCK_SIZE)
        else:
            key_state[0] = self.add_XOR_component([key_state[0].id, alpha[0].id],
                                                  [[i for i in range(self.KEY_BLOCK_SIZE)], [i for i in range(self.LAYER_BLOCK_SIZE)]],
                                                  self.KEY_BLOCK_SIZE)
            key_state[1] = self.add_XOR_component([key_state[1].id, beta[0].id],
                                                  [[i for i in range(self.KEY_BLOCK_SIZE)], [i for i in range(self.LAYER_BLOCK_SIZE)]],
                                                  self.KEY_BLOCK_SIZE)
                                              
        
        round_state_shuffle = []
        for l in range(number_of_layers):
            shuffled_state = self.add_permutation_component([round_output.id],
                                                            [[i for i in range(64*l, 64*l + 64)]],
                                                            self.LAYER_BLOCK_SIZE,
                                                            state_permutation)
            mixed_shuffled_state = self.add_XOR_component([shuffled_state.id, W[(number_of_rounds + 1)%2].id],
                                                          [[i for i in range(self.LAYER_BLOCK_SIZE)], [i for i in range(64*l, 64*l + 64)]],
                                                          self.LAYER_BLOCK_SIZE)
            round_state_shuffle.append(mixed_shuffled_state)
                
        round_state_rotate = []
        for l in range(number_of_layers):
            for w in range(16):
                if self.rotations_matrix[w]==0:
                    rotate = self.add_constant_component(4, 0)
                else:
                    rotate = self.add_rotate_component([round_state_shuffle[l].id],
                                                       [[i for i in range(4*w, 4*w + 4)]],
                                                       self.WORD_SIZE,
                                                       -self.rotations_matrix[w])
                round_state_rotate.append(rotate)
            
        central_keyed_state = []
        for l in range(number_of_layers):
            for w in range(16):
                central_xor = self.add_XOR_component([round_state_rotate[16*l + w].id, W[(number_of_rounds)%2].id],
                                                     [[i for i in range(self.WORD_SIZE)], [i for i in range(64*l + 4*w, 64*l + 4*w + 4)]],
                                                     self.WORD_SIZE)
                central_keyed_state.append(central_xor)
        
        central_shuffled_state = []
        for l in range(number_of_layers):
            shuffled_state = self.add_permutation_component([central_keyed_state[16*l + i].id for i in range(16)],
                                                            [[i for i in range(4)] for j in range(16)],
                                                            self.LAYER_BLOCK_SIZE,
                                                            inverse_state_permutation)
            central_shuffled_state.append(shuffled_state)
            
        round_output = self.add_round_output_component([central_shuffled_state[i].id for i in range(number_of_layers)],
                                                       [[i for i in range(self.LAYER_BLOCK_SIZE)] for j in range(number_of_layers)],
                                                       self.CIPHER_BLOCK_SIZE)
                                                       
        #Inverse encryption
        for round_number in list(range(1, number_of_rounds+1))[::-1]:
        
            self.add_round()
                                         
            if number_of_layers == 2 and (number_of_rounds - round_numbers)%2 == 0:
                exchanging_rows = self.add_permutation_component([round_output.id],
                                                                 [[i for i in range(CIPHER_BLOCK_SIZE)]],
                                                                 self.CIPHER_BLOCK_SIZE,
                                                                 exchange_rows_permutation)
            else:
                exchanging_rows = round_output
                              
            round_sboxes = []
            for sb in range(self.NUM_SBOXES):
                sbox = self.add_SBOX_component([exchanging_rows.id],
                                               [[i for i in range(4*sb, 4*sb + 4)]],
                                               self.SBOX_BIT_SIZE, 
                                               self.inverse_sbox)
                round_sboxes.append(sbox)
                
            round_state_rotate = []
            for l in range(number_of_layers):
                for w in range(16):
                    if self.rotations_matrix[w]==0:
                        rotate = self.add_constant_component(4, 0)
                    else:
                        rotate = self.add_rotate_component([round_sboxes[16*l + w].id],
                                                           [[i for i in range(4)]],
                                                           self.WORD_SIZE,
                                                           self.rotations_matrix[w])
                    round_state_rotate.append(rotate)
                
            round_state_shuffle = []
            for l in range(number_of_layers):
                shuffled_state = self.add_permutation_component([round_state_rotate[16*l + i].id for i in range(16)],
                                                 [[i for i in range(4)] for j in range(16)],
                                                 self.LAYER_BLOCK_SIZE,
                                                 inverse_state_permutation)
                round_state_shuffle.append(shuffled_state)
                                
            round_key_shuffle = []
            for l in range(number_of_layers):
                xor = self.add_XOR_component([round_state_shuffle[l].id, 
                                              key_state[(round_number + 1)%2].id, 
                                              tweak_state[(round_number + 1)%2].id, 
                                              round_constant[(round_number - 1)*number_of_layers + l].id],
                                             [[i for i in range(self.LAYER_BLOCK_SIZE)], 
                                              [i for i in range(64*l, 64*l + 64)], 
                                              [i for i in range(64*l, 64*l + 64)], 
                                              [i for i in range(64*l, 64*l + 64)]],
                                             self.LAYER_BLOCK_SIZE)
                round_key_shuffle.append(xor)
                    
            tweak_state[round_number%2] = self.add_permutation_component([tweak_state[(round_number + 1)%2].id],
                                                                         [[i for i in range(self.TWEAK_BLOCK_SIZE)]],
                                                                         self.TWEAK_BLOCK_SIZE,
                                                                         tweak_permutation[(round_number + 1)%2])
                                              
            round_output = self.add_round_output_component([round_key_shuffle[i].id for i in range(number_of_layers)],
                                                       [[i for i in range(self.LAYER_BLOCK_SIZE)] for j in range(number_of_layers)],
                                                       self.CIPHER_BLOCK_SIZE)                 
                                                       
        #Last round different from others    
        self.add_round()
                                   
        last_round_sboxes = []
        for sb in range(self.NUM_SBOXES):
            sbox = self.add_SBOX_component(
                [round_output.id],
                [[i for i in range(4*sb, 4*sb + 4)]],
                self.SBOX_BIT_SIZE, 
                self.inverse_sbox)
            last_round_sboxes.append(sbox)
            
        last_round_add_round_key = []
        for sb in range(self.NUM_SBOXES):
            add_round_key = self.add_XOR_component([key_state[1].id, last_round_sboxes[sb].id],
                                                     [[i for i in range(4*sb, 4*sb + 4)],
                                                      [i for i in range(self.SBOX_BIT_SIZE)]],
                                                     self.SBOX_BIT_SIZE)
            last_round_add_round_key.append(add_round_key)
                          
        round_output = self.add_round_output_component([last_round_add_round_key[i].id for i in range(self.NUM_SBOXES)],
                                                       [[i for i in range(self.SBOX_BIT_SIZE)] for j in range(self.NUM_SBOXES)],
                                                       self.CIPHER_BLOCK_SIZE)
                                                       
        cipher_output = self.add_cipher_output_component([round_output.id],
                                                         [[i for i in range(self.CIPHER_BLOCK_SIZE)][::-1]],
                                                         self.CIPHER_BLOCK_SIZE)
                                                         
    def update_constants(self, constant):
        spill = self.add_SHIFT_component([constant.id],
                                         [[i for i in range(self.LAYER_BLOCK_SIZE)]],
                                         self.LAYER_BLOCK_SIZE,
                                         -51)
        tmp_0 = self.add_SHIFT_component([constant.id],
                                         [[i for i in range(self.LAYER_BLOCK_SIZE)]],
                                         self.LAYER_BLOCK_SIZE,
                                         13)
        tmp_1 = self.add_SHIFT_component([spill.id],
                                         [[i for i in range(self.LAYER_BLOCK_SIZE)]],
                                         self.LAYER_BLOCK_SIZE,
                                         50)
        tmp_2 = self.add_SHIFT_component([spill.id],
                                         [[i for i in range(self.LAYER_BLOCK_SIZE)]],
                                         self.LAYER_BLOCK_SIZE,
                                         33)
        tmp_3 = self.add_SHIFT_component([spill.id],
                                         [[i for i in range(self.LAYER_BLOCK_SIZE)]],
                                         self.LAYER_BLOCK_SIZE,
                                         19)
        tmp = self.add_XOR_component([tmp_0.id, tmp_1.id, tmp_2.id, tmp_3.id, spill.id],
                                     [[i for i in range(self.LAYER_BLOCK_SIZE)] for j in range(5)],
                                     self.LAYER_BLOCK_SIZE)
        spill = self.add_SHIFT_component([tmp.id],
                                         [[i for i in range(self.LAYER_BLOCK_SIZE)]],
                                         self.LAYER_BLOCK_SIZE,
                                         -54)
        tmp_0 = self.add_SHIFT_component([tmp.id],
                                         [[i for i in range(self.LAYER_BLOCK_SIZE)]],
                                         self.LAYER_BLOCK_SIZE,
                                         10)
        tmp_1 = self.add_SHIFT_component([spill.id],
                                         [[i for i in range(self.LAYER_BLOCK_SIZE)]],
                                         self.LAYER_BLOCK_SIZE,
                                         50)
        tmp_2 = self.add_SHIFT_component([spill.id],
                                         [[i for i in range(self.LAYER_BLOCK_SIZE)]],
                                         self.LAYER_BLOCK_SIZE,
                                         33)
        tmp_3 = self.add_SHIFT_component([spill.id],
                                         [[i for i in range(self.LAYER_BLOCK_SIZE)]],
                                         self.LAYER_BLOCK_SIZE,
                                         19)
        tmp = self.add_XOR_component([tmp_0.id, tmp_1.id, tmp_2.id, tmp_3.id, spill.id],
                                     [[i for i in range(self.LAYER_BLOCK_SIZE)] for j in range(5)],
                                     self.LAYER_BLOCK_SIZE)
        return tmp
        
    def o_function(self, key):
        key_rot_0 = self.add_rotate_component([key[0].id],
                                              [[i for i in range(self.KEY_BLOCK_SIZE)]],
                                              self.KEY_BLOCK_SIZE,
                                              1)
        key_shift_0 = self.add_SHIFT_component([key[0].id],
                                               [[i for i in range(self.KEY_BLOCK_SIZE)]],
                                               self.KEY_BLOCK_SIZE,
                                               self.KEY_BLOCK_SIZE-1)
        key[0] = self.add_XOR_component([key_rot_0.id, key_shift_0.id],
                                        [[i for i in range(self.KEY_BLOCK_SIZE)], [i for i in range(self.KEY_BLOCK_SIZE)]],
                                        self.KEY_BLOCK_SIZE)
        
        key_lshift_1 = self.add_SHIFT_component([key[1].id],
                                                [[i for i in range(self.KEY_BLOCK_SIZE)]],
                                                self.KEY_BLOCK_SIZE,
                                                -1)
        key_rshift_1 = self.add_SHIFT_component([key[1].id],
                                                [[i for i in range(self.KEY_BLOCK_SIZE)]],
                                                self.KEY_BLOCK_SIZE,
                                                self.KEY_BLOCK_SIZE-1)
        key_rotated_1 = self.add_XOR_component([key[1].id, key_rshift_1.id],
                                               [[i for i in range(self.KEY_BLOCK_SIZE)], [i for i in range(self.KEY_BLOCK_SIZE)]],
                                               self.KEY_BLOCK_SIZE)
        key[1] = self.add_rotate_component([key_rotated_1.id],
                                           [[i for i in range(self.KEY_BLOCK_SIZE)]],
                                           self.KEY_BLOCK_SIZE,
                                           -1)  
        return(key)
