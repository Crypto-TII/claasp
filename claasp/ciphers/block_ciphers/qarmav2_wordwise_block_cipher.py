
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

PARAMETERS_CONFIGURATION_LIST = [{'number_of_rounds': 10, 'number_of_layers': 1, 'key_bit_size': 128, 'tweak_bit_size': 128}]


class QARMAv2WordwiseBlockCipher(Cipher):
    """
    Return a cipher object of Qarma v2 Block Cipher.

    INPUT:

    - ``number_of_rounds`` -- **integer** (default: `10`); number of rounds of the cipher. Must be greater or equal than 1.
    - ``number_of_layers`` -- **integer** (default: `1`); number of layers of the state represented as matrices. Must be equal to 1 or 2.
    - ``key_bit_size``     -- **integer** (default: `128`); length of the key in bits. If number_of_layers is equal to 1 it must be equal to 128, otherwise it must be equal to 128, 192 or 256.
    - ``tweak_bit_size``   -- **integer** (default: `128`); length of the tweak in bits. Must be equal to either 64*number_of_layers or 128*number_of_layers.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.qarmav2_block_cipher import QARMAv2BlockCipher
        sage: qarmav2 = QARMAv2BlockCipher(number_of_rounds = 4)
        sage: key = 0x0123456789abcdeffedcba9876543210
        sage: tweak = 0x7e5c3a18f6d4b2901eb852fc9630da74
        sage: plaintext = 0x0000000000000000
        sage: ciphertext = 0x2cc660354929f2ca
        sage: qarmav2.evaluate([key, plaintext, tweak]) == ciphertext
        True
    """

    def __init__(self, number_of_rounds=10, number_of_layers=1, key_bit_size=128, tweak_bit_size=128):

        if number_of_layers not in [1, 2]:
            raise ValueError("number_of_layers incorrect (should be in [1,2])")
        if number_of_rounds < 1:
            raise ValueError("number_of_rounds incorrect (should be at least 1)")
        if key_bit_size != 128 and number_of_layers==1 or key_bit_size not in [128, 192, 256] and number_of_layers==2:
            raise ValueError("key_bit_size incorrect (should be 128 with 1 layer and 128, 192 or 256 with 2 layers)")
        if tweak_bit_size != 64*number_of_layers and tweak_bit_size != 128*number_of_layers:
            raise ValueError("tweak_bit_size incorrect (should be either 64*number_of_layers or 128*number_of_layers)")

        # cipher dictionary initialize
        self.CIPHER_BLOCK_SIZE = 64 * number_of_layers
        self.LAYER_BLOCK_SIZE = 64
        self.KEY_BLOCK_SIZE = self.CIPHER_BLOCK_SIZE
        self.TWEAK_BLOCK_SIZE = self.CIPHER_BLOCK_SIZE
        self.NROUNDS = number_of_rounds
        self.WORD_SIZE = 4
        self.SBOX_BIT_SIZE = self.WORD_SIZE
        self.LAYER_SBOXES = 16
        self.NUM_SBOXES = self.LAYER_SBOXES * number_of_layers
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
                            
        self.mix_column_matrix = [
                                  [0x0, 0x2, 0x4, 0x8,],
                                  [0x8, 0x0, 0x2, 0x4,],
                                  [0x4, 0x8, 0x0, 0x2,],
                                  [0x2, 0x4, 0x8, 0x0,],
                                 ]
                            
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
        inverse_permutation = []
        for i in self.tweak_permutations[number_of_layers]:
            inverse_permutation += list(range(4*i, 4*i + 4))
        direct_permutation = [inverse_permutation.index(i) for i in range(self.TWEAK_BLOCK_SIZE)]
        tweak_permutation = [direct_permutation, inverse_permutation]
        
        exchange_rows_permutation = list(range(64,96)) + list(range(32, 64)) + list(range(32)) + list(range(96, 128))
                 
        #Key initialization
        key_state = self.key_initialization()
             
        #Tweak initialization
        tweak_state = self.tweak_initialization(tweak_permutation)
        
        #Round constants initialization
        constants_states = self.constants_initialization()
        
        self.add_round()
                       
        #First round different from others 
        self.first_round_start(state, key_state, tweak_state, constants_states)
        
        #Direct encryption 
        for round_number in range(1, number_of_rounds+1):
            self.direct_round(state, key_state, tweak_state, constants_states)
            self.add_round()
            
        #Reflector 
        self.reflector(state, key_state, tweak_state, constants_states)
                                 
        #Inverse encryption 
        for round_number in list(range(1, number_of_rounds+1))[::-1]:
            self.add_round()
            self.inverse_round(state, key_state, tweak_state, constants_states)
                           
        #Last round different from others 
        self.last_round_end(state, key_state, tweak_state, constants_states)
                                           
    def key_initialization(self):
        #Key initialization
        key_0 = [[INPUT_KEY], [list(range(self.KEY_BLOCK_SIZE))]]
        if key_bit_size == 2*self.KEY_BLOCK_SIZE:
            key_1 = [[INPUT_KEY], [list(range(self.KEY_BLOCK_SIZE, 2*self.KEY_BLOCK_SIZE))]]
        elif key_bit_size == self.KEY_BLOCK_SIZE:
            key_1 = key_0
        else:
            next_key = self.add_permutation_component([INPUT_KEY, majority_function(INPUT_KEY).id], 
                                                      [list(range(self.KEY_BLOCK_SIZE, 3*self.KEY_BLOCK_SIZE//2)), list(range(self.KEY_BLOCK_SIZE//2))],
                                                      list(range(self.KEY_BLOCK_SIZE)))
            key_1 = [[next_key.id], [list(range(self.KEY_BLOCK_SIZE))]]
        key_state = [key_0, key_1]
        
        return key_state
    
    def tweak_initialization(self, tweak_permutation):
        #Tweak initialization
        tweak_0 = [[INPUT_TWEAK],[tweak_permutation[1]]]
        for j in range(1, number_of_rounds-1):
            perm_tweak = [tweak_0[1][0][i] for i in tweak_permutation[1]]
            tweak_0[1][0] = perm_tweak
        if tweak_bit_size == self.TWEAK_BLOCK_SIZE:
            tweak_1 = [[INPUT_TWEAK], [tweak_permutation[1]]]
        else:
            tweak_1 = [[INPUT_TWEAK], [list(range(self.TWEAK_BLOCK_SIZE, 2*self.TWEAK_BLOCK_SIZE))]]
        tweak_state = [tweak_0, tweak_1]
        
        return tweak_state
        
    def constants_initialization(self):
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
        
        return round_constant
    
    def first_round_start(self, state, key_state, tweak_state, constants_states):             
        #First round different from others
        id_links = 
        bit_positions = 
        masked_state = self.state_masking(id_links, bit_positions)     
        
        id_links = 
        bit_positions = 
        sboxes = 
        sboxed_state = self.state_sboxing(id_links, bit_positions, sboxes)
         
        round_output = self.add_permutation_component([sboxed_state[i] for i in range(16*number_of_layers)],
                                                       [[i for i in range(4)] for j in range(16*number_of_layers)],
                                                       self.CIPHER_BLOCK_SIZE,
                                                       [i for i in range(self.CIPHER_BLOCK_SIZE)])
               
        return round_output
        
    def direct_round(self, state, key_state, tweak_state, constants_states):
        #Direct encryption
        id_links = 
        bit_positions = 
        masked_state = self.state_masking(id_links, bit_positions)
        
        bit_positions = 
        tweak_permutation = 
        tweak_state[][] = self.tweak_update(bit_positions, tweak_permutation)
        
        id_links = 
        bit_positions = 
        rotated_state = self.state_rotation(id_links, bit_positions)
        
        id_links = 
        bit_positions = 
        sboxes = 
        sboxed_state = self.state_sboxing(id_links, bit_positions, sboxes)
                                     
        if number_of_layers == 2 and (number_of_rounds - round_number)%2 == 0:
            round_output = self.add_round_output_component([sboxed_state[i//self.NUM_SBOXES] for i in exchange_rows_permutation],
                                                           [[i % self.NUM_SBOXES] for i in exchange_rows_permutation],
                                                           self.CIPHER_BLOCK_SIZE)
        else:
            round_output = self.add_round_output_component([sboxed_state[i] for i in range(16*number_of_layers)],
                                                           [[i for i in range(self.SBOX_BIT_SIZE)] for j in range(self.NUM_SBOXES)],
                                                           self.CIPHER_BLOCK_SIZE)   
                         
        return round_output
        
    def reflector(self, state, key_state, tweak_state, constants_states):
        #Reflector         
        new_keys = self.o_function(key_state)
        key_state = new_keys
        W = self.o_function(new_keys)
        
        alpha, beta = self.constants_update()
        
        key_state = 
        constants_state = 
        key_state = self.key_update(key_state, constants_state)
        
        id_links = 
        bit_positions = 
        masked_state = self.state_masking(id_links, bit_positions) #1 - reflector
        
        id_links = 
        bit_positions = 
        rotated_state = self.state_rotation(id_links, bit_positions)
        
        id_links = 
        bit_positions = 
        masked_state = self.state_masking(id_links, bit_positions) #2 - reflector
        
        round_output = self.add_round_output_component([masked_state[inverse_state_permutation[i] // 4] for i in range(64 * number_of_layers)],
                                                       [[inverse_state_permutation[j % 4]] for j in range(64 * number_of_layers)],
                                                       self.CIPHER_BLOCK_SIZE)
                     
        return round_output
    
    def inverse_round(self, state, key_state, tweak_state, constants_states):
        #Inverse encryption              
        if number_of_layers == 2 and (number_of_rounds - round_number)%2 == 0:
            exchanging_rows = exchange_rows_permutation
        else:
            exchanging_rows = list(range(self.CIPHER_BLOCK_SIZE))
            
        id_links = 
        bit_positions = 
        sboxes = 
        sboxed_state = self.state_sboxing(id_links, bit_positions, sboxes)
        
        id_links = 
        bit_positions = 
        rotated_state = self.state_rotation(id_links, bit_positions)
        
        if round_number == 1:
            id_links = 
            bit_positions = 
            masked_state = self.state_masking(id_links, bit_positions)
        else:
            id_links = 
            bit_positions = 
            masked_state = self.state_masking(id_links, bit_positions)
            
            bit_positions = 
            tweak_permutation = 
            tweak_state[][] = self.tweak_update(bit_positions, tweak_permutation)
             
        if round_number != 1:                                  
            round_output = self.add_round_output_component([masked_state[inverse_state_permutation[i%64]//4+16*(i//64)] for i in range(64 * number_of_layers)],
                                                           [[inverse_state_permutation[i%64]%4] for i in range(64 * number_of_layers)],
                                                           self.CIPHER_BLOCK_SIZE)                 
                   
        else:
            round_output = self.add_permutation_component([masked_state[i] for i in range(16 * number_of_layers)],
                                                          [[i for i in range(4)] for j in range(16 * number_of_layers)],
                                                          self.CIPHER_BLOCK_SIZE,
                                                          state_permutation)
                                   
        return round_output
        
    def last_round_end(self, state, key_state, tweak_state, constants_states):                
        #Last round different from others
        id_links = 
        bit_positions = 
        sboxes = 
        sboxed_state = self.state_sboxing(id_links, bit_positions, sboxes)
        
        id_links = 
        bit_positions = 
        masked_state = self.state_masking(id_links, bit_positions)
        
        round_output = self.add_round_output_component([masked_state[i] for i in range(self.NUM_SBOXES)],
                                                       [[i for i in range(self.SBOX_BIT_SIZE)] for j in range(self.NUM_SBOXES)],
                                                       self.CIPHER_BLOCK_SIZE)
                                                       
        cipher_output = self.add_cipher_output_component([round_output.id],
                                                         [[i for i in range(self.CIPHER_BLOCK_SIZE)]],
                                                         self.CIPHER_BLOCK_SIZE)
                                         
        return cipher_output
        
        
        
        
        
        
        
    #-------------------------------------TOTALS-------------------------------------#
        
    def state_masking(self, id_links, bit_positions):
        masked_state = []
        for l in range(number_of_layers):
            for word in range(16):
                masked_state.append(self.add_XOR_component(id_links[word + 16*l],
                                                           bit_positions[word + 16*l],
                                                           self.WORD_SIZE).id)
                                                          
        return masked_state
        
    def state_sboxing(self, id_links, bit_positions, sboxes):
        sboxed_state = []
        for l in range(number_of_layers):
            for word in range(16):
                sboxed_state.append(self.add_SBOX_component(id_links[word + 16*l],
                                                            bit_positions[word + 16*l],
                                                            sboxes[word + 16*l]
                                                            self.WORD_SIZE).id)
                                                          
        return sboxed_state
        
    def tweak_update(self, bit_positions, tweak_permutation): #direct encryption
        perm_tweak = [bit_positions[1][0][i] for i in tweak_permutation[round_number%2]]
                   
        return perm_tweak
    
    def state_rotation(self, id_links, bit_positions):
        round_state_rotate = []
        for l in range(number_of_layers):
            for col in range(4):
                round_state_rotate.extend(self.M_function([id_links[col+4*i+16*l] for i in range(4)], [bit_positions[col+4*i+16*l] for j in range(4)]))
                
        return round_state_rotate
    
    def key_update(self, key_state, constants_state):
        new_keys = self.o_function(key_state)
        key_state = new_keys
        W = self.o_function(new_keys)
        
        alpha, beta = self.constants_update()
        
        if number_of_layers == 2:
            key_state[0] = [[self.add_XOR_component(key_state[0][0]+[alpha[0].id, alpha[1].id],
                                                  key_state[0][1]+[[i for i in range(self.LAYER_BLOCK_SIZE)], [i for i in range(self.LAYER_BLOCK_SIZE)]],
                                                  self.KEY_BLOCK_SIZE).id], [list(range(self.LAYER_BLOCK_SIZE))]]
            key_state[1] = [[self.add_XOR_component(key_state[1][0]+[beta[0].id, beta[1].id],
                                                  key_state[1][0]+[[i for i in range(self.LAYER_BLOCK_SIZE)], [i for i in range(self.LAYER_BLOCK_SIZE)]],
                                                  self.KEY_BLOCK_SIZE).id], [list(range(self.LAYER_BLOCK_SIZE))]]
        else:
            key_state[0] = [[self.add_XOR_component(key_state[0][0]+[alpha[0].id],
                                                  key_state[0][1]+[[i for i in range(self.LAYER_BLOCK_SIZE)]],
                                                  self.KEY_BLOCK_SIZE).id], [list(range(self.LAYER_BLOCK_SIZE))]]
            key_state[1] = [[self.add_XOR_component(key_state[1][0]+[beta[0].id],
                                                  key_state[1][0]+[[i for i in range(self.LAYER_BLOCK_SIZE)]],
                                                  self.KEY_BLOCK_SIZE).id], [list(range(self.LAYER_BLOCK_SIZE))]]
                                              
        return key_state
        
    def constants_update(self):
        alpha_0 = self.add_constant_component(self.LAYER_BLOCK_SIZE, 0x13198A2E03707344)
        alpha = [alpha_0]
        if number_of_layers == 2:
            alpha_1 = self.update_single_constant(alpha[0])
            alpha.append(alpha_1)
        beta_0 = self.update_single_constant(alpha[-1])
        beta = [beta_0]
        if number_of_layers == 2:
            beta_1 = self.update_single_constant(beta_0)
            beta.append(beta_1)
    
        return alpha, beta
        
    #--------------------------------------------------------------------------------#
        
        
        
        
        
     
     
    def state_masking(self): #first round
        first_round_add_round_key = self.add_XOR_component(key_state[0][0]+[INPUT_PLAINTEXT],
                                                           key_state[0][1]+
                                                           [list(range(self.CIPHER_BLOCK_SIZE))[::-1]],
                                                           self.CIPHER_BLOCK_SIZE)
                                            
        return first_round_add_round_key
    
    def state_sboxing(self): #first round  
        first_round_sboxes = []
        for sb in range(self.NUM_SBOXES):
            sbox = self.add_SBOX_component([first_round_add_round_key.id],
                                           [[i for i in range(4*sb, 4*sb + 4)]],
                                           self.SBOX_BIT_SIZE, 
                                           self.sbox)
            first_round_sboxes.append(sbox)
            
        return first_round_sboxes
    
    def state_masking(self): #direct encryption
        round_key_shuffle = []
        for l in range(number_of_layers):
            xor = self.add_XOR_component([round_output.id]+ 
                                          key_state[round_number%2][0]+ 
                                          tweak_state[round_number%2][0]+ 
                                          [round_constant[(round_number - 1)*number_of_layers + l].id],
                                         [[i for i in range(64*l, 64*l + 64)]]+ 
                                          key_state[round_number%2][1]+ 
                                          tweak_state[round_number%2][1]+
                                          [[i for i in range(64)]],
                                         self.LAYER_BLOCK_SIZE)
            round_key_shuffle.append(xor)
            
        return round_key_shuffle
    
    def tweak_update(self): #direct encryption
        perm_tweak = [tweak_state[round_number%2][1][0][i] for i in tweak_permutation[round_number%2]]
        tweak_state[round_number%2][1][0] = perm_tweak
                   
        return tweak_state
    
    def state_rotation(self): #direct encryption        
        round_state_rotate = []
        for l in range(number_of_layers):
            for col in range(4):
                round_state_rotate.extend(self.M_function([round_key_shuffle[l].id for i in range(4)], [[state_permutation[i]+4*col+16*j for i in range(4)] for j in range(4)]))
                
        return round_state_rotate
    
    def state_sboxing(self): #direct encryption
        round_sboxes = []
        for l in range(number_of_layers):
            for sb in range(self.LAYER_SBOXES):
                sbox = self.add_SBOX_component([round_state_rotate[int(sb/4)+4*(sb%4)+16*l]],
                                               [[i for i in range(4)]],
                                               self.SBOX_BIT_SIZE, 
                                               self.sbox)
                round_sboxes.append(sbox)
                    
        return round_sboxes()
    
    def key_update(self): #reflector
        new_keys = self.o_function(key_state)
        key_state = new_keys
        W = self.o_function(new_keys)
        
        self.update_constants()
        
        if number_of_layers == 2:
            key_state[0] = [[self.add_XOR_component(key_state[0][0]+[alpha[0].id, alpha[1].id],
                                                  key_state[0][1]+[[i for i in range(self.LAYER_BLOCK_SIZE)], [i for i in range(self.LAYER_BLOCK_SIZE)]],
                                                  self.KEY_BLOCK_SIZE).id], [list(range(self.LAYER_BLOCK_SIZE))]]
            key_state[1] = [[self.add_XOR_component(key_state[1][0]+[beta[0].id, beta[1].id],
                                                  key_state[1][0]+[[i for i in range(self.LAYER_BLOCK_SIZE)], [i for i in range(self.LAYER_BLOCK_SIZE)]],
                                                  self.KEY_BLOCK_SIZE).id], [list(range(self.LAYER_BLOCK_SIZE))]]
        else:
            key_state[0] = [[self.add_XOR_component(key_state[0][0]+[alpha[0].id],
                                                  key_state[0][1]+[[i for i in range(self.LAYER_BLOCK_SIZE)]],
                                                  self.KEY_BLOCK_SIZE).id], [list(range(self.LAYER_BLOCK_SIZE))]]
            key_state[1] = [[self.add_XOR_component(key_state[1][0]+[beta[0].id],
                                                  key_state[1][0]+[[i for i in range(self.LAYER_BLOCK_SIZE)]],
                                                  self.KEY_BLOCK_SIZE).id], [list(range(self.LAYER_BLOCK_SIZE))]]
                                              
        return key_state
        
    def constants_update(self): #reflector
        alpha_0 = self.add_constant_component(self.LAYER_BLOCK_SIZE, 0x13198A2E03707344)
        alpha = [alpha_0]
        if number_of_layers == 2:
            alpha_1 = self.update_single_constant(alpha[0])
            alpha.append(alpha_1)
        beta_0 = self.update_single_constant(alpha[-1])
        beta = [beta_0]
        if number_of_layers == 2:
            beta_1 = self.update_single_constant(beta_0)
            beta.append(beta_1)
    
        return [alpha, beta]
        
    def state_masking(self): #1 - reflector
        round_state_shuffle = []
        for l in range(number_of_layers):
            mixed_shuffled_state = self.add_XOR_component([round_output.id, W[(number_of_rounds + 1)%2][0]],
                                                          [[state_permutation[i] + 64*l for i in range(64)], [i for i in range(64*l, 64*l + 64)]],
                                                          self.LAYER_BLOCK_SIZE)
            round_state_shuffle.append(mixed_shuffled_state)
        
        return round_state_shuffle
    
    def state_rotation(self): #reflector
        round_state_rotate = []
        for l in range(number_of_layers):
            for col in range(4):
                round_state_rotate.extend(self.M_function([round_state_shuffle[l].id for i in range(4)], [[i for i in range(4*col+16*j, 4*col+16*j+4)] for j in range(4)]))
                
        return round_state_rotate
    
    def state_masking(self): #2 - reflector
        central_keyed_state = []
        for l in range(number_of_layers):
            for w in range(16):
                central_xor = self.add_XOR_component([round_state_rotate[int(w/4)+4*(w%4)+16*l], W[(number_of_rounds)%2][0]],
                                                     [[i for i in range(4)], [i for i in range(64*l + 4*w, 64*l + 4*w + 4)]],
                                                     self.WORD_SIZE)
                central_keyed_state.append(central_xor)
        
        return central_keyed_state
    
    def state_sboxing(self): #inverse encryption               
        if number_of_layers == 2 and (number_of_rounds - round_number)%2 == 0:
            exchanging_rows = exchange_rows_permutation
        else:
            exchanging_rows = list(range(self.CIPHER_BLOCK_SIZE))
            
        round_sboxes = []
        for sb in range(self.NUM_SBOXES):
            sbox = self.add_SBOX_component([round_output.id],
                                           [[exchanging_rows[i] for i in range(4*sb, 4*sb + 4)]],
                                           self.SBOX_BIT_SIZE, 
                                           self.inverse_sbox)
            round_sboxes.append(sbox)
                
        return round_sboxes
    
    def state_rotation(self): #inverse encryption
        round_state_rotate = []
        for l in range(number_of_layers):
            for col in range(4):
                round_state_rotate.extend(self.M_function([round_sboxes[col+4*i+16*l].id for i in range(4)], [[i for i in range(4)] for j in range(4)]))
                
        return round_state_rotate
    
    def state_masking(self): #inverse encryption
        round_key_shuffle = []
        if round_number == 1:
            for l in range(number_of_layers):
                for col in range(4):
                    xor = self.add_XOR_component([round_state_rotate[int(i/4)+4*(i%4)+16*l]]+ 
                                                  key_state[(round_number + 1)%2][0]+ 
                                                  [INPUT_TWEAK, 
                                                  round_constant[(round_number - 1)*number_of_layers + l].id],
                                                 [[i for i in range(16)]]+ 
                                                  [[key_state[(round_number + 1)%2][1][i] for i in state_permutation][16*col:16*(col+1)]]+ 
                                                  [[state_permutation[i]+(self.LAYER_BLOCK_SIZE)*l for i in range(self.LAYER_BLOCK_SIZE)][16*col:16*(col+1)]]+ 
                                                  [[state_permutation[i] for i in range(64)][16*col:16*(col+1)]],
                                                 self.LAYER_BLOCK_SIZE)
                    round_key_shuffle.append(xor)
        else:
            for l in range(number_of_layers):
                for col in range(4):
                    xor = self.add_XOR_component([round_state_rotate[int(i/4)+4*(i%4)+16*l]]+ 
                                                  key_state[(round_number + 1)%2][0]+ 
                                                  tweak_state[(round_number + 1)%2][0]+ 
                                                  [round_constant[(round_number - 1)*number_of_layers + l].id],
                                                 [[i for i in range(16)]]+ 
                                                  [[key_state[(round_number + 1)%2][1][i] for i in state_permutation][16*col:16*(col+1)]]+ 
                                                  [[tweak_state[(round_number + 1)%2][1][i] for i in state_permutation][16*col:16*(col+1)]]+ 
                                                  [[state_permutation[i] for i in range(64)][16*col:16*(col+1)]],
                                                 16)
                    round_key_shuffle.append(xor)
                
        return round_key_shuffle
        
    def tweak_update(self): #inverse encryption
        if round_number != 1:
            perm_tweak = [tweak_state[(round_number + 1)%2][1][0][i] for i in tweak_permutation[(round_number + 1)%2]]
            tweak_state[(round_number + 1)%2][1][0] = perm_tweak
            
        return tweak_state
    
    def state_sboxing(self): #last round     
        last_round_sboxes = []
        for sb in range(self.NUM_SBOXES):
            sbox = self.add_SBOX_component(
                [round_output.id],
                [[i for i in range(4*sb, 4*sb + 4)]],
                self.SBOX_BIT_SIZE, 
                self.inverse_sbox)
            last_round_sboxes.append(sbox)
            
        return last_round_sboxes
    
    def state_masking(self): #last round
        last_round_add_round_key = []
        for sb in range(self.NUM_SBOXES):
            add_round_key = self.add_XOR_component([key_state[1].id, last_round_sboxes[sb].id],
                                                     [[i for i in range(4*sb, 4*sb + 4)],
                                                      [i for i in range(self.SBOX_BIT_SIZE)]],
                                                     self.SBOX_BIT_SIZE)
            last_round_add_round_key.append(add_round_key)
                          
        return last_round_add_round_key
                                                     
    def update_single_constant(self, constant):
        spill = self.add_SHIFT_component([constant.id],
                                         [[i for i in range(self.LAYER_BLOCK_SIZE)]],
                                         self.LAYER_BLOCK_SIZE,
                                         51)
        tmp_0 = self.add_SHIFT_component([constant.id],
                                         [[i for i in range(self.LAYER_BLOCK_SIZE)]],
                                         self.LAYER_BLOCK_SIZE,
                                         -13)
        tmp_1 = self.add_SHIFT_component([spill.id],
                                         [[i for i in range(self.LAYER_BLOCK_SIZE)]],
                                         self.LAYER_BLOCK_SIZE,
                                         -50)
        tmp_2 = self.add_SHIFT_component([spill.id],
                                         [[i for i in range(self.LAYER_BLOCK_SIZE)]],
                                         self.LAYER_BLOCK_SIZE,
                                         -33)
        tmp_3 = self.add_SHIFT_component([spill.id],
                                         [[i for i in range(self.LAYER_BLOCK_SIZE)]],
                                         self.LAYER_BLOCK_SIZE,
                                         -19)
        tmp = self.add_XOR_component([tmp_0.id, tmp_1.id, tmp_2.id, tmp_3.id, spill.id],
                                     [[i for i in range(self.LAYER_BLOCK_SIZE)] for j in range(5)],
                                     self.LAYER_BLOCK_SIZE)
        spill = self.add_SHIFT_component([tmp.id],
                                         [[i for i in range(self.LAYER_BLOCK_SIZE)]],
                                         self.LAYER_BLOCK_SIZE,
                                         54)
        tmp_0 = self.add_SHIFT_component([tmp.id],
                                         [[i for i in range(self.LAYER_BLOCK_SIZE)]],
                                         self.LAYER_BLOCK_SIZE,
                                         -10)
        tmp_1 = self.add_SHIFT_component([spill.id],
                                         [[i for i in range(self.LAYER_BLOCK_SIZE)]],
                                         self.LAYER_BLOCK_SIZE,
                                         -50)
        tmp_2 = self.add_SHIFT_component([spill.id],
                                         [[i for i in range(self.LAYER_BLOCK_SIZE)]],
                                         self.LAYER_BLOCK_SIZE,
                                         -33)
        tmp_3 = self.add_SHIFT_component([spill.id],
                                         [[i for i in range(self.LAYER_BLOCK_SIZE)]],
                                         self.LAYER_BLOCK_SIZE,
                                         -19)
        tmp = self.add_XOR_component([tmp_0.id, tmp_1.id, tmp_2.id, tmp_3.id, spill.id],
                                     [[i for i in range(self.LAYER_BLOCK_SIZE)] for j in range(5)],
                                     self.LAYER_BLOCK_SIZE)
        return tmp
        
    def o_function(self, key):
        key_rot_0 = self.add_rotate_component(key[0][0],
                                              key[0][1],
                                              self.KEY_BLOCK_SIZE,
                                              1)
        key_shift_0 = self.add_SHIFT_component(key[0][0],
                                               key[0][1],
                                               self.KEY_BLOCK_SIZE,
                                               self.KEY_BLOCK_SIZE-1)
        key_1 = [[self.add_XOR_component([key_rot_0.id, key_shift_0.id],
                                              [[i for i in range(self.KEY_BLOCK_SIZE)], [i for i in range(self.KEY_BLOCK_SIZE)]],
                                              self.KEY_BLOCK_SIZE).id], [list(range(self.KEY_BLOCK_SIZE))]]
        
        key_lshift_1 = self.add_SHIFT_component(key[1][0],
                                                key[1][1],
                                                self.KEY_BLOCK_SIZE,
                                                -1)
        key_rshift_1 = self.add_SHIFT_component([key_lshift_1.id],
                                                [[i for i in range(self.KEY_BLOCK_SIZE)]],
                                                self.KEY_BLOCK_SIZE,
                                                self.KEY_BLOCK_SIZE-1)
        key_rotated_1 = self.add_XOR_component(key[1][0]+[key_rshift_1.id],
                                               key[1][1]+[[i for i in range(self.KEY_BLOCK_SIZE)]],
                                               self.KEY_BLOCK_SIZE)
        key_2 = [[self.add_rotate_component([key_rotated_1.id],
                                                 [[i for i in range(self.KEY_BLOCK_SIZE)]],
                                                 self.KEY_BLOCK_SIZE,
                                                 -1).id], [list(range(self.KEY_BLOCK_SIZE))]]
        key_new = [key_1, key_2]
        return(key_new)
        
    def M_function(self, input_ids, input_pos):
        output = []
        for c in range(4):
            output.append(self.add_XOR_component([input_ids[(c + r + 1)%4] for r in range(3)],
                                                 [input_pos[(c + r + 1)%4][r+1:] + input_pos[(c + r + 1)%4][:r+1] for r in range(3)],
                                                 4).id)
        return output
        
    def majority_function(self, key):
        maj_key_size = self.KEY_BLOCK_SIZE/2
        and_0_1 = self.add_AND_component([key, key],
                                         [[i for i in range(maj_key_size)], [i for i in range(maj_key_size, 2*maj_key_size)]],
                                         maj_key_size)
        and_0_2 = self.add_AND_component([key, key],
                                         [[i for i in range(maj_key_size)], [i for i in range(2*maj_key_size, 3*maj_key_size)]],
                                         maj_key_size)
        and_1_2 = self.add_AND_component([key, key],
                                         [[i for i in range(maj_key_size, 2*maj_key_size)], [i for i in range(2*maj_key_size, 3*maj_key_size)]],
                                         maj_key_size)
        maj_key_rotated = self.add_OR_component([and_0_1, and_0_2, and_1_2],
                                        [[i for i in range(maj_key_size)] for j in range(3)],
                                        maj_key_size)
        maj_key = self.add_rotate_component([maj_key_rotated],
                                            [[i for i in range(maj_key_size)]],
                                            maj_key_size,
                                            17)
        return maj_key
