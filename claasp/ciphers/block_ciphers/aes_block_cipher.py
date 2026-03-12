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
from claasp.name_mappings import INPUT_KEY, INPUT_PLAINTEXT, BLOCK_CIPHER


# AES configuration: (key_size, Nk, Nr)
# AES-128: key_size=128, Nk=4, Nr=10
# AES-192: key_size=192, Nk=6, Nr=12
# AES-256: key_size=256, Nk=8, Nr=14
PARAMETERS_CONFIGURATION_LIST = [
    {'key_bit_size': 128, 'number_of_rounds': 10},
    {'key_bit_size': 192, 'number_of_rounds': 12},
    {'key_bit_size': 256, 'number_of_rounds': 14}
]


class AESBlockCipher(Cipher):
    """
    Return a cipher object of AES Block Cipher supporting all variants (AES-128, AES-192, AES-256).
    
    This implementation follows the FIPS-197 specification and pseudocode notation.
    
        Algorithm 1: CIPHER(in, Nr, w)
        Algorithm 2: KEYEXPANSION(key)

        Delegation behavior:

        - When ``word_size == 8`` and ``state_size == 4`` (default), this class uses
            the FIPS-197 implementation in this file.
        - When either ``word_size`` or ``state_size`` is non-default, construction
            delegates to ``ToyAESBlockCipher``, to be used for testing/research purposes.

    INPUT:

    - ``key_bit_size`` -- **integer** (default: `128`); size of the key in bits (128, 192, or 256)
        - ``number_of_rounds`` -- **integer** (default: computed from key size); number of rounds
      - AES-128: Nr = 10 rounds
      - AES-192: Nr = 12 rounds
      - AES-256: Nr = 14 rounds
        - ``word_size`` -- **integer** (default: `8`); if different from `8`, delegates to ``ToyAESBlockCipher``
        - ``state_size`` -- **integer** (default: `4`); if different from `4`, delegates to ``ToyAESBlockCipher``

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
        sage: # AES-128
        sage: aes128 = AESBlockCipher(key_bit_size=128)
        sage: key = 0x2b7e151628aed2a6abf7158809cf4f3c
        sage: plaintext = 0x6bc1bee22e409f96e93d7e117393172a
        sage: ciphertext = 0x3ad77bb40d7a3660a89ecaf32466ef97
        sage: aes128.evaluate([key, plaintext]) == ciphertext
        True
        
        sage: # AES-192
        sage: aes192 = AESBlockCipher(key_bit_size=192)
        sage: key = 0x8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
        sage: plaintext = 0x6bc1bee22e409f96e93d7e117393172a
        sage: ciphertext = 0xbd334f1d6e45f25ff712a214571fa5cc
        sage: aes192.evaluate([key, plaintext]) == ciphertext
        True
        
        sage: # AES-256
        sage: aes256 = AESBlockCipher(key_bit_size=256)
        sage: key = 0x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
        sage: plaintext = 0x6bc1bee22e409f96e93d7e117393172a
        sage: ciphertext = 0xf3eed1bdb5d2a03c064b5a7e3db181f8
        sage: aes256.evaluate([key, plaintext]) == ciphertext
        True

        sage: # Non-standard word/state parameters delegate to ToyAESBlockCipher
        sage: from claasp.ciphers.toys.toyaes_block_cipher import ToyAESBlockCipher
        sage: aes_compat = AESBlockCipher(number_of_rounds=2, word_size=4, state_size=2)
        sage: toy_aes = ToyAESBlockCipher(number_of_rounds=2, word_size=4, state_size=2)
        sage: aes_compat.evaluate([0x1234, 0xabcd]) == toy_aes.evaluate([0x1234, 0xabcd])
        True
    """

    def __init__(self, key_bit_size=128, number_of_rounds=None, word_size=8, state_size=4):
        if word_size != 8 or state_size != 4:
            from claasp.ciphers.toys.toyaes_block_cipher import ToyAESBlockCipher

            toy_rounds = 10 if number_of_rounds is None else number_of_rounds
            toy_cipher = ToyAESBlockCipher(number_of_rounds=toy_rounds, word_size=word_size, state_size=state_size)

            self.__dict__ = toy_cipher.__dict__.copy()
            self._family_name = "aes_block_cipher"
            self.Nk = None
            self.Nr = toy_rounds
            return

        # Determine Nk (number of 32-bit words in key) and Nr (number of rounds)
        # FIPS-197 Table 1
        if key_bit_size == 128:
            self.Nk = 4  # Number of 32-bit words in the key
            self.Nr = 10 if number_of_rounds is None else number_of_rounds  # Number of rounds
        elif key_bit_size == 192:
            self.Nk = 6
            self.Nr = 12 if number_of_rounds is None else number_of_rounds
        elif key_bit_size == 256:
            self.Nk = 8
            self.Nr = 14 if number_of_rounds is None else number_of_rounds
        else:
            raise ValueError(f"Invalid key_bit_size: {key_bit_size}. Must be 128, 192, or 256.")
        
        super().__init__(family_name="aes_block_cipher",
                                cipher_type=BLOCK_CIPHER,
                                cipher_inputs=[INPUT_KEY, INPUT_PLAINTEXT],
                                cipher_inputs_bit_size=[key_bit_size, 128],
                                cipher_output_bit_size=128)

        # FIPS-197 notation and constants
        # Nb = 4 (number of columns/32-bit words in state) - always 4 for AES
        # Nk = number of 32-bit words in key (4, 6, or 8)
        # Nr = number of rounds (10, 12, or 14)
        self.Nb = 4  # State is always 4 words (128 bits / 32 bits)
        self.CIPHER_BLOCK_SIZE = 128  # State size in bits
        self.KEY_BLOCK_SIZE = key_bit_size  # Key size in bits
        self.SBOX_BIT_SIZE = 8  # S-box operates on bytes
        self.NUM_SBOXES = 16  # Always 16 S-boxes in the state (4x4 bytes)
        self.WORD_BIT_SIZE = 32  # Word size in bits
        self.NUM_ROWS = 4  # State has 4 rows
        
        # S-box as defined in FIPS-197 Section 5.1.1
        self.SBOX_LOOKUP_TABLE = [
                0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
                0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
                0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
                0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
                0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
                0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
                0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
                0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
                0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
                0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
                0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
                0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
                0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
                0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
                0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
                0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
            ]
        
        # Rcon: Round constants for key expansion (FIPS-197 Section 5.2)
        # Rcon[i] = (RC[i], 0x00, 0x00, 0x00) where RC[i] = x^(i-1) in GF(2^8)
        self.Rcon = [
                    "0x01000000", "0x02000000", "0x04000000", "0x08000000", 
                    "0x10000000", "0x20000000", "0x40000000", "0x80000000", 
                    "0x1B000000", "0x36000000", "0x36000000", "0x6C000000", 
                    "0xD8000000", "0xAB000000", "0x4D000000", "0x9A000000"
                ]
        
        # MixColumns transformation matrix (FIPS-197 Section 5.1.3)
        # Operates in GF(2^8) with irreducible polynomial m(x) = x^8 + x^4 + x^3 + x + 1 (0x11b)
        self.MIX_COLUMN = [
            [[0x02, 0x03, 0x01, 0x01],
             [0x01, 0x02, 0x03, 0x01], 
             [0x01, 0x01, 0x02, 0x03], 
             [0x03, 0x01, 0x01, 0x02]], 
             0x11b,  # Irreducible polynomial
             self.SBOX_BIT_SIZE]

        # FIPS-197 Algorithm 2: KEYEXPANSION(key)
        # Key schedule will be generated during cipher construction
        self.key_words = {}
        
        # FIPS-197 Algorithm 1: CIPHER(in, w)
        # Build the cipher rounds
        self.CIPHER()
    
    def KEYEXPANSION(self):
        """
        KEYEXPANSION - Generate the key schedule.
        FIPS-197 Algorithm 2: KEYEXPANSION(byte key[4*Nk], word w[Nb*(Nr+1)], Nk)
        
        Generates all key words w[0..4*Nr+3] needed for the cipher.
        - w[0..Nk-1]: Direct extraction from input key
        - w[Nk..4*Nr+3]: Generated via key expansion algorithm
        """
        # Generate ALL key words needed for the entire cipher
        # FIPS-197: KeyExpansion generates w[0..Nb*(Nr+1)-1]
        total_words = 4 * (self.Nr + 1)  # w[0..4*Nr+3] = 4*(Nr+1) words
        for word_idx in range(self.Nk, total_words):
            self.generate_key_word(word_idx)
    
    def CIPHER(self):
        """
        CIPHER - Main encryption algorithm.
        FIPS-197 Algorithm 1: CIPHER(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
        
        Algorithm structure:
            01: begin
            02:   state ← in
            03:   ADDROUNDKEY(state, w[0, Nb-1])      // Initial round whitening
            04:   for round = 1 step 1 to Nr-1
            05:     SUBBYTES(state)
            06:     SHIFTROWS(state)
            07:     MIXCOLUMNS(state)
            08:     ADDROUNDKEY(state, w[round*Nb, (round+1)*Nb-1])
            09:   end for
            10:   SUBBYTES(state)                      // Final round
            11:     SHIFTROWS(state)
            12:     ADDROUNDKEY(state, w[Nr*Nb, (Nr+1)*Nb-1])
            13:   out ← state
            14: end
        """
        for round_number in range(self.Nr):
            
            self.add_round()
            
            if round_number == 0:
                # FIPS-197 Algorithm 2: Generate key schedule before encryption
                self.KEYEXPANSION()
                
                # FIPS-197 Algorithm 1, Lines 02-03: Initial round whitening
                # Get the round key for the initial round: w[0..3]
                w_0_3 = self.get_round_key_components(0)
                
                # Line 02: state ← in (plaintext input)
                state = INPUT_PLAINTEXT
                # Line 03: state ← ADDROUNDKEY(state, w[0..3])
                state = self.ADDROUNDKEY(state, w_0_3, -1)

            # Round transformation (Lines 05-08 for rounds 1..Nr-1, Lines 10-12 for final round)
            # FIPS-197 Algorithm 1, Line 05/10: state ← SUBBYTES(state)
            state = self.SUBBYTES(state)
            
            # FIPS-197 Algorithm 1, Line 06/11: state ← SHIFTROWS(state)
            state = self.SHIFTROWS(state)
            
            # FIPS-197 Algorithm 1, Line 07: state ← MIXCOLUMNS(state) (not in final round)
            state = self.MIXCOLUMNS(round_number, state)
            
            # FIPS-197 Algorithm 1, Line 08/12: state ← ADDROUNDKEY(state, w[round*Nb..(round+1)*Nb-1])
            w = self.get_round_key_components(round_number + 1)
            state = self.ADDROUNDKEY(state, w, round_number)

            # Line 13: out ← state
            self.add_keyschedule_round_output(w)
            self.add_round_output(state, round_number)
    
    def get_round_key_components(self, round_number):
        """Get the 4 words for round key: w[4*round..4*round+3]."""
        start_word_idx = 4 * round_number
        round_key_words = []
        for word_offset in range(4):
            word_idx = start_word_idx + word_offset
            word = self.get_word(word_idx)
            round_key_words.append(word)
        return round_key_words
    
    def generate_key_word(self, word_idx):
        """
        Generate a single word w[word_idx] according to FIPS-197 Algorithm 2.
        w[i] = w[i-Nk] ⊕ temp
        """
        # Line 08: temp ← w[i−1]
        prev_word = self.get_word(word_idx - 1)
        
        # Lines 09-13: Determine temp based on i mod Nk
        if word_idx % self.Nk == 0:
            # Line 10: temp ← SUBWORD(ROTWORD(temp))⊕Rcon[i/Nk]
            
            # ROTWORD
            rotated = self.add_rotate_component(
                [prev_word.id] * 4,
                [[i for i in range(byte_idx * 8, (byte_idx + 1) * 8)] for byte_idx in range(4)],
                32, -8)
            
            # SUBWORD
            sbox_outputs = []
            for byte_idx in range(4):
                sbox_out = self.add_SBOX_component(
                    [rotated.id],
                    [[byte_idx * 8 + i for i in range(8)]],
                    8, self.SBOX_LOOKUP_TABLE)
                sbox_outputs.append(sbox_out)

            # ⊕ Rcon[i/Nk]
            rcon_idx = word_idx // self.Nk
            constant = self.add_constant_component(32, int(self.Rcon[rcon_idx - 1], 16))
            temp_input_id_links = [s.id for s in sbox_outputs] + [constant.id]
            temp_input_bit_positions = [[i for i in range(8)]] * 4 + [list(range(32))]
        elif self.Nk > 6 and word_idx % self.Nk == 4:
            # Line 12: temp ← SUBWORD(temp) for AES-256
            sbox_outputs = []
            for byte_idx in range(4):
                sbox_out = self.add_SBOX_component(
                    [prev_word.id],
                    [[byte_idx * 8 + i for i in range(8)]],
                    8, self.SBOX_LOOKUP_TABLE)
                sbox_outputs.append(sbox_out)

            temp_input_id_links = [s.id for s in sbox_outputs]
            temp_input_bit_positions = [[i for i in range(8)]] * 4
        else:
            # temp = w[i-1] (no transformation)
            temp_input_id_links = [prev_word.id]
            temp_input_bit_positions = [list(range(32))]
        
        # Line 14: w[i] ← w[i−Nk]⊕temp
        word_minus_nk = self.get_word(word_idx - self.Nk)
        new_word = self.add_XOR_component(
            [word_minus_nk.id] + temp_input_id_links,
            [list(range(32))] + temp_input_bit_positions,
            32)
        
        # Store the generated word
        self.key_words[word_idx] = new_word
        return new_word
    
    def get_word(self, word_idx):
        """
        Get word w[word_idx].
        For word_idx < Nk: Extract from input key (FIPS-197 Algorithm 2, Lines 03-06)
        For word_idx >= Nk: Return previously generated word
        """
        if word_idx in self.key_words:
            return self.key_words[word_idx]
        
        if word_idx < self.Nk:
            # Lines 03-06: w[i] ← key[4*i..4*i+3] for 0 ≤ i < Nk
            start_bit = word_idx * 32
            word_component = self.add_intermediate_output_component(
                [INPUT_KEY],
                [[start_bit + i for i in range(32)]],
                32,
                f"key_word_{word_idx}")
            self.key_words[word_idx] = word_component
            return word_component
        else:
            raise KeyError(f"Word w[{word_idx}] not found in key_words dictionary")

    def SBOX(self, s, r, c):
        """
        Apply SBOX lookup table to the byte at s[r,c] in the 4×4 state matrix.
        
        Returns:
            Component representing SBOX(s[r,c])
        """
        # Column-major byte indexing: byte_idx = c*4 + r
        byte_idx = c * self.NUM_ROWS + r
        start_bit = byte_idx * self.SBOX_BIT_SIZE
        return self.add_SBOX_component(
            [s.id],
            [[start_bit + i for i in range(self.SBOX_BIT_SIZE)]],
            self.SBOX_BIT_SIZE, self.SBOX_LOOKUP_TABLE)

    def SUBBYTES(self, s):
        """
        SUBBYTES transformation - Apply S-box to each byte of state.
        Pseudocode expanding Algorithm 1 Step 05 as described in FIPS-197 Section 5.1.1:
        SUBBYTES(s)
            for 0 ≤ r < 4 and 0 ≤ c < 4
                s[r,c] = SBOX(s[r,c]) 
            return s
        """
        s_output = []
        for c in range(self.Nb):
            for r in range(self.NUM_ROWS):
                s_rc = self.SBOX(s, r, c)
                s_output.append(s_rc)
        return s_output

    def SHIFTROWS(self, sbox_layer_components):
        """
        SHIFTROWS transformation - Cyclically shift rows.
        Pseudocode expanding Algorithm 1 Step 06 as described in FIPS-197 Section 5.1.2
        SHIFTROWS(s)
            for 0 ≤ r < 4 and 0 ≤ c < 4
                s{r,c} = s{r,(c+r) mod 4}
            return s

        """
        shift_row_layer_components = []
        for j in range(self.NUM_ROWS):
            rotation_component = self.add_rotate_component(
                [sbox_layer_components[i].id for i in
                 range(j, j + self.NUM_ROWS * (self.NUM_ROWS - 1) + 1, self.NUM_ROWS)],
                [[i for i in range(self.SBOX_BIT_SIZE)] for _ in range(self.NUM_ROWS)],
                self.WORD_BIT_SIZE,
                -self.SBOX_BIT_SIZE * j)
            shift_row_layer_components.append(rotation_component)
        return shift_row_layer_components

    def MIXCOLUMNS(self, round_number, shift_row_layer_components):
        """
        MIXCOLUMNS transformation - Mix columns.
        Pseudocode expanding Algorithm 1 Step 07 as described in FIPS-197 Section 5.1.3 
        MIXCOLUMNS(s)
            for 0 ≤ c < 4 
                ⎡s{0,c}⎤    ⎡02 03 01 01⎤   ⎡s{0,c}⎤
                ⎢s{1,c}|    ⎢01 02 03 01|   ⎢s{1,c}|
                ⎢s{2,c}| =  ⎢01 01 02 03| * ⎢s{2,c}| 
                ⎣s{3,c}⎦    ⎣03 01 01 02⎦   ⎣s{3,c}⎦
            return s
        """
        if round_number == self.Nr - 1:
            # Final round: no MIXCOLUMNS
            return shift_row_layer_components
        
        mix_column_layer_components = []
        for j in range(self.NUM_ROWS):
            mix_column_component = self.add_mix_column_component(
                [shift_row_layer_components[i].id for i in range(self.NUM_ROWS)],
                [[i for i in range(j * self.SBOX_BIT_SIZE, (j + 1) * self.SBOX_BIT_SIZE)] for _ in
                 range(self.NUM_ROWS)],
                self.WORD_BIT_SIZE,
                self.MIX_COLUMN)
            mix_column_layer_components.append(mix_column_component)
        return mix_column_layer_components

    def ADDROUNDKEY(self, s, w, round_number):
        """
        ADDROUNDKEY transformation - XOR state with round key.
        Pseudocode expanding Algorithm 1 Step 03, 08, 12 as described in FIPS-197 Section 5.1.4
        ADDROUNDKEY(s,w)
            for 0 ≤ c < 4
                [s{0,c},s{1,c},s{2,c},s{3,c}] = [s{0,c},s{1,c},s{2,c},s{3,c}]⊕[w(4*round+c)]
            return s
        """
        # Algorithm 1 Step 03: Initial round whitening (round_number == -1): plaintext XOR round key
        if s == INPUT_PLAINTEXT:
            s_id_list = [s] + [rk.id for rk in w]
            s_input_position_lists = [[i for i in range(self.CIPHER_BLOCK_SIZE)]] + \
                                     [[i for i in range(self.WORD_BIT_SIZE)] for _ in range(self.Nb)]
        else:        
            # For final round (round_number == Nr-1), we receive shift_row components
            # For other rounds, we receive mix_column components
            
            if round_number == self.Nr - 1:
                # Algorithm 1 Step 12: Final round case
                shift_rows_ids = []
                for i in range(self.NUM_ROWS):
                    shift_rows_ids.extend([s[j].id for j in range(self.NUM_ROWS)])
                shift_rows_input_position_lists = []
                for i in range(self.NUM_ROWS):
                    shift_rows_input_position_lists.extend(
                        [[j for j in range(i * self.SBOX_BIT_SIZE, (i + 1) * self.SBOX_BIT_SIZE)] for _ in
                        range(self.NUM_ROWS)])
                s_id_list = shift_rows_ids + [w[i].id for i in range(self.NUM_ROWS)]
                s_input_position_lists = shift_rows_input_position_lists + [[i for i in range(self.WORD_BIT_SIZE)] for _ in range(self.NUM_ROWS)]
                
            else:
                # Algorithm 1 Step 08: Non-final round case
                s_id_list = [s[i].id for i in range(self.NUM_ROWS)] + [w[i].id for i in range(self.NUM_ROWS)]
                s_input_position_lists = [[i for i in range(self.WORD_BIT_SIZE)] for _ in range(2 * self.NUM_ROWS)]
            
        s = self.add_XOR_component(s_id_list, s_input_position_lists, self.CIPHER_BLOCK_SIZE)
        return s

    def add_round_output(self, state_component, round_number):
        """Output the state after the round."""
        if round_number == self.Nr - 1:
            self.add_cipher_output_component([state_component.id],
                                             [[i for i in range(self.CIPHER_BLOCK_SIZE)]],
                                             self.CIPHER_BLOCK_SIZE)
        else:
            self.add_intermediate_output_component([state_component.id],
                                                   [[i for i in range(self.CIPHER_BLOCK_SIZE)]],
                                                   self.CIPHER_BLOCK_SIZE,
                                                   f"state_after_round_{round_number}")
    
    def add_keyschedule_round_output(self, w):
        """Output the round key schedule."""
        self.add_intermediate_output_component([w[i].id for i in range(self.NUM_ROWS)],
                                              [[i for i in range(self.WORD_BIT_SIZE)] for _ in range(self.NUM_ROWS)],
                                              self.CIPHER_BLOCK_SIZE,
                                              "round_key_output")
