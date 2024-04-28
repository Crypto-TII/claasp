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


import os
import sys
import inspect

import claasp
from claasp import editor
from claasp.components.cipher_output_component import CipherOutput
from claasp.compound_xor_differential_cipher import convert_to_compound_xor_cipher
from claasp.rounds import Rounds
from claasp.cipher_modules import tester, evaluator
from claasp.utils.templates import TemplateManager, CSVBuilder
from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
from claasp.cipher_modules import code_generator
import importlib
from claasp.cipher_modules.inverse_cipher import *

tii_path = inspect.getfile(claasp)
tii_dir_path = os.path.dirname(tii_path)

TII_C_LIB_PATH = f'{tii_dir_path}/cipher/'


class Cipher:


    def __init__(self, family_name, cipher_type, cipher_inputs,
                 cipher_inputs_bit_size, cipher_output_bit_size,
                 cipher_reference_code=None):
        """
        Construct an instance of the Cipher class.

        This class is used to store compact representations of a editor.

        INPUT:

        - ``family_name`` -- **string**; the name of the family of the cipher (e.g. sha, aes, speck, etc,
          with no postfix)
        - ``cipher_type`` -- **string**; type of the cipher (e.g. block, stream, hash...)
        - ``cipher_inputs`` -- **list**; list of inputs of the cipher (e.g., key, plaintext...)
        - ``cipher_inputs_bit_size`` -- **list**; list of the lengths of the inputs
        - ``cipher_output_bit_size`` -- **integer**; number of bits of the output
        - ``cipher_reference_code`` -- **string**; generated python code

        EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [6], 6)
        sage: cipher.add_round()
        sage: sbox_0_0 = cipher.add_SBOX_component(["input"], [[0,1,2]], 4, [6,7,0,1,2,3,4,5])
        sage: sbox_0_1 = cipher.add_SBOX_component(["input"], [[3,4,5]], 4, [7,0,1,2,3,4,5,6])
        sage: rotate_0_2 = cipher.add_rotate_component([sbox_0_0.id, sbox_0_1.id], [[0,1,2],[3,4,5]], 6, 3)
        sage: cipher.add_round()
        sage: sbox_1_0 = cipher.add_SBOX_component([rotate_0_2.id], [[0,1,2]], 4, [6,7,0,1,2,3,4,5])
        sage: sbox_1_1 = cipher.add_SBOX_component([rotate_0_2.id], [[3,4,5]], 4, [7,0,1,2,3,4,5,6])
        sage: rotate_1_2 = cipher.add_rotate_component([sbox_1_0.id, sbox_1_1.id], [[0,1,2],[3,4,5]], 6, 3)
        sage: cipher.id == "cipher_name_i6_o6_r2"
        True
        sage: cipher.number_of_rounds
        2
        sage: cipher.print()
        cipher_id = cipher_name_i6_o6_r2
        cipher_type = permutation
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [6]
        cipher_output_bit_size = 6
        cipher_number_of_rounds = 2
        <BLANKLINE>
           # round = 0 - round component = 0
           id = sbox_0_0
           type = sbox
           input_bit_size = 3
           input_id_link = ['input']
           input_bit_positions = [[0, 1, 2]]
           output_bit_size = 4
           description = [6, 7, 0, 1, 2, 3, 4, 5]
        <BLANKLINE>
           # round = 0 - round component = 1
           id = sbox_0_1
           type = sbox
           input_bit_size = 3
           input_id_link = ['input']
           input_bit_positions = [[3, 4, 5]]
           output_bit_size = 4
           description = [7, 0, 1, 2, 3, 4, 5, 6]
        <BLANKLINE>
           # round = 0 - round component = 2
           id = rot_0_2
           type = word_operation
           input_bit_size = 6
           input_id_link = ['sbox_0_0', 'sbox_0_1']
           input_bit_positions = [[0, 1, 2], [3, 4, 5]]
           output_bit_size = 6
           description = ['ROTATE', 3]
        <BLANKLINE>
           # round = 1 - round component = 0
           id = sbox_1_0
           type = sbox
           input_bit_size = 3
           input_id_link = ['rot_0_2']
           input_bit_positions = [[0, 1, 2]]
           output_bit_size = 4
           description = [6, 7, 0, 1, 2, 3, 4, 5]
        <BLANKLINE>
           # round = 1 - round component = 1
           id = sbox_1_1
           type = sbox
           input_bit_size = 3
           input_id_link = ['rot_0_2']
           input_bit_positions = [[3, 4, 5]]
           output_bit_size = 4
           description = [7, 0, 1, 2, 3, 4, 5, 6]
        <BLANKLINE>
           # round = 1 - round component = 2
           id = rot_1_2
           type = word_operation
           input_bit_size = 6
           input_id_link = ['sbox_1_0', 'sbox_1_1']
           input_bit_positions = [[0, 1, 2], [3, 4, 5]]
           output_bit_size = 6
           description = ['ROTATE', 3]
        cipher_reference_code = None
        """
        self._family_name = family_name
        self._type = cipher_type
        self._inputs = cipher_inputs
        self._inputs_bit_size = cipher_inputs_bit_size
        self._output_bit_size = cipher_output_bit_size
        self._rounds = Rounds()
        self._reference_code = cipher_reference_code
        self._id = self.make_cipher_id()
        self._file_name = self.make_file_name()

    def __repr__(self):
        return self.id
    def _are_there_not_forbidden_components(self, forbidden_types, forbidden_descriptions):
        return self._rounds.are_there_not_forbidden_components(forbidden_types, forbidden_descriptions)

    def add_AND_component(self, input_id_links, input_bit_positions, output_bit_size):
        return editor.add_AND_component(self, input_id_links, input_bit_positions, output_bit_size)

    def add_cipher_output_component(self, input_id_links, input_bit_positions, output_bit_size):
        return editor.add_cipher_output_component(self, input_id_links, input_bit_positions, output_bit_size)

    def add_concatenate_component(self, input_id_links, input_bit_positions, output_bit_size):
        return editor.add_concatenate_component(self, input_id_links, input_bit_positions, output_bit_size)

    def add_constant_component(self, output_bit_size, value):
        return editor.add_constant_component(self, output_bit_size, value)

    def add_FSR_component(self, input_id_links, input_bit_positions, output_bit_size, description):
        return editor.add_FSR_component(self, input_id_links, input_bit_positions, output_bit_size, description)

    def add_intermediate_output_component(self, input_id_links, input_bit_positions, output_bit_size, output_tag):
        return editor.add_intermediate_output_component(self, input_id_links, input_bit_positions,
                                                        output_bit_size, output_tag)

    def add_linear_layer_component(self, input_id_links, input_bit_positions, output_bit_size, description):
        return editor.add_linear_layer_component(self, input_id_links, input_bit_positions,
                                                 output_bit_size, description)

    def add_mix_column_component(self, input_id_links, input_bit_positions, output_bit_size, mix_column_description):
        return editor.add_mix_column_component(self, input_id_links, input_bit_positions,
                                               output_bit_size, mix_column_description)

    def add_MODADD_component(self, input_id_links, input_bit_positions, output_bit_size, modulus=None):
        return editor.add_MODADD_component(self, input_id_links, input_bit_positions, output_bit_size, modulus)

    def add_MODSUB_component(self, input_id_links, input_bit_positions, output_bit_size, modulus=None):
        return editor.add_MODSUB_component(self, input_id_links, input_bit_positions, output_bit_size, modulus)

    def add_NOT_component(self, input_id_links, input_bit_positions, output_bit_size):
        return editor.add_NOT_component(self, input_id_links, input_bit_positions, output_bit_size)

    def add_OR_component(self, input_id_links, input_bit_positions, output_bit_size):
        return editor.add_OR_component(self, input_id_links, input_bit_positions, output_bit_size)

    def add_permutation_component(self, input_id_links, input_bit_positions, output_bit_size, permutation_description):
        return editor.add_permutation_component(self, input_id_links, input_bit_positions,
                                                output_bit_size, permutation_description)

    def add_reverse_component(self, input_id_links, input_bit_positions, output_bit_size):
        return editor.add_reverse_component(self, input_id_links, input_bit_positions, output_bit_size)

    def add_rotate_component(self, input_id_links, input_bit_positions, output_bit_size, parameter):
        return editor.add_rotate_component(self, input_id_links, input_bit_positions, output_bit_size, parameter)

    def add_round(self):
        editor.add_round(self)

    def add_round_key_output_component(self, input_id_links, input_bit_positions, output_bit_size):
        return editor.add_round_key_output_component(self, input_id_links, input_bit_positions, output_bit_size)

    def add_round_output_component(self, input_id_links, input_bit_positions, output_bit_size):
        return editor.add_round_output_component(self, input_id_links, input_bit_positions, output_bit_size)

    def add_SBOX_component(self, input_id_links, input_bit_positions, output_bit_size, description):
        return editor.add_SBOX_component(self, input_id_links, input_bit_positions, output_bit_size, description)

    def add_SHIFT_component(self, input_id_links, input_bit_positions, output_bit_size, parameter):
        return editor.add_SHIFT_component(self, input_id_links, input_bit_positions, output_bit_size, parameter)

    def add_shift_rows_component(self, input_id_links, input_bit_positions, output_bit_size, parameter):
        return editor.add_shift_rows_component(self, input_id_links, input_bit_positions, output_bit_size, parameter)

    def add_sigma_component(self, input_id_links, input_bit_positions, output_bit_size, rotation_amounts_parameter):
        return editor.add_sigma_component(self, input_id_links, input_bit_positions,
                                          output_bit_size, rotation_amounts_parameter)

    def add_theta_keccak_component(self, input_id_links, input_bit_positions, output_bit_size):
        return editor.add_theta_keccak_component(self, input_id_links, input_bit_positions, output_bit_size)

    def add_theta_xoodoo_component(self, input_id_links, input_bit_positions, output_bit_size):
        return editor.add_theta_xoodoo_component(self, input_id_links, input_bit_positions, output_bit_size)

    def add_variable_rotate_component(self, input_id_links, input_bit_positions, output_bit_size, parameter):
        return editor.add_variable_rotate_component(self, input_id_links, input_bit_positions,
                                                    output_bit_size, parameter)

    def add_variable_shift_component(self, input_id_links, input_bit_positions, output_bit_size, parameter):
        return editor.add_variable_shift_component(self, input_id_links, input_bit_positions,
                                                   output_bit_size, parameter)

    def add_word_permutation_component(self, input_id_links, input_bit_positions,
                                       output_bit_size, permutation_description, word_size):
        return editor.add_word_permutation_component(self, input_id_links, input_bit_positions,
                                                     output_bit_size, permutation_description, word_size)

    def add_XOR_component(self, input_id_links, input_bit_positions, output_bit_size):
        return editor.add_XOR_component(self, input_id_links, input_bit_positions, output_bit_size)

    def as_python_dictionary(self):
        return {
            'cipher_id': self._id,
            'cipher_type': self._type,
            'cipher_inputs': self._inputs,
            'cipher_inputs_bit_size': self._inputs_bit_size,
            'cipher_output_bit_size': self._output_bit_size,
            'cipher_number_of_rounds': self.number_of_rounds,
            'cipher_rounds': self._rounds.rounds_as_python_dictionary(),
            'cipher_reference_code': self._reference_code
        }

    def component_from(self, round_number, index):
        return self._rounds.component_from(round_number, index)

    def delete_generated_evaluate_c_shared_library(self):
        """
        Delete the file named <id_cipher>_evaluate.c and the corresponding executable.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher as fancy
            sage: fancy().delete_generated_evaluate_c_shared_library() # doctest: +SKIP
        """
        code_generator.delete_generated_evaluate_c_shared_library(self)

    def evaluate(self, cipher_input, intermediate_output=False, verbosity=False):
        """
        Return the output of the cipher.

        INPUT:

        - ``cipher_input`` -- **list**; block cipher inputs
        - ``intermediate_output`` -- **boolean** (default: `False`); set this flag to True to return a dictionary with
          each intermediate output
        - ``verbosity`` -- **boolean** (default: `False`); set this flag to True to print the input/output of each
          component

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.identity_block_cipher import IdentityBlockCipher as identity
            sage: identity().evaluate([0x01234567,0x89ABCDEF])
            19088743
        """
        return evaluator.evaluate(self, cipher_input, intermediate_output, verbosity)

    def evaluate_using_c(self, inputs, intermediate_output=False, verbosity=False):
        """
        Return the output of the cipher.

        INPUT:

        - ``inputs``
        - ``intermediate_output`` -- **boolean** (default: `False`); Set this flag to True in order to return a
          dictionary with each intermediate output
        - ``verbosity`` -- **boolean** (default: `False`); Set this flag to True in order to print the input/output of
          each component

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher as fancy
            sage: fancy(number_of_rounds=2).evaluate_using_c([0x012345,0x89ABCD], True) # random
            {'round_key_output': [3502917, 73728],
             'round_output': [9834215],
             'cipher_output': [7457252]}
        """
        return evaluator.evaluate_using_c(self, inputs, intermediate_output, verbosity)

    def cipher_inverse(self):
        """
        Return the graph representation of the inverse of the cipher under analysis

        EXAMPLE::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: key = 0xabcdef01abcdef01
            sage: plaintext = 0x01234567
            sage: cipher = SpeckBlockCipher(number_of_rounds=2)
            sage: ciphertext = cipher.evaluate([plaintext, key])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext, key]) == plaintext
            True

        TEST::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: key = 0x2b7e151628aed2a6abf7158809cf4f3c
            sage: plaintext = 0x6bc1bee22e409f96e93d7e117393172a
            sage: cipher = AESBlockCipher(number_of_rounds=2)
            sage: ciphertext = cipher.evaluate([key, plaintext])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext, key]) == plaintext
            True

            sage: from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
            sage: key = 0x0e2ddd5c5b4ca9d4
            sage: plaintext = 0xb779ee0a
            sage: cipher = TeaBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: ciphertext = cipher.evaluate([plaintext, key])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext, key]) == plaintext
            True

            sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
            sage: key = 0x98edeafc899338c45fad
            sage: plaintext = 0x42c20fd3b586879e
            sage: cipher = PresentBlockCipher(number_of_rounds=2)
            sage: ciphertext = cipher.evaluate([plaintext, key])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext, key]) == plaintext
            True

            sage: from claasp.ciphers.permutations.ascon_sbox_sigma_permutation import AsconSboxSigmaPermutation
            sage: plaintext = 0
            sage: cipher = AsconSboxSigmaPermutation(number_of_rounds=2)
            sage: ciphertext = cipher.evaluate([plaintext])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext]) == plaintext
            True

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: key = 0x1211100a09080201
            sage: plaintext = 0x6120676e
            sage: cipher = SimonBlockCipher(number_of_rounds=2)
            sage: ciphertext = cipher.evaluate([plaintext, key])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext, key]) == plaintext
            True

            sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
            sage: key = 0x687ded3b3c85b3f35b1009863e2a8cbf
            sage: plaintext = 0x42c20fd3b586879e
            sage: cipher = MidoriBlockCipher(number_of_rounds=2)
            sage: ciphertext = cipher.evaluate([plaintext, key])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext, key]) == plaintext
            True

            sage: from claasp.ciphers.block_ciphers.skinny_block_cipher import SkinnyBlockCipher
            sage: key = 0xffffeeee
            sage: plaintext = 0x5778
            sage: cipher = SkinnyBlockCipher(number_of_rounds=2)
            sage: ciphertext = cipher.evaluate([plaintext, key])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext, key]) == plaintext
            True

            sage: from claasp.ciphers.permutations.spongent_pi_permutation import SpongentPiPermutation
            sage: plaintext = 0x1234
            sage: cipher = SpongentPiPermutation(number_of_rounds=2)
            sage: ciphertext = cipher.evaluate([plaintext])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext]) == plaintext
            True

            sage: from claasp.ciphers.block_ciphers.xtea_block_cipher import XTeaBlockCipher
            sage: key = 0x1de1c3c2c65880074c32dce537b22ab3
            sage: plaintext = 0xbd7d764dff0ada1e
            sage: cipher = XTeaBlockCipher(number_of_rounds=2)
            sage: ciphertext = cipher.evaluate([plaintext, key])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext, key]) == plaintext
            True

            sage: from claasp.ciphers.permutations.photon_permutation import PhotonPermutation
            sage: plaintext = 0x1234
            sage: cipher = PhotonPermutation(number_of_rounds=2)
            sage: ciphertext = cipher.evaluate([plaintext])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext]) == plaintext
            True

            sage: from claasp.ciphers.block_ciphers.lea_block_cipher import LeaBlockCipher
            sage: key = 0x0f1e2d3c4b5a69788796a5b4c3d2e1f0
            sage: plaintext = 0x101112131415161718191a1b1c1d1e1f
            sage: cipher = LeaBlockCipher(block_bit_size=128, key_bit_size=128, number_of_rounds=2)
            sage: ciphertext = cipher.evaluate([plaintext, key])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext, key]) == plaintext
            True

            sage: from claasp.ciphers.permutations.sparkle_permutation import SparklePermutation
            sage: plaintext = 0x1234
            sage: cipher = SparklePermutation(number_of_steps=2)
            sage: ciphertext = cipher.evaluate([plaintext])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext]) == plaintext
            True

            sage: from claasp.ciphers.permutations.xoodoo_invertible_permutation import XoodooInvertiblePermutation
            sage: plaintext = 0x1234
            sage: cipher = XoodooInvertiblePermutation(number_of_rounds=2)
            sage: ciphertext = cipher.evaluate([plaintext])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext]) == plaintext
            True

            sage: from claasp.ciphers.permutations.gift_sbox_permutation import GiftSboxPermutation
            sage: key = 0x000102030405060708090A0B0C0D0E0F
            sage: plaintext = 0x000102030405060708090A0B0C0D0E0F
            sage: cipher = GiftSboxPermutation(number_of_rounds=2)
            sage: ciphertext = cipher.evaluate([plaintext, key])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext, key]) == plaintext
            True

            sage: from claasp.ciphers.block_ciphers.raiden_block_cipher import RaidenBlockCipher
            sage: key = 0x1de1c3c2c65880074c32dce537b22ab3
            sage: plaintext = 0xbd7d764dff0ada1e
            sage: cipher = RaidenBlockCipher(number_of_rounds=2)
            sage: ciphertext = cipher.evaluate([plaintext, key])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext, key]) == plaintext
            True

            sage: from claasp.ciphers.block_ciphers.hight_block_cipher import HightBlockCipher
            sage: key = 0x000000066770000000a0000000000001
            sage: plaintext = 0x0011223344556677
            sage: cipher = HightBlockCipher(block_bit_size=64, key_bit_size=128, number_of_rounds=2)
            sage: ciphertext = cipher.evaluate([plaintext, key])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext, key]) == plaintext
            True

            sage: from claasp.ciphers.block_ciphers.des_block_cipher import DESBlockCipher
            sage: cipher = DESBlockCipher(number_of_rounds=4)
            sage: key = 0x133457799BBCDFF1
            sage: plaintext = 0x0123456789ABCDEF
            sage: ciphertext = cipher.evaluate([key, plaintext])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext, key]) == plaintext
            True

            sage: from claasp.ciphers.permutations.salsa_permutation import SalsaPermutation
            sage: cipher = SalsaPermutation(number_of_rounds=5)
            sage: plaintext = 0xffff
            sage: ciphertext = cipher.evaluate([plaintext])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext]) == plaintext
            True

            sage: from claasp.ciphers.block_ciphers.bea1_block_cipher import BEA1BlockCipher
            sage: cipher = BEA1BlockCipher(number_of_rounds=2)
            sage: key = 0x8cdd0f3459fb721e798655298d5c1
            sage: plaintext = 0x47a57eff5d6475a68916
            sage: ciphertext = cipher.evaluate([key, plaintext])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext, key]) == plaintext
            True

            sage: from claasp.ciphers.permutations.keccak_invertible_permutation import KeccakInvertiblePermutation
            sage: plaintext = 0x1234
            sage: cipher = KeccakInvertiblePermutation(number_of_rounds=2, word_size=8)
            sage: ciphertext = cipher.evaluate([plaintext])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext]) == plaintext
            True

            sage: from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation
            sage: cipher = ChachaPermutation(number_of_rounds=5)
            sage: plaintext = 0xffff
            sage: ciphertext = cipher.evaluate([plaintext])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext]) == plaintext
            True

            sage: from claasp.ciphers.permutations.gimli_sbox_permutation import GimliSboxPermutation
            sage: cipher = GimliSboxPermutation(number_of_rounds=2, word_size=32)
            sage: plaintext = 0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
            sage: ciphertext = cipher.evaluate([plaintext])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext]) == plaintext
            False # loop 356

            sage: from claasp.ciphers.block_ciphers.sparx_block_cipher import SparxBlockCipher
            sage: plaintext = 0x0123456789abcdef
            sage: key = 0x00112233445566778899aabbccddeeff
            sage: cipher = SparxBlockCipher(number_of_rounds=2)
            sage: ciphertext = cipher.evaluate([plaintext, key])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext, key]) == plaintext
            False # loop 66

            sage: from claasp.ciphers.block_ciphers.threefish_block_cipher import ThreefishBlockCipher
            sage: cipher = ThreefishBlockCipher(number_of_rounds=2)
            sage: plaintext = 0xF8F9FAFBFCFDFEFFF0F1F2F3F4F5F6F7E8E9EAEBECEDEEEFE0E1E2E3E4E5E6E7
            sage: key = 0x17161514131211101F1E1D1C1B1A191827262524232221202F2E2D2C2B2A2928
            sage: tweak = 0x07060504030201000F0E0D0C0B0A0908
            sage: ciphertext = cipher.evaluate([plaintext, key, tweak])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext, key, tweak]) == plaintext
            False # loop 29


            sage: from claasp.ciphers.permutations.tinyjambu_permutation import TinyJambuPermutation
            sage: cipher = TinyJambuPermutation(number_of_rounds=2)
            sage: plaintext = 0xffff
            sage: key = 0x1234
            sage: ciphertext = cipher.evaluate([key, plaintext])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext, key]) == plaintext
            False # loop 8

            sage: from claasp.ciphers.block_ciphers.lowmc_block_cipher import LowMCBlockCipher
            sage: cipher = LowMCBlockCipher(block_bit_size=192, key_bit_size=192, number_of_rounds=4)
            sage: key = 0x800000000000000000000000000000000000000000000000
            sage: plaintext = 0xABFF00000000000000000000000000000000000000000000
            sage: ciphertext = cipher.evaluate([key, plaintext])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext, key]) == plaintext
            False # loop 274

            sage: from claasp.ciphers.block_ciphers.twofish_block_cipher import TwofishBlockCipher
            sage: cipher = TwofishBlockCipher(key_length=256, number_of_rounds=2)
            sage: key = 0xD43BB7556EA32E46F2A282B7D45B4E0D57FF739D4DC92C1BD7FC01700CC8216F
            sage: plaintext = 0x90AFE91BB288544F2C32DC239B2635E6
            sage: ciphertext = cipher.evaluate([key, plaintext])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext, key]) == plaintext
            True

            sage: from claasp.ciphers.block_ciphers.kasumi_block_cipher import KasumiBlockCipher
            sage: cipher = KasumiBlockCipher(number_of_rounds=2)
            sage: key = 0x9900aabbccddeeff1122334455667788
            sage: plaintext = 0xfedcba0987654321
            sage: ciphertext = cipher.evaluate([key, plaintext])
            sage: cipher_inv = cipher.cipher_inverse()
            sage: cipher_inv.evaluate([ciphertext, key]) == plaintext
            False # loop 96

        """
        inverted_cipher = Cipher(f"{self.id}{CIPHER_INVERSE_SUFFIX}", f"{self.type}", [], [], self.output_bit_size)

        inverted_cipher_components = []
        cipher_components_tmp = get_cipher_components(self)
        available_bits = []
        key_schedule_component_ids = get_key_schedule_component_ids(self)
        all_equivalent_bits = get_all_equivalent_bits(self)
        while len(cipher_components_tmp) > 0:
            # print(len(cipher_components_tmp))
            number_of_unprocessed_components = 0
            for c in cipher_components_tmp:
                # print(c.id, "---------", len(cipher_components_tmp))
                # OPTION 1 - Add components that are not invertible
                if are_there_enough_available_inputs_to_evaluate_component(c, available_bits, all_equivalent_bits,
                                                                           key_schedule_component_ids, self):
                    # print("--------> evaluated")
                    inverted_component = evaluated_component(c, available_bits, key_schedule_component_ids,
                                                             all_equivalent_bits, self)
                    update_available_bits_with_component_output_bits(c, available_bits, self)
                    inverted_cipher_components.append(inverted_component)
                    cipher_components_tmp.remove(c)
                # OPTION 2 - Add components that are invertible
                elif (is_possibly_invertible_component(c) and are_there_enough_available_inputs_to_perform_inversion(c,
                                                                                                                     available_bits,
                                                                                                                     all_equivalent_bits,
                                                                                                                     self)) or (
                        c.type == CIPHER_INPUT and (c.description[0] == INPUT_KEY or c.description[0] == INPUT_TWEAK)):
                    # print("--------> inverted")
                    inverted_component = component_inverse(c, available_bits, all_equivalent_bits,
                                                           key_schedule_component_ids, self)
                    update_available_bits_with_component_input_bits(c, available_bits)
                    update_available_bits_with_component_output_bits(c, available_bits, self)
                    inverted_cipher_components.append(inverted_component)
                    cipher_components_tmp.remove(c)
                else:
                    number_of_unprocessed_components += 1
                    if number_of_unprocessed_components == len(cipher_components_tmp):
                        raise Error("Unable to invert cipher for now.")

                        # STEP 3 - rebuild cipher
        for _ in range(self.number_of_rounds):
            inverted_cipher.add_round()
        for component in inverted_cipher_components:
            if component.type == CIPHER_INPUT:
                inverted_cipher.inputs.append(component.id)
                inverted_cipher.inputs_bit_size.append(component.output_bit_size)
            elif component.type == CIPHER_OUTPUT:
                inverted_cipher._rounds.round_at(self.number_of_rounds - 1)._components.append(component)
            elif component.id in key_schedule_component_ids:
                inverted_cipher._rounds.round_at(0)._components.append(component)
            else:
                inverted_cipher._rounds.round_at(self.number_of_rounds - 1 - component.round)._components.append(
                    component)

        sorted_inverted_cipher = sort_cipher_graph(inverted_cipher)

        return sorted_inverted_cipher

    def get_partial_cipher(self, start_round=None, end_round=None, keep_key_schedule=True):

        if start_round is None:
            start_round = 0
        if end_round is None:
            end_round = self.number_of_rounds - 1

        assert end_round < self.number_of_rounds
        assert start_round <= end_round

        inputs = deepcopy(self.inputs)
        partial_cipher = Cipher(f"{self.family_name}_partial_{start_round}_to_{end_round}", f"{self.type}", inputs,
                                self._inputs_bit_size, self.output_bit_size)
        for round in self.rounds_as_list:
            partial_cipher.rounds_as_list.append(deepcopy(round))

        removed_components_ids, intermediate_outputs = remove_components_from_rounds(partial_cipher, start_round,
                                                                                     end_round, keep_key_schedule)

        if start_round > 0:
            for input_type in set([input for input in self.inputs if INPUT_KEY not in input]):
                removed_components_ids.append(input_type)
                input_index = partial_cipher.inputs.index(input_type)
                partial_cipher.inputs.pop(input_index)
                partial_cipher.inputs_bit_size.pop(input_index)

            partial_cipher.inputs.insert(0, intermediate_outputs[start_round - 1].id)
            partial_cipher.inputs_bit_size.insert(0, intermediate_outputs[start_round - 1].output_bit_size)
            update_input_links_from_rounds(partial_cipher.rounds_as_list[start_round:end_round + 1],
                                           removed_components_ids, intermediate_outputs)

        if end_round < self.number_of_rounds - 1:
            removed_components_ids.append(CIPHER_OUTPUT)
            last_round = partial_cipher.rounds_as_list[end_round]
            for component in last_round.components:
                if component.description == ['round_output']:
                    last_round.remove_component(component)
                    new_cipher_output = Component(component.id, CIPHER_OUTPUT,
                                                  Input(component.output_bit_size, component.input_id_links,
                                                        component.input_bit_positions),
                                                  component.output_bit_size, [CIPHER_OUTPUT])
                    new_cipher_output.__class__ = CipherOutput
                    last_round.add_component(new_cipher_output)

        return partial_cipher

    def add_suffix_to_components(self, suffix, component_id_list=None):
        renamed_inputs = self.inputs
        if component_id_list is None:
            component_id_list = self.get_all_components_ids() + self.inputs
            renamed_inputs = [f"{input}{suffix}" if input in component_id_list else input for input in self.inputs]
        renamed_cipher = Cipher(f"{self.family_name}", f"{self.type}", renamed_inputs,
                                self.inputs_bit_size, self.output_bit_size)
        for round in self.rounds_as_list:
            renamed_cipher.add_round()
            for component_number in range(round.number_of_components):
                component = round.component_from(component_number)
                renamed_input_id_links = [f"{id}{suffix}" if id in component_id_list else id for id in
                                          component.input_id_links]
                if component.id in component_id_list:
                    renamed_component_id = f'{component.id}{suffix}'
                else:
                    renamed_component_id = component.id
                renamed_component = Component(renamed_component_id, component.type,
                                              Input(component.input_bit_size, renamed_input_id_links,
                                                    component.input_bit_positions),
                                              component.output_bit_size, component.description)
                renamed_component.__class__ = component.__class__
                renamed_cipher.rounds.current_round.add_component(renamed_component)

        return renamed_cipher

    def cipher_partial_inverse(self, start_round=None, end_round=None, keep_key_schedule=False):
        """
        Returns the inverted portion of a cipher.

        INPUT:

        - ``start_round`` -- **integer**; initial round number of the partial cipher
        - ``end_round`` -- **integer**; final round number of the partial cipher

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: key = 0xabcdef01abcdef01
            sage: plaintext = 0x01234567
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: result = speck.evaluate([plaintext, key], intermediate_output=True)
            sage: partial_speck = speck.cipher_partial_inverse(1, 2)
            sage: partial_speck.evaluate([result[0], key]) == result[2]['intermediate_output_0_6'][0]

        """

        partial_cipher = self.get_partial_cipher(start_round, end_round, True)
        partial_cipher_inverse = partial_cipher.cipher_inverse()

        key_schedule_component_ids = get_key_schedule_component_ids(partial_cipher_inverse)
        key_schedule_components = [partial_cipher_inverse.get_component_from_id(id) for id in key_schedule_component_ids
                                   if
                                   INPUT_KEY not in id]

        if not keep_key_schedule:
            for current_round in partial_cipher_inverse.rounds_as_list:
                for key_component in set(key_schedule_components).intersection(current_round.components):
                    partial_cipher_inverse.rounds.remove_round_component(current_round.id, key_component)

        return partial_cipher_inverse

    def evaluate_vectorized(self, cipher_input, intermediate_outputs=False, verbosity=False, evaluate_api = False):
        """
        Return the output of the cipher for multiple inputs.

        The inputs are given as a list cipher_input,such that cipher_inputs[0] contains the first input,
        and cipher_inputs[1] the second.
        Each of the inputs is given as a numpy ndarray of np.uint8, of shape n*m, where n is the size
        (in bytes) of the input, and m is the number of samples.

        The return is a list of m*n ndarrays (format transposed compared to the input format),
        where the list is of size 1 if intermediate_output is False, and NUMBER_OF_ROUNDS otherwise.

        This function determines automatically if a bit-based evaluation is required,
        and does the transformation transparently. The inputs and outputs are similar to evaluate_vectorized_byte.

        INPUT:

        - ``cipher_input`` -- **list**; block cipher inputs (ndarray of uint8 representing one byte each, n rows, m columns,
          with m the number of inputs to evaluate)
        - ``intermediate_outputs`` -- **boolean** (default: `False`)
        - ``verbosity`` -- **boolean** (default: `False`); set this flag to True in order to print the input/output of
          each component
        - ``evaluate_api`` -- **boolean** (default: `False`); if set to True, takes integer inputs (as the evaluate function)
        and returns integer inputs; it is expected that cipher.evaluate(x) == cipher.evaluate_vectorized(x, evaluate_api = True)
        is True.
        EXAMPLES::

            sage: import numpy as np
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher as speck
            sage: speck = speck(block_bit_size=32, key_bit_size=64, number_of_rounds=22)
            sage: K=np.random.randint(256, size=(8,2), dtype=np.uint8)
            sage: X=np.random.randint(256, size=(4,2), dtype=np.uint8)
            sage: result=speck.evaluate_vectorized([X, K])
            sage: K0Lib=int.from_bytes(K[:,0].tobytes(), byteorder='big')
            sage: K1Lib=int.from_bytes(K[:,1].tobytes(), byteorder='big')
            sage: X0Lib=int.from_bytes(X[:,0].tobytes(), byteorder='big')
            sage: X1Lib=int.from_bytes(X[:,1].tobytes(), byteorder='big')
            sage: C0Lib=speck.evaluate([X0Lib, K0Lib])
            sage: C1Lib=speck.evaluate([X1Lib, K1Lib])
            sage: int.from_bytes(result[-1][0].tobytes(), byteorder='big') == C0Lib
            True
            sage: int.from_bytes(result[-1][1].tobytes(), byteorder='big') == C1Lib
            True
        """
        return evaluator.evaluate_vectorized(self, cipher_input, intermediate_outputs, verbosity, evaluate_api)

    def evaluate_with_intermediate_outputs_continuous_diffusion_analysis(
            self, cipher_input, sbox_precomputations, sbox_precomputations_mix_columns, verbosity=False):
        """
        Return the output of the continuous generalized cipher.

        INPUT:

        - ``cipher_input`` -- **list of Decimal**; block cipher input message
        - ``sbox_precomputations`` **dictionary**
        - ``sbox_precomputations_mix_columns`` **dictionary**
        - ``verbosity`` -- **boolean** (default: `False`); set this flag to True in order to print the input/output of
          each component


        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher as speck
            sage: from decimal import *
            sage: plaintext_input = [Decimal('1') for i in range(32)]
            sage: plaintext_input[10] = Decimal('0.802999073954890452142763024312444031238555908203125')
            sage: key_input = [Decimal('-1') for i in range(64)]
            sage: cipher_inputs = [plaintext_input, key_input]
            sage: output = speck(number_of_rounds=2).evaluate_with_intermediate_outputs_continuous_diffusion_analysis(
            ....:     cipher_inputs,
            ....:     {},
            ....:     {}
            ....: )
            sage: output[0][0] == Decimal('-1.000000000')
            True
        """
        return evaluator.evaluate_with_intermediate_outputs_continuous_diffusion_analysis(
            self, cipher_input, sbox_precomputations, sbox_precomputations_mix_columns, verbosity)

    def generate_bit_based_c_code(self, intermediate_output=False, verbosity=False):
        """
        Return a string containing the C code that defines the self.evaluate() method.

        INPUT:

        - ``intermediate_output`` -- **boolean** (default: `False`); set this flag to True in order to return a
          dictionary with each intermediate output
        - ``verbosity`` -- **boolean** (default: `False`); set this flag to True in order to make the code print the
          input/output of each component

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher as fancy
            sage: s = fancy().generate_bit_based_c_code()
            sage: s[:8] == '#include'
            True
        """
        return code_generator.generate_bit_based_c_code(self, intermediate_output, verbosity)

    def generate_evaluate_c_code_shared_library(self, intermediate_output=False, verbosity=False):
        """
        Store the C code in a file named <id_cipher>_evaluate.c, and build the corresponding executable.

        INPUT:

        - ``intermediate_output`` -- **boolean** (default: `False`); set this flag to True in order to make the C code
          print a dictionary with each intermediate output
        - ``verbosity`` -- **boolean** (default: `False`); set this flag to True in order to make the C code print the
          input/output of each component

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher as fancy
            sage: fancy().generate_evaluate_c_code_shared_library() # doctest: +SKIP
        """
        code_generator.generate_evaluate_c_code_shared_library(self, intermediate_output, verbosity)

    def generate_word_based_c_code(self, word_size, intermediate_output=False, verbosity=False):
        """
        Return a string containing the optimized C code that defines the self.evaluate() method.

        INPUT:

        - ``word_size`` -- **integer**; the size of the word
        - ``intermediate_output`` -- **boolean** (default: `False`); set this flag to True in order to return a
          dictionary with each intermediate output
        - ``verbosity`` -- **boolean** (default: `False`); set this flag to True in order to make the code print the
          input/output of each component

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher as speck
            sage: word_based_c_code = speck().generate_word_based_c_code(20)
            sage: word_based_c_code[:8] == '#include'
            True
        """
        return code_generator.generate_word_based_c_code(self, word_size, intermediate_output, verbosity)

    def get_all_components(self):
        return self._rounds.get_all_components()

    def get_all_components_ids(self):
        return self._rounds.get_all_components_ids()

    def get_all_inputs_bit_positions(self):
        return {cipher_input: range(bit_size) for cipher_input, bit_size in zip(self._inputs, self._inputs_bit_size)}

    def get_component_from_id(self, component_id):
        """
        Return the component according to the id given as input.

        INPUT:

        - ``id_component`` -- **string**; id of a component

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=2)
            sage: component = fancy.get_component_from_id('sbox_0_0')
            sage: component.description
            [0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15]
        """
        return self._rounds.get_component_from_id(component_id)

    def get_components_in_round(self, round_number):
        return self._rounds.components_in_round(round_number)

    def get_current_component_id(self):
        """
        Use this function to get the current component id.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.cipher import Cipher
            sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
            sage: cipher.add_round()
            sage: constant_0_0 = cipher.add_constant_component(4, 0xF)
            sage: constant_0_1 = cipher.add_constant_component(4, 0xF)
            sage: cipher.add_round()
            sage: constant_1_0 = cipher.add_constant_component(4, 0xF)
            sage: cipher.get_current_component_id()
            'constant_1_0'
        """
        if self.current_round_number is None:
            return "no component in this cipher"
        index_of_last_component = self._rounds.current_round_number_of_components - 1
        return self._rounds.component_from(self.current_round_number, index_of_last_component).id

    def get_number_of_components_in_round(self, round_number):
        return self._rounds.number_of_components(round_number)

    def get_round_from_component_id(self, component_id):
        """
        Return the round according to the round of the component id given as input.

        INPUT:

        - ``id_component`` -- **string**; id of a component

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=2)
            sage: fancy.get_round_from_component_id('xor_1_14')
            1
        """
        return self._rounds.get_round_from_component_id(component_id)

    def impossible_differential_search(self, technique="sat", solver="Kissat", scenario="single-key"):
        """
        Return a list of impossible differentials if there are any; otherwise return an empty list
        INPUT:

        - ``technique`` -- **string**; {"sat", "smt", "milp", "cp"}: the technique to use for the search
        - ``solver`` -- **string**; the name of the solver to use for the search
        - ``scenario`` -- **string**; the type of impossible differentials to search, single-key or related-key
        """
        return self.find_impossible_property(type="differential", technique=technique, solver=solver, scenario=scenario)

    def is_algebraically_secure(self, timeout):
        """
        Return `True` if the cipher is resistant against algebraic attack.

        INPUT:

        - ``timeout`` -- **integer**; the timeout for the Grobner basis computation in seconds
        """
        algebraic_model = AlgebraicModel(self)
        return algebraic_model.is_algebraically_secure(timeout)

    def is_andrx(self):
        """
        Return True if the cipher is AndRX, False otherwise.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
            sage: midori = MidoriBlockCipher(number_of_rounds=20)
            sage: midori.is_andrx()
            False
        """
        forbidden_types = {'sbox', 'mix_column', 'linear_layer'}
        forbidden_descriptions = {'OR', 'MODADD', 'MODSUB', 'SHIFT', 'SHIFT_BY_VARIABLE_AMOUNT'}

        return self._are_there_not_forbidden_components(forbidden_types, forbidden_descriptions)

    def is_arx(self):
        """
        Return True if the cipher is ARX, False otherwise.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
            sage: midori = MidoriBlockCipher(number_of_rounds=20)
            sage: midori.is_arx()
            False
        """
        forbidden_types = {'sbox', 'mix_column', 'linear_layer'}
        forbidden_descriptions = {'OR', 'AND', 'MODSUB', 'SHIFT', 'SHIFT_BY_VARIABLE_AMOUNT'}

        return self._are_there_not_forbidden_components(forbidden_types, forbidden_descriptions)

    def is_power_of_2_word_based(self):
        """
        Return the word size if the cipher is word based (64, 32, 16 or 8 bits), False otherwise.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.xtea_block_cipher import XTeaBlockCipher
            sage: XTeaBlockCipher(number_of_rounds=32).is_power_of_2_word_based()
            32
            sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
            sage: MidoriBlockCipher(number_of_rounds=16).is_power_of_2_word_based()
            False
        """
        return self._rounds.is_power_of_2_word_based()

    def is_shift_arx(self):
        """
        Return True if the cipher is Shift-ARX, False otherwise.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.xtea_block_cipher import XTeaBlockCipher
            sage: xtea = XTeaBlockCipher(number_of_rounds=32)
            sage: xtea.is_shift_arx()
            True
        """
        forbidden_types = {'sbox', 'mix_column', 'linear_layer'}
        forbidden_descriptions = {'AND', 'OR', 'MODSUB'}

        return self._are_there_not_forbidden_components(forbidden_types, forbidden_descriptions)

    def is_spn(self):
        """
        Return True if the cipher is SPN.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: aes.is_spn()
            True
        """
        spn_components = {CIPHER_OUTPUT, CONSTANT, INTERMEDIATE_OUTPUT, MIX_COLUMN,
                          SBOX, 'ROTATE', 'XOR'}
        set_of_components, set_of_mix_column_sizes, set_of_rotate_and_shift_values, set_of_sbox_sizes = \
            self.get_sizes_of_components_by_type()
        if (len(set_of_sbox_sizes) > 1) or (len(set_of_mix_column_sizes) > 1):
            return False
        sbox_size = 0
        mix_column_size = 0
        if len(set_of_sbox_sizes) > 0:
            sbox_size = set_of_sbox_sizes.pop()
        if len(set_of_mix_column_sizes) > 0:
            mix_column_size = set_of_mix_column_sizes.pop()
        if sbox_size == 0 and mix_column_size == 0 or sbox_size != mix_column_size:
            return False
        check_size = max([sbox_size, mix_column_size])
        for value in set_of_rotate_and_shift_values:
            if value % check_size != 0:
                return False
        return set_of_components <= spn_components

    def get_model(self, technique, problem):
        """
        Returns a model for a given technique and problem.

        INPUT:

          - ``technique`` -- **string** ; sat, smt, milp or cp
          - ``problem`` -- **string** ; xor_differential, xor_linear, cipher_model (more to be added as more model types are added to the library)
          """
        if problem == 'xor_differential':
            constructor_name = f'{technique[0].capitalize()}{technique[1:]}XorDifferentialModel'
        elif problem == "xor_linear":
            constructor_name = f'{technique[0].capitalize()}{technique[1:]}XorLinearModel'
        elif problem == 'cipher_model':
            constructor_name = f'{technique[0].capitalize()}{technique[1:]}CipherModel'

        module_name = f'claasp.cipher_modules.models.{technique}.{technique}_models.{technique}_{problem}_model'

        module = importlib.import_module(module_name)
        constructor = getattr(module, constructor_name)
        return constructor(self)

    def get_sizes_of_components_by_type(self):
        set_of_sbox_sizes = set()
        set_of_mix_column_sizes = set()
        set_of_components = set()
        set_of_rotate_and_shift_values = set()
        for component in self._rounds.get_all_components():
            if component.type == SBOX:
                set_of_sbox_sizes.add(component.input_bit_size)
            if component.type == MIX_COLUMN:
                set_of_mix_column_sizes.add(component.description[2])
            if component.type == WORD_OPERATION:
                set_of_components.add(component.description[0])
                if component.description[0] == 'ROTATE' or component.description[0] == 'SHIFT':
                    set_of_rotate_and_shift_values.add(component.description[1])
            else:
                set_of_components.add(component.type)
        return set_of_components, set_of_mix_column_sizes, set_of_rotate_and_shift_values, set_of_sbox_sizes

    def make_cipher_id(self):
        return editor.make_cipher_id(self._family_name, self._inputs, self._inputs_bit_size,
                                     self._output_bit_size, self.number_of_rounds)

    def make_file_name(self):
        return editor.make_file_name(self._id)

    def print(self):
        """
        Print the structure of the cipher into the sage terminal.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.cipher import Cipher
            sage: cipher = Cipher("cipher_name", "permutation", ["input"], [32], 32)
            sage: cipher.add_round()
            sage: constant_0_0 = cipher.add_constant_component(16, 0xAB01)
            sage: constant_0_1 = cipher.add_constant_component(16, 0xAB01)
            sage: cipher.print()
            cipher_id = cipher_name_i32_o32_r1
            cipher_type = permutation
            cipher_inputs = ['input']
            cipher_inputs_bit_size = [32]
            cipher_output_bit_size = 32
            cipher_number_of_rounds = 1
            <BLANKLINE>
                # round = 0 - round component = 0
                id = constant_0_0
                type = constant
                input_bit_size = 0
                input_id_link = ['']
                input_bit_positions = [[]]
                output_bit_size = 16
                description = ['0xab01']
            <BLANKLINE>
                # round = 0 - round component = 1
                id = constant_0_1
                type = constant
                input_bit_size = 0
                input_id_link = ['']
                input_bit_positions = [[]]
                output_bit_size = 16
                description = ['0xab01']
            cipher_reference_code = None
        """
        print("cipher_id = " + self._id)
        print("cipher_type = " + self._type)
        print(f"cipher_inputs = {self._inputs}")
        print(f"cipher_inputs_bit_size = {self._inputs_bit_size}")
        print(f"cipher_output_bit_size = {self._output_bit_size}")
        print(f"cipher_number_of_rounds = {self._rounds.number_of_rounds}")
        self._rounds.print_rounds()
        if self._reference_code:
            print(f"cipher_reference_code = {self._reference_code}")
        else:
            print("cipher_reference_code = None")

    def print_as_python_dictionary(self):
        """
        Use this function to print the cipher as a python dictionary into the sage terminal.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.cipher import Cipher
            sage: cipher = Cipher("cipher_name", "block_cipher", ["key", "plaintext"], [32, 32], 32)
            sage: cipher.add_round()
            sage: constant_0_0 = cipher.add_constant_component(16, 0xAB01)
            sage: constant_0_1 = cipher.add_constant_component(16, 0xAB01)
            sage: cipher.print_as_python_dictionary()
            cipher = {
            'cipher_id': 'cipher_name_k32_p32_o32_r1',
            'cipher_type': 'block_cipher',
            'cipher_inputs': ['key', 'plaintext'],
            'cipher_inputs_bit_size': [32, 32],
            'cipher_output_bit_size': 32,
            'cipher_number_of_rounds': 1,
            'cipher_rounds' : [
              # round 0
              [
              {
                # round = 0 - round component = 0
                'id': 'constant_0_0',
                'type': 'constant',
                'input_bit_size': 0,
                'input_id_link': [''],
                'input_bit_positions': [[]],
                'output_bit_size': 16,
                'description': ['0xab01'],
              },
              {
                # round = 0 - round component = 1
                'id': 'constant_0_1',
                'type': 'constant',
                'input_bit_size': 0,
                'input_id_link': [''],
                'input_bit_positions': [[]],
                'output_bit_size': 16,
                'description': ['0xab01'],
              },
              ],
              ],
            'cipher_reference_code': None,
            }
        """
        print("cipher = {")
        print("'cipher_id': '" + self._id + "',")
        print("'cipher_type': '" + self._type + "',")
        print(f"'cipher_inputs': {self._inputs},")
        print(f"'cipher_inputs_bit_size': {self._inputs_bit_size},")
        print(f"'cipher_output_bit_size': {self._output_bit_size},")
        print(f"'cipher_number_of_rounds': {self._rounds.number_of_rounds},")
        print("'cipher_rounds' : [")
        self._rounds.print_rounds_as_python_dictionary()
        print("  ],")
        if self._reference_code:
            print(f"'cipher_reference_code': \n'''{self._reference_code}''',")
        else:
            print("'cipher_reference_code': None,")
        print("}")

    def print_as_python_dictionary_to_file(self, file_name=""):
        """
        Use this function to print the cipher as a python dictionary to a file.

        INPUT:

        - ``file_name`` -- **string**; a python string representing a valid file name

        EXAMPLES::

            sage: from claasp.cipher import Cipher
            sage: cipher = Cipher("cipher_name", "block_cipher", ["key", "plaintext"], [32, 32], 32)
            sage: cipher.print_as_python_dictionary_to_file("claasp/ciphers/dictionary_example.py")
            sage: os.remove("claasp/ciphers/dictionary_example.py")
        """
        original_stdout = sys.stdout  # Save a reference to the original standard output
        if file_name == "":
            file_name = self._file_name
        with open(file_name, 'w') as f:
            sys.stdout = f  # Change the standard output to the file we created.
            self.print_as_python_dictionary()
        sys.stdout = original_stdout  # Reset the standard output to its original value

    def print_evaluation_python_code(self, verbosity=False):
        """
        Print the python code that implement the evaluation function of the cipher.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.identity_block_cipher import IdentityBlockCipher as identity
            sage: identity().print_evaluation_python_code() # random
            from copy import copy
            from bitstring import BitArray
            from claasp.cipher_modules.generic_functions import *

            def evaluate(input):
                plaintext_output = copy(BitArray(uint=input[0], length=32))
                key_output = copy(BitArray(uint=input[1], length=32))
                intermediate_output = {}
                intermediate_output['cipher_output'] = []
                intermediate_output['round_key_output'] = []
                components_io = {}
                component_input = BitArray(1)
            <BLANKLINE>
                # round: 0, component: 0, component_id: concatenate_0_0
                component_input = select_bits(key_output, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31])
                output_bit_size = 32
                concatenate_0_0_output = component_input
                components_io['concatenate_0_0'] = [component_input.uint, concatenate_0_0_output.uint]
            <BLANKLINE>
                # round: 0, component: 1, component_id: intermediate_output_0_1
                component_input = select_bits(concatenate_0_0_output, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31])
                output_bit_size = 32
                intermediate_output_0_1_output = component_input
                intermediate_output['round_key_output'].append(intermediate_output_0_1_output.uint)
                components_io['intermediate_output_0_1'] = [component_input.uint, intermediate_output_0_1_output.uint]
            <BLANKLINE>
                # round: 0, component: 2, component_id: concatenate_0_2
                component_input = select_bits(plaintext_output, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31])
                output_bit_size = 32
                concatenate_0_2_output = component_input
                components_io['concatenate_0_2'] = [component_input.uint, concatenate_0_2_output.uint]
            <BLANKLINE>
                # round: 0, component: 3, component_id: cipher_output_0_3
                component_input = select_bits(concatenate_0_2_output, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31])
                output_bit_size = 32
                cipher_output_0_3_output = component_input
                intermediate_output['cipher_output'].append(cipher_output_0_3_output.uint)
                cipher_output = cipher_output_0_3_output.uint
                components_io['cipher_output_0_3'] = [component_input.uint, cipher_output_0_3_output.uint]
            <BLANKLINE>
                return cipher_output, intermediate_output, components_io
            <BLANKLINE>
        """
        generated_code = code_generator.generate_python_code_string(self, verbosity)
        print(generated_code)

    def print_evaluation_python_code_to_file(self, file_name):
        """
        Use this function to print the python code to a file.

        INPUT:

        - ``file_name`` -- **string**; name of the output file

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.identity_block_cipher import IdentityBlockCipher as identity
            sage: identity = identity()
            sage: identity.file_name
            'identity_block_cipher_p32_k32_o32_r1.py'
            sage: identity.print_evaluation_python_code_to_file(identity.id + 'evaluation.py') # doctest: +SKIP
        """
        original_stdout = sys.stdout  # Save a reference to the original standard output

        with open(file_name, 'w') as f:
            sys.stdout = f  # Change the standard output to the file we created.
            self.print_evaluation_python_code()
        sys.stdout = original_stdout  # Reset the standard output to its original value

    def print_input_information(self):
        """
        Print a list of the inputs with their corresponding bit size.

        Possible cipher inputs are:
            * plaintext
            * key
            * tweak
            * initialization vector
            * nonce
            * constant
            * etc.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher()
            sage: fancy.print_input_information()
            plaintext of bit size 24
            key of bit size 24
        """
        for cipher_input, bit_size in zip(self._inputs, self._inputs_bit_size):
            print(f"{cipher_input} of bit size {bit_size}")

    def polynomial_system(self):
        """
        Return a polynomial system for the cipher.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.identity_block_cipher import IdentityBlockCipher
            sage: IdentityBlockCipher().polynomial_system()
            Polynomial Sequence with 128 Polynomials in 256 Variables
        """
        algebraic_model = AlgebraicModel(self)
        return algebraic_model.polynomial_system()

    def polynomial_system_at_round(self, r):
        """
        Return a polynomial system for the cipher at round `r`.

        INPUT:

        - ``r`` -- **integer**; round index

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: FancyBlockCipher(number_of_rounds=1).polynomial_system_at_round(0)
            Polynomial Sequence with 252 Polynomials in 288 Variables
        """
        algebraic_model = AlgebraicModel(self)
        return algebraic_model.polynomial_system_at_round(r)

    def remove_key_schedule(self):
        return editor.remove_key_schedule(self)

    def remove_round_component(self, round_id, component):
        editor.remove_round_component(self, round_id, component)

    def remove_round_component_from_id(self, round_id, component_id):
        editor.remove_round_component_from_id(self, round_id, component_id)

    def set_file_name(self, file_name):
        self._file_name = file_name

    def set_id(self, cipher_id):
        self._id = cipher_id

    def set_inputs(self, inputs_ids_list, inputs_bit_size_list):
        self._inputs = inputs_ids_list
        self._inputs_bit_size = inputs_bit_size_list

    def sort_cipher(self):
        return editor.sort_cipher(self)

    def test_against_reference_code(self, number_of_tests=5):
        """
        Test the graph representation against its reference implementation (if available) with random inputs.

        INPUT:

        - ``number_of_tests`` -- **integer** (default: `5`); number of tests to execute

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.xtea_block_cipher import XTeaBlockCipher as xtea
            sage: xtea(number_of_rounds=32).test_against_reference_code()
            True
        """
        return tester.test_against_reference_code(self, number_of_tests)

    def test_vector_check(self, list_of_test_vectors_input, list_of_test_vectors_output):
        """
        Testing the cipher with list of test vectors input and list of test vectors output.

        INPUT:

        - ``list_of_test_vectors_input`` -- **list**; list of input testing vectors
        - ``list_of_test_vectors_output`` -- **list**; list of the expected output of the corresponding input testing
          vectors. That is, list_of_test_vectors_output[i] = cipher.evaluate(list_of_test_vectors_input[i])

        OUTPUT:

        - ``test_result`` -- output of the testing. True if all the cipher.evaluate(input)=output for every input
        test vectors, and False, otherwise.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher as speck
            sage: speck = speck(number_of_rounds=22)
            sage: key1 = 0x1918111009080100
            sage: plaintext1 = 0x6574694c
            sage: ciphertext1 = 0xa86842f2
            sage: key2 = 0x1918111009080100
            sage: plaintext2 = 0x6574694d
            sage: ciphertext2 = 0x2b5f25d6
            sage: input_list=[[plaintext1, key1], [plaintext2, key2]]
            sage: output_list=[ciphertext1, ciphertext2]
            sage: speck.test_vector_check(input_list, output_list)
            True
            sage: input_list.append([0x11111111, 0x1111111111111111])
            sage: output_list.append(0xFFFFFFFF)
            sage: speck.test_vector_check(input_list, output_list)
            Testing Failed
            index: 2
            input:  [286331153, 1229782938247303441]
            output:  4294967295
            False
        """
        return tester.test_vector_check(self, list_of_test_vectors_input, list_of_test_vectors_output)

    def inputs_size_to_dict(self):
        inputs_dictionary = {}
        for i, name in enumerate(self.inputs):
            inputs_dictionary[name] = self.inputs_bit_size[i]
        return inputs_dictionary

    def find_impossible_property(self, type, technique="sat", solver="kissat", scenario="single-key"):
        """
        From [SGLYTQH2017] : Finds impossible differentials or zero-correlation linear approximations (based on type)
        by fixing the input and output iteratively to all possible Hamming weight 1 value, and asking the solver
        to find a solution; if none is found, then the propagation is impossible.
        Return a list of impossible differentials or zero_correlation linear approximations if there are any; otherwise return an empty list
        INPUT:

        - ``type`` -- **string**; {"differential", "linear"}: the type of property to search for
        - ``technique`` -- **string**; {"sat", "smt", "milp", "cp"}: the technique to use for the search
        - ``solver`` -- **string**; the name of the solver to use for the search
        """
        from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
        model = self.get_model(technique, f'xor_{type}')
        if type == 'differential':
            search_function = model.find_one_xor_differential_trail
        else:
            search_function = model.find_one_xor_linear_trail
        last_component_id = self.get_all_components()[-1].id
        impossible = []
        inputs_dictionary = self.inputs_size_to_dict()
        plain_bits = inputs_dictionary['plaintext']
        key_bits = inputs_dictionary['key']

        if scenario == "single-key":
            # Fix the key difference to be zero, and the plaintext difference to be non-zero.
            for input_bit_position in range(plain_bits):
                for output_bit_position in range(plain_bits):
                    fixed_values = []
                    fixed_values.append(set_fixed_variables('key', 'equal', list(range(key_bits)),
                                                            integer_to_bit_list(0, key_bits, 'big')))
                    fixed_values.append(set_fixed_variables('plaintext', 'equal', list(range(plain_bits)),
                                                            integer_to_bit_list(1 << input_bit_position, plain_bits,
                                                                                'big')))
                    fixed_values.append(set_fixed_variables(last_component_id, 'equal', list(range(plain_bits)),
                                                            integer_to_bit_list(1 << output_bit_position, plain_bits,
                                                                                'big')))
                    solution = search_function(fixed_values, solver_name=solver)
                    if solution['status'] == "UNSATISFIABLE":
                        impossible.append((1 << input_bit_position, 1 << output_bit_position))
        elif scenario == "related-key":
            for input_bit_position in range(key_bits):
                for output_bit_position in range(plain_bits):
                    fixed_values = []
                    fixed_values.append(set_fixed_variables('key', 'equal', list(range(key_bits)),
                                                            integer_to_bit_list(1 << (input_bit_position), key_bits,
                                                                                'big')))
                    fixed_values.append(set_fixed_variables('plaintext', 'equal', list(range(plain_bits)),
                                                            integer_to_bit_list(0, plain_bits, 'big')))

                    fixed_values.append(set_fixed_variables(last_component_id, 'equal', list(range(plain_bits)),
                                                            integer_to_bit_list(1 << output_bit_position, plain_bits,
                                                                                'big')))
                    solution = search_function(fixed_values, solver_name=solver)
                    if solution['status'] == "UNSATISFIABLE":
                        impossible.append((1 << input_bit_position, 1 << output_bit_position))
        return impossible

    def zero_correlation_linear_search(self, technique="sat", solver="Kissat"):
        """
        Return a list of zero_correlation linear approximations if there are any; otherwise return an empty list
        INPUT:

        - ``technique`` -- **string**; {"sat", "smt", "milp", "cp"}: the technique to use for the search
        - ``solver`` -- **string**; the name of the solver to use for the search
        """
        return self.find_impossible_property(type="linear", technique=technique, solver=solver)

    def convert_to_compound_xor_cipher(self):
        convert_to_compound_xor_cipher(self)

    @property
    def current_round(self):
        return self._rounds.current_round

    @property
    def current_round_number(self):
        return self._rounds.current_round_number

    @property
    def current_round_number_of_components(self):
        return self.current_round.number_of_components

    @property
    def family_name(self):
        return self._family_name

    @property
    def file_name(self):
        return self._file_name

    @property
    def id(self):
        return self._id

    @property
    def inputs(self):
        return self._inputs

    @property
    def inputs_bit_size(self):
        return self._inputs_bit_size

    @property
    def number_of_rounds(self):
        return self._rounds.number_of_rounds

    @property
    def output_bit_size(self):
        return self._output_bit_size

    @property
    def reference_code(self):
        return self._reference_code

    @property
    def rounds(self):
        return self._rounds

    @property
    def rounds_as_list(self):
        return self._rounds.rounds

    @property
    def type(self):
        return self._type

    def create_networx_graph_from_input_ids(self):
        import networkx as nx
        data = self.as_python_dictionary()['cipher_rounds']
        # Create a directed graph
        G = nx.DiGraph()

        # Flatten the list of lists
        flat_data = [item for sublist in data for item in sublist]

        # Add nodes
        for item in flat_data:
            G.add_node(item["id"])

        # Add edges based on input_id_link
        for item in flat_data:
            for input_id in item.get("input_id_link", []):
                # Adding an edge from input_id to the current item's id
                G.add_edge(input_id, item["id"])

        return G

    def create_top_and_bottom_subgraphs_from_components_graph(self, e0_bottom_ids, e1_top_ids):
        import networkx as nx

        def induced_subgraph_of_predecessors(DG, nodes):
            visited = set()

            def dfs(v):
                if v not in visited:
                    visited.add(v)
                    for predecessor in DG.predecessors(v):
                        dfs(predecessor)

            for node in nodes:
                dfs(node)

            return DG.subgraph(visited)

        def get_descendants_subgraph(G, start_nodes):
            """
            Extract a subgraph containing only the descendants (successors) of a given list of nodes from a graph.

            Parameters:
            - G (nx.DiGraph): The original directed graph.
            - start_nodes (list): The list of nodes to start the search from.

            Returns:
            - H (nx.DiGraph): The subgraph containing start_nodes and their descendants.
            """
            # Create an empty directed subgraph
            H = nx.DiGraph()

            # Add nodes from start_nodes to the subgraph and their descendants
            for node in start_nodes:
                if node in G:
                    H.add_node(node)
                    for successor in nx.dfs_successors(G, source=node):
                        H.add_edge(node, successor)
                        H.add_node(successor)

            return H

        graph_cipher = self.create_networx_graph_from_input_ids()
        ancestors_ids = induced_subgraph_of_predecessors(graph_cipher, e0_bottom_ids)
        descendants_ids = get_descendants_subgraph(graph_cipher, e1_top_ids)
        return ancestors_ids, descendants_ids

    def update_input_id_links_from_component_id(self, component_id, new_input_id_links):
        round_number = self.get_round_from_component_id(component_id)
        self._rounds.rounds[round_number].update_input_id_links_from_component_id(component_id, new_input_id_links)

    def all_sboxes_are_standard(self):
        for comp in self.get_all_components():
            if 'sbox' in comp.id:
                if (comp.input_bit_size != comp.output_bit_size) or (comp.input_bit_size %2 !=0) or (comp.output_bit_size %2 !=0):
                    return False
        return True

    def all_component_sizes_are_even(cipher):
        for comp in cipher.get_all_components:
            if comp.input_bit_size % 2 !=0 or comp.output_bit_size % 2 !=0:
                return False
        return True