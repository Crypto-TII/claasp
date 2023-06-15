
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
from copy import deepcopy

import claasp
from claasp import editor
from claasp.compound_xor_differential_cipher import convert_to_compound_xor_cipher
from claasp.rounds import Rounds
from claasp.cipher_modules import tester, evaluator
from claasp.utils.templates import TemplateManager, CSVBuilder
from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
from claasp.cipher_modules import continuous_tests, neural_network_tests, code_generator, \
    component_analysis_tests, avalanche_tests, algebraic_tests
from claasp.name_mappings import CIPHER_OUTPUT, CONSTANT, INTERMEDIATE_OUTPUT, MIX_COLUMN, SBOX, WORD_OPERATION
import importlib

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

    def add_intermediate_output_component(self, input_id_links, input_bit_positions, output_bit_size, output_tag):
        return editor.add_intermediate_output_component(self, input_id_links, input_bit_positions,
                                                        output_bit_size, output_tag)

    def add_linear_layer_component(self, input_id_links, input_bit_positions, output_bit_size, description):
        return editor.add_linear_layer_component(self, input_id_links, input_bit_positions,
                                                 output_bit_size, description)

    def add_mix_column_component(self, input_id_links, input_bit_positions, output_bit_size, mix_column_description):
        return editor.add_mix_column_component(self, input_id_links, input_bit_positions,
                                               output_bit_size, mix_column_description)

    def add_MODADD_component(self, input_id_links, input_bit_positions, output_bit_size):
        return editor.add_MODADD_component(self, input_id_links, input_bit_positions, output_bit_size)

    def add_MODSUB_component(self, input_id_links, input_bit_positions, output_bit_size):
        return editor.add_MODSUB_component(self, input_id_links, input_bit_positions, output_bit_size)

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

    def algebraic_tests(self, timeout):
        """
        Return a dictionary explaining the result of the algebraic test.

        INPUT:

        - ``timeout`` -- **integer**; the timeout for the Grobner basis computation in seconds

        OUTPUTS: a dictionary with the following keys:

            - ``npolynomials`` -- number of polynomials
            - ``nvariables`` -- number of variables
            - ``timeout`` -- timeout in seconds
            - ``pass`` -- whether the algebraic test pass w.r.t the given timeout

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: d = speck.algebraic_tests(5)  # long time
            sage: d == {'input_parameters': {'timeout': 5}, 'test_results':
            ....: {'number_of_variables': [304, 800],
            ....: 'number_of_equations': [240, 688], 'number_of_monomials': [304, 800],
            ....: 'max_degree_of_equations': [1, 1], 'test_passed': [False, False]}}  # long time
            True
        """
        return algebraic_tests.algebraic_tests(self, timeout)

    def analyze_cipher(self, tests_configuration):
        """
        Generate a dictionary with the analysis of the cipher.

        The analysis is related to the following tests:

        - Diffusion Tests

        INPUT:

        - ``tests_configuration`` -- **python dictionary**

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: sp = SpeckBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=5)
            sage: tests_configuration = {"diffusion_tests": {"run_tests": True, "number_of_samples": 100,
            ....: "run_avalanche_dependence": True, "run_avalanche_dependence_uniform": True,
            ....: "run_avalanche_weight": True, "run_avalanche_entropy": True,
            ....: "avalanche_dependence_uniform_bias": 0.2, "avalanche_dependence_criterion_threshold": 0,
            ....: "avalanche_dependence_uniform_criterion_threshold":0, "avalanche_weight_criterion_threshold": 0.1,
            ....: "avalanche_entropy_criterion_threshold":0.1}, "component_analysis_tests": {"run_tests": True}}
            sage: analysis = sp.analyze_cipher(tests_configuration)
            sage: analysis["diffusion_tests"]["test_results"]["key"]["round_output"][ # random
            ....: "avalanche_dependence_vectors"]["differences"][31]["output_vectors"][0]["vector"] # random
        """
        tmp_tests_configuration = deepcopy(tests_configuration)
        analysis_results = {}
        if "diffusion_tests" in tests_configuration and tests_configuration["diffusion_tests"]["run_tests"]:
            tmp_tests_configuration["diffusion_tests"].pop("run_tests")
            analysis_results['diffusion_tests'] = \
                avalanche_tests.avalanche_tests(self, **tmp_tests_configuration["diffusion_tests"])
        if "component_analysis_tests" in tests_configuration and tests_configuration[
                "component_analysis_tests"]["run_tests"]:
            analysis_results["component_analysis_tests"] = component_analysis_tests.component_analysis_tests(self)
        if "algebraic_tests" in tests_configuration and tests_configuration["algebraic_tests"]["run_tests"]:
            timeout = tests_configuration["algebraic_tests"]["timeout"]
            analysis_results["algebraic_tests"] = algebraic_tests.algebraic_tests(self, timeout=timeout)

        return analysis_results

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

    def avalanche_probability_vectors(self, nb_samples):
        """
        Return the avalanche probability vectors of each input bit difference for each round.

        The inputs considered are plaintext, key, etc.

        The i-th component of the vector is the probability that i-th bit of the output
        flips due to the input bit difference.

        .. NOTE::

            apvs["key"]["round_output"][position][index_occurrence] = vector of round_output size with input diff
            injected in key

        INPUT:

        - ``nb_samples`` -- **integer**; used to compute the estimated probability of flipping

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher as speck
            sage: speck = speck(block_bit_size=16, key_bit_size=32, number_of_rounds=5)
            sage: apvs = speck.avalanche_probability_vectors(100)
            sage: apvs["key"]["round_output"][31][0] # random
        """
        return avalanche_tests.avalanche_probability_vectors(self, nb_samples)

    def component_analysis_tests(self):
        """
        Return a list of dictionaries, each one giving some properties of the cipher's operations.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(word_size=8, state_size=4, number_of_rounds=2)
            sage: result = aes.component_analysis_tests()
            sage: len(result)
            9
        """
        return component_analysis_tests.component_analysis_tests(self)

    def print_component_analysis_as_radar_charts(self, component_analysis_results):
        """
        Return a matplotlib object containing the radar charts of the components analysis test

        INPUT:

        - ``component_analysis_results`` -- **list**; results of the component analysis method

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(word_size=8, state_size=4, number_of_rounds=2)
            sage: result = aes.component_analysis_tests()
            sage: fig = aes.print_component_analysis_as_radar_charts(result)
            sage: fig.show() # doctest: +SKIP
        """
        return component_analysis_tests.print_component_analysis_as_radar_charts(component_analysis_results)

    def component_from(self, round_number, index):
        return self._rounds.component_from(round_number, index)

    def compute_criterion_from_avalanche_probability_vectors(self, all_apvs, avalanche_dependence_uniform_bias):
        r"""
        Return a python dictionary that contains the dictionaries corresponding to each criterion.

        ALGORITHM:

        The avalanche dependence is the number of output bit that flip with respect to an input bit difference,
        for a given round.
        If the worst avalanche dependence for a certain round is close to the output bit size with respect to a certain
        threshold, we say that the cipher satisfies the avalanche dependence criterion for this round.

        The avalanche dependence uniform is the number of output bit that flip with a probability
        $\in \left[\frac{1}{2} - \text{bias}; \frac{1}{2} + \text{bias}\right]$,
        with respect to an input bit difference, for a given round. If the worst avalanche dependence uniform for a
        certain round is close to the output bit size with respect to a certain threshold,
        we say that the cipher satisfies the avalanche dependence uniform criterion for this round.

        The avalanche weight is the expected Hamming weight of the output difference with respect to an input bit
        difference, for a given round.
        If the avalanche weights of all the input bit differences for a certain round is close to half of
        the output bit size with respect to a certain threshold, we say that the cipher satisfies the
        avalanche criterion for this round.

        The avalanche entropy is defined as uncertainty about whether output bits flip with respect to an input
        bit difference, for a given round.
        If the strict avalanche entropy of all the input bit differences for a certain round is close to
        the output bit size with respect to a certain threshold, we say that the cipher satisfies the
        strict avalanche criterion for this round.

        .. NOTE::

            d["key"]["round_output"][position][index_occurrence]["avalanche_dependence"] = vector of round_output size
            with input diff injected in key

        INPUT:

        - ``all_apvs`` -- **dictionary**; all avalanche probability vectors returned by avalanche_probability_vectors()
        - ``avalanche_dependence_uniform_bias`` -- **float**; define the range where the probability of flipping should be

        .. SEEALSO::

            :py:meth:`~avalanche_probability_vectors` for the returning vectors.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher as speck
            sage: speck = speck(block_bit_size=16, key_bit_size=32, number_of_rounds=5)
            sage: apvs = speck.avalanche_probability_vectors(100)
            sage: d = speck.compute_criterion_from_avalanche_probability_vectors(apvs, 0.2)
            sage: d["key"]["round_output"][0][0]["avalanche_dependence_vectors"] # random
        """
        return avalanche_tests.compute_criterion_from_avalanche_probability_vectors(self, all_apvs,
                                                                                    avalanche_dependence_uniform_bias)

    def continuous_avalanche_factor(self, lambda_value, number_of_samples):
        """
        Continuous generalization of the metric Avalanche Factor. This method implements Definition 14 of [MUR2020]_.

        INPUT:

        - ``lambda_value`` --  **float**; threshold value used to express the input difference
        - ``number_of_samples`` --  **integer**; number of samples used to compute the continuous avalanche factor

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher as speck
            sage: speck_cipher = speck(number_of_rounds=2)
            sage: result = speck_cipher.continuous_avalanche_factor(0.001, 10)
            sage: result['plaintext']['round_key_output']['continuous_avalanche_factor']['values'][0]['value']
            0.0
        """
        return continuous_tests.continuous_avalanche_factor(self, lambda_value, number_of_samples)

    def continuous_diffusion_factor(self, beta_number_of_samples, gf_number_samples):
        """
        Continuous Diffusion Factor. This method implements Definition 16 of [MUR2020]_.

        INPUT:

        - ``beta_number_of_samples`` -- **integer**; number of samples used to compute the continuous measure metric
        - ``gf_number_samples`` -- **integer**;  number of vectors used to approximate gf_2

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher as speck
            sage: speck_cipher = speck(number_of_rounds=2) # long time
            sage: output = speck_cipher.continuous_diffusion_factor(5, 20) # long time
            sage: output['plaintext']['cipher_output']['diffusion_factor']['values'][0]['2'] > 0 # long time
            True
        """
        return continuous_tests.continuous_diffusion_factor(self, beta_number_of_samples, gf_number_samples)

    def continuous_diffusion_tests(self,
                                   continuous_avalanche_factor_number_of_samples=100,
                                   threshold_for_avalanche_factor=0.001,
                                   continuous_neutral_measure_beta_number_of_samples=10,
                                   continuous_neutral_measure_gf_number_samples=10,
                                   continuous_diffusion_factor_beta_number_of_samples=10,
                                   continuous_diffusion_factor_gf_number_samples=10,
                                   is_continuous_avalanche_factor=True,
                                   is_continuous_neutrality_measure=True,
                                   is_diffusion_factor=True):
        """
        Return a python dictionary that contains the dictionaries corresponding to each metric in [MUR2020]_.

        INPUT:

        - ``continuous_avalanche_factor_number_of_samples`` -- **integer** (default: `100`); number of samples
          used to obtain the metric continuous_avalanche_factor
        - ``threshold_for_avalanche_factor`` -- **float** (default: `0.001`); threshold value used to compute the
          input difference for the metric continuous_avalanche_factor
        - ``continuous_neutral_measure_beta_number_of_samples`` -- **integer** (default: `10`); number of samples
          used to compute the continuous measure metric
        - ``continuous_neutral_measure_gf_number_samples`` -- **integer** (default: `10`);  number of vectors used
          to approximate gf_2
        - ``continuous_diffusion_factor_beta_number_of_samples`` -- **integer** (default: `10`); number of samples
          used to compute the continuous measure metric
        - ``continuous_diffusion_factor_gf_number_samples`` -- **integer** (default: `10`);  number of vectors
          used to approximate gf_2
        - ``is_continuous_avalanche_factor`` -- **boolean** (default: `True`); flag indicating if we want the
          continuous_avalanche_factor or not
        - ``is_continuous_neutrality_measure`` -- **boolean** (default: `True`); flag indicating if we want the
          continuous_neutrality_measure or not
        - ``is_diffusion_factor`` -- **boolean** (default: `True`); flag indicating if we want the
          continuous_neutrality_measure, or not

        OUTPUT:

            - A python dictionary that contains the test result to each metric. E.g.: continuous_neutrality_measure,
              continuous_avalanche_factor, diffusion_factor

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher as speck
            sage: speck_cipher = speck(number_of_rounds=1) # long time
            sage: output = speck_cipher.continuous_diffusion_tests() # long time
            sage: output['plaintext']['round_key_output']['continuous_neutrality_measure']['values'][0]['1'] == 0.0 # long time
            True
        """
        return continuous_tests.continuous_diffusion_tests(self,
                                                           continuous_avalanche_factor_number_of_samples,
                                                           threshold_for_avalanche_factor,
                                                           continuous_neutral_measure_beta_number_of_samples,
                                                           continuous_neutral_measure_gf_number_samples,
                                                           continuous_diffusion_factor_beta_number_of_samples,
                                                           continuous_diffusion_factor_gf_number_samples,
                                                           is_continuous_avalanche_factor,
                                                           is_continuous_neutrality_measure,
                                                           is_diffusion_factor)

    def continuous_neutrality_measure_for_bit_j(self, beta_number_of_samples, gf_number_samples,
                                                input_bit=None, output_bits=None):
        """
        Continuous Neutrality Measure. This method implements Definition 15 of [MUR2020]_.

        INPUT:

        - ``beta_number_of_samples`` -- **integer**; number of samples used to compute the continuous measure metric
        - ``gf_number_samples`` -- **integer**;  number of vectors used to approximate gf_2
        - ``input_bit`` -- **integer** (default: `None`); input bit position to be analyzed
        - ``output_bits`` -- **list** (default: `None`); output bit positions to be analyzed

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher as speck
            sage: output = speck(number_of_rounds=2).continuous_neutrality_measure_for_bit_j(50, 200) # long time
            sage: output['plaintext']['cipher_output']['continuous_neutrality_measure']['values'][0]['2'] > 0 # long time
            True
        """
        return continuous_tests.continuous_neutrality_measure_for_bit_j(self, beta_number_of_samples,
                                                                        gf_number_samples, input_bit,
                                                                        output_bits)

    def continuous_neutrality_measure_for_bit_j_and_beta(self, input_bit, beta, number_of_samples, output_bits):
        return continuous_tests.continuous_neutrality_measure_for_bit_j_and_beta(self, beta, input_bit,
                                                                                 number_of_samples, output_bits)

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

    def diffusion_tests(self, number_of_samples=5,
                        avalanche_dependence_uniform_bias=0.05,
                        avalanche_dependence_criterion_threshold=0,
                        avalanche_dependence_uniform_criterion_threshold=0,
                        avalanche_weight_criterion_threshold=0.01,
                        avalanche_entropy_criterion_threshold=0.01,
                        run_avalanche_dependence=True,
                        run_avalanche_dependence_uniform=True,
                        run_avalanche_weight=True,
                        run_avalanche_entropy=True):
        """
        Return a python dictionary that contains the dictionaries corresponding to each criterion and their analysis.

        INPUT:

        - ``number_of_samples`` -- **integer** (default: `5`); used to compute the estimated probability of flipping
        - ``avalanche_dependence_uniform_bias`` -- **float** (default: `0.05`); define the range where the probability
          of flipping should be
        - ``avalanche_dependence_criterion_threshold`` --  **float** (default: `0`); It is a bias. The criterion is satisfied
          for a given input bit difference if for all output bits of the round under analysis, the corresponding
          avalanche dependence criterion d is such that block_bit_size - bias <= d <= block_bit_size + bias
        - ``avalanche_dependence_uniform_criterion_threshold`` --  **float** (default: `0`); It is a bias. The criterion is
          satisfied for a given input bit difference if for all output bits of the round under analysis, the
          corresponding avalanche dependence uniform criterion d is such that
          block_bit_size - bias <= d <= block_bit_size + bias
        - ``avalanche_weight_criterion_threshold`` --  **float** (default: `0.01`); It is a bias. The criterion is
          satisfied for a given input bit difference if for all output bits of the round under analysis, the
          corresponding avalanche weight criterion is such that block_bit_size/2 - bias <= d <= block_bit_size/2 + bias
        - ``avalanche_entropy_criterion_threshold`` --  **float** (default: `0.01`); It is a bias. The criterion is
          satisfied for a given input bit difference if for all output bits of the round under analysis, the
          corresponding avalanche entropy criterion d is such that block_bit_size - bias <= d <= block_bit_size + bias
        - ``run_avalanche_dependence`` -- **boolean** (default: `True`); if True, add the avalanche dependence results
          to the output dictionary
        - ``run_avalanche_dependence_uniform`` -- **boolean** (default: `True`); if True, add the avalanche dependence
          uniform results to the output dictionary
        - ``run_avalanche_weight`` -- **boolean** (default: `True`); if True, add the avalanche weight results to the
          output dictionary
        - ``run_avalanche_entropy`` -- **boolean** (default: `True`); if True, add the avalanche entropy results to the
          output dictionary

        .. NOTE::

            diff inserted in:
            d["test_results"]["plaintext"]["round_output"]["avalanche_entropy"]["differences"][position][
            "output_vectors"][round]

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=5)
            sage: d = speck.diffusion_tests(number_of_samples=100)
            sage: d["test_results"]["key"]["round_output"][ # random
            ....: "avalanche_dependence_vectors"]["differences"][0]["output_vectors"][0]["vector"] # random
        """
        return avalanche_tests.avalanche_tests(self,
                                               number_of_samples, avalanche_dependence_uniform_bias,
                                               avalanche_dependence_criterion_threshold,
                                               avalanche_dependence_uniform_criterion_threshold,
                                               avalanche_weight_criterion_threshold,
                                               avalanche_entropy_criterion_threshold, run_avalanche_dependence,
                                               run_avalanche_dependence_uniform, run_avalanche_weight,
                                               run_avalanche_entropy)

    def generate_heatmap_graphs_for_avalanche_tests(self, avalanche_results, difference_positions=None, criterion_names=None):
        """
        Return a string containing latex instructions to generate heatmap graphs of the avalanche tests.
        The string can then be printed on a terminal or on a file.

        INPUT:

        - ``avalanche_results`` -- **dictionary**; results of the avalanche tests
        - ``difference_positions`` -- **list** (default: `None`); positions of the differences to inject.
            The default value is equivalent to pick one of the worst position for a difference and the average value.
        - ``criterion_names`` -- **list** (default: `None`); names of the criteria to observe
            The default value is equivalent to to pick all of the 4 criteria:
            - "avalanche_dependence_vectors"
            - "avalanche_dependence_uniform_vectors"
            - "avalanche_entropy_vectors"
            - "avalanche_weight_vectors"

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: sp = SpeckBlockCipher(block_bit_size=64, key_bit_size=128, number_of_rounds=5)
            sage: d = sp.diffusion_tests(number_of_samples=100)
            sage: h = sp.generate_heatmap_graphs_for_avalanche_tests(d)
            sage: h[:20]
            '\\documentclass[12pt]'

            sage: from claasp.ciphers.permutations.ascon_permutation import AsconPermutation
            sage: ascon = AsconPermutation(number_of_rounds=4)
            sage: d = ascon.diffusion_tests(number_of_samples=100) # long
            sage: h = ascon.generate_heatmap_graphs_for_avalanche_tests(d, [0], ["avalanche_weight_vectors"]) # long

            sage: from claasp.ciphers.permutations.xoodoo_permutation import XoodooPermutation
            sage: cipher = XoodooPermutation(number_of_rounds=4)
            sage: d = cipher.diffusion_tests(number_of_samples=100) # long
            sage: h = cipher.generate_heatmap_graphs_for_avalanche_tests(d, [1,193], ["avalanche_dependence_vectors", "avalanche_entropy_vectors"]) # long
        """
        return avalanche_tests.generate_heatmap_graphs_for_avalanche_tests(self, avalanche_results, difference_positions, criterion_names)

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

    def evaluate_vectorized(self, cipher_input, intermediate_outputs=False, verbosity=False):
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
        return evaluator.evaluate_vectorized(self, cipher_input, intermediate_outputs, verbosity)

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

    def find_good_input_difference_for_neural_distinguisher(self, difference_positions,
                                                            initial_population=32, number_of_generations=50,
                                                            nb_samples=10 ** 4, previous_generation=None,
                                                            verbose=False):
        """
        Return good neural distinguisher input differences for a cipher.

        INPUT:

        - ``difference_positions`` -- **table of booleans**; one for each input to the cipher. True in positions where
          differences are allowed
        - ``initial_population`` -- **integer** (default: `32`); parameter of the evolutionary algorithm
        - ``number_of_generations`` -- **integer** (default: `50`); number of iterations of the evolutionary algorithm
        - ``nb_samples`` -- **integer** (default: `10`); number of samples for testing each input difference
        - ``previous_generation`` -- (default: `None`); optional: initial table of differences to try
        - ``verbose`` -- **boolean** (default: `False`); verbosity

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.neural_network_tests import find_good_input_difference_for_neural_distinguisher
            sage: cipher = SpeckBlockCipher()
            sage: diff, scores, highest_round = find_good_input_difference_for_neural_distinguisher(cipher, [True, False], verbose = False, number_of_generations=5)
        """
        return neural_network_tests.find_good_input_difference_for_neural_distinguisher(self,
                                                                                        difference_positions,
                                                                                        initial_population,
                                                                                        number_of_generations,
                                                                                        nb_samples,
                                                                                        previous_generation,
                                                                                        verbose)

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

    # LM: TII team needs to update this method because the keys from diffusion_tests_results do not correspond
    def generate_csv_report(self, nb_samples, output_absolute_path):
        """
        Generate a CSV report containing criteria to estimate the vulnerability of the cipher.

        This method generate a CSV report containing the criteria presented in the paper
        "The design of Xoodoo and Xoofff" [1].
        [1] https://tosc.iacr.org/index.php/ToSC/article/view/7359

        INPUT:

        - ``nb_samples`` -- **integer**; number of samples
        - ``output_absolute_path`` -- **string**; output of the absolute path

        EXAMPLES::

            sage: import inspect
            sage: import claasp
            sage: import os.path
            sage: tii_path = inspect.getfile(claasp)
            sage: tii_dir_path = os.path.dirname(tii_path)
            sage: from claasp.ciphers.block_ciphers.identity_block_cipher import IdentityBlockCipher
            sage: identity = IdentityBlockCipher()
            sage: identity.generate_csv_report(10, f"{tii_dir_path}/{identity.id}_report.csv")
            sage: os.path.isfile(f"{tii_dir_path}/{identity.id}_report.csv")
            True
            sage: import os
            sage: os.remove(f"{tii_dir_path}/{identity.id}_report.csv")
        """

        diffusion_tests_results = self.diffusion_tests(nb_samples)
        first_input_tag = list(diffusion_tests_results['test_results'].keys())[0]
        output_tags = diffusion_tests_results['test_results'][first_input_tag].keys()
        property_values_array = []
        for output_tag in output_tags:
            property_values_array_temp = avalanche_tests.get_average_criteria_list_by_output_tag(
                diffusion_tests_results, output_tag
            )
            property_values_array += property_values_array_temp

        str_of_inputs_bit_size = list(map(str, self._inputs_bit_size))
        cipher_primitive = self._id + "_" + "_".join(str_of_inputs_bit_size)
        cipher_data = {
            'type': self._type,
            'scheme': self._id,
            'cipher_inputs': self._inputs,
            'cipher_inputs_bit_size': list(map(str, self._inputs_bit_size)),
            'primitive': cipher_primitive,
            'total_number_rounds': self.number_of_rounds,
            'details': property_values_array
        }
        template_manager = TemplateManager()
        excel_builder = CSVBuilder(cipher_data)
        template_manager.set_builder(excel_builder)
        template_information = {"template_path": "diffusion_test_template.csv"}
        excel = template_manager.get_template().render_template(template_information)
        text_file = open(output_absolute_path, "w")
        text_file.write(excel)
        text_file.close()

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


    def impossible_differential_search(self, technique = "sat", solver = "Kissat", scenario = "single-key"):
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

    def neural_network_blackbox_distinguisher_tests(
            self, nb_samples=10000, hidden_layers=[32, 32, 32], number_of_epochs=10):
        """
        Return a python dictionary that contains the accuracies corresponding to each round.

        INPUT:

        - ``nb_samples`` -- **integer** (default: `10000`); how many sample the neural network is trained with
        - ``hidden_layers`` -- **list** (default: `[32, 32, 32]`); a list containing the number of neurons in each
          hidden layer of the neural network
        - ``number_of_epochs`` -- **integer** (default: `10`); how long is the training of the neural network

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher as speck
            sage: #speck(number_of_rounds=22).neural_network_blackbox_distinguisher_tests(nb_samples = 10) # random
        """
        return neural_network_tests.neural_network_blackbox_distinguisher_tests(
            self, nb_samples, hidden_layers, number_of_epochs)

    def neural_network_differential_distinguisher_tests(
            self, nb_samples=10000, hidden_layers=[32, 32, 32], number_of_epochs=10, diff=[0x01]):
        """
        Return a python dictionary that contains the accuracies corresponding to each round.

        INPUT:

        - ``nb_samples`` -- **integer** (default: `10000`); how many sample the neural network is trained with
        - ``hidden_layers`` -- **list** (default: `[32, 32, 32]`); a list containing the number of neurons in each
          hidden layer of the neural network
        - ``number_of_epochs`` -- **integer** (default: `10`); how long is the training of the neural network
        - ``diff`` -- **list** (default: `[0x01]`); list of input differences

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher as speck
            sage: #speck(number_of_rounds=22).neural_network_differential_distinguisher_tests(nb_samples = 10) # random
        """
        return neural_network_tests.neural_network_differential_distinguisher_tests(
            self, nb_samples, hidden_layers, number_of_epochs, diff)

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


    def find_impossible_property(self, type, technique = "sat", solver = "kissat", scenario = "single-key"):
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
                    solution = search_function(fixed_values, solver_name = solver)
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
                    solution = search_function(fixed_values, solver_name = solver)
                    if solution['status'] == "UNSATISFIABLE":
                        impossible.append((1 << input_bit_position, 1 << output_bit_position))
        return impossible

    def zero_correlation_linear_search(self, technique = "sat", solver = "Kissat"):
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
