
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


import sys
import math
import numpy as np
from math import log
from claasp.cipher_modules import evaluator
from claasp.name_mappings import INTERMEDIATE_OUTPUT, CIPHER_OUTPUT
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap

class AvalancheTests:
    def __init__(self, cipher):
        self._cipher = cipher

    def avalanche_tests(self, number_of_samples=5, avalanche_dependence_uniform_bias=0.05,
                        avalanche_dependence_criterion_threshold=0, avalanche_dependence_uniform_criterion_threshold=0,
                        avalanche_weight_criterion_threshold=0.01, avalanche_entropy_criterion_threshold=0.01,
                        run_avalanche_dependence=True, run_avalanche_dependence_uniform=True,
                        run_avalanche_weight=True, run_avalanche_entropy=True):
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

            d["test_results"]["plaintext"]["round_output"]["avalanche_entropy"][i]["vectors"][j]
            The vector returned by this command correspond to the avalanche entropy after j+1 rounds, when an input
            difference has been injected in position i in the plaintext.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=5)
            sage: from claasp.cipher_modules.avalanche_tests import AvalancheTests
            sage: test = AvalancheTests(speck)
            sage: d = test.avalanche_tests(number_of_samples=100)
            sage: d["test_results"]["key"]["round_output"]["avalanche_dependence_vectors"][0]["vectors"][1] # random

        """

        all_avalanche_probability_vectors = self.avalanche_probability_vectors(number_of_samples)
        criterion = self.compute_criterion_from_avalanche_probability_vectors(all_avalanche_probability_vectors,
                                                                         avalanche_dependence_uniform_bias)
        intermediate_output_names = self._add_intermediate_output_components_id_to_dictionary(self._cipher.get_all_components())
        diffusion_tests = {"input_parameters": {
            "cipher": self._cipher,
            "test_name": "avalanche_tests",
            "number_of_samples": number_of_samples,
            "avalanche_dependence_uniform_bias": avalanche_dependence_uniform_bias,
            "avalanche_dependence_criterion_threshold": avalanche_dependence_criterion_threshold,
            "avalanche_dependence_uniform_criterion_threshold": avalanche_dependence_uniform_criterion_threshold,
            "avalanche_weight_criterion_threshold": avalanche_weight_criterion_threshold,
            "avalanche_entropy_criterion_threshold": avalanche_entropy_criterion_threshold},
            "test_results": self._init_dictionary_test_results(intermediate_output_names)}

        parameters = {
            "avalanche_dependence_vectors": [run_avalanche_dependence, 1,
                                             avalanche_dependence_criterion_threshold],
            "avalanche_dependence_uniform_vectors": [run_avalanche_dependence_uniform, 1,
                                                     avalanche_dependence_uniform_criterion_threshold],
            "avalanche_weight_vectors": [run_avalanche_weight, 1 / 2, avalanche_weight_criterion_threshold],
            "avalanche_entropy_vectors": [run_avalanche_entropy, 1, avalanche_entropy_criterion_threshold]}

        for criterion_name in parameters.keys():
            for index, input_name in enumerate(self._cipher.inputs):
                for intermediate_output_name in list(intermediate_output_names.keys()):
                    if parameters[criterion_name][0]:
                        self._add_intermediate_output_values_to_dictionary(criterion_name, intermediate_output_names,
                                                                        parameters,diffusion_tests, index, input_name,
                                                                        intermediate_output_name)
                        all_output_vectors, largest_round_criterion_not_satisfied = \
                            self._calculate_regular_difference(criterion_name, criterion, intermediate_output_names, parameters,
                                                         diffusion_tests, input_name, intermediate_output_name)
                        self._calculate_average_difference(all_output_vectors, criterion_name, parameters, diffusion_tests,
                                                     input_name, intermediate_output_name)
                        self._calculate_worst_input_differences(criterion_name, largest_round_criterion_not_satisfied,
                                                         diffusion_tests, input_name, intermediate_output_name)

        return diffusion_tests


    def _init_dictionary_test_results(self, dict_intermediate_output_names):
        dict_test_results = {}
        for input_name in self._cipher.inputs:
            dict_test_results[input_name] = {}
            for intermediate_output_name in list(dict_intermediate_output_names.keys()):
                dict_test_results[input_name][intermediate_output_name] = {}

        return dict_test_results


    def _is_output(self, component):
        return component.type == INTERMEDIATE_OUTPUT or component.type == CIPHER_OUTPUT


    def _add_intermediate_output_components_id_to_dictionary(self, components):
        intermediate_output_names = {}
        for component in components:
            if self._is_output(component):
                if component.description[0] not in list(intermediate_output_names.keys()):
                    number_of_occurrences = 0
                    components_id = []
                    intermediate_output_names[component.description[0]] = [component.output_bit_size,
                                                                           number_of_occurrences,
                                                                           components_id]
                number_of_occurrences_position = 1
                intermediate_output_names[component.description[0]][number_of_occurrences_position] += 1
                components_id_position = 2
                intermediate_output_names[component.description[0]][components_id_position].append(component.id)

        return intermediate_output_names


    def _add_intermediate_output_values_to_dictionary(self, criterion_name, dict_intermediate_output_names,
                                                     dict_parameters, dict_test_results, index,
                                                     input_name, intermediate_output_name):
        dict_test_results["test_results"][input_name][intermediate_output_name][criterion_name] = {}
        dict_test_results["input_parameters"][f'{intermediate_output_name}_{criterion_name}_input_bit_size'] = \
            self._cipher.inputs_bit_size[index]
        output_bit_size = dict_intermediate_output_names[intermediate_output_name][0]
        dict_test_results["input_parameters"][f'{intermediate_output_name}_{criterion_name}_output_bit_size'] = output_bit_size
        dict_test_results["input_parameters"][f'{intermediate_output_name}_{criterion_name}_expected_value_per_bit'] = \
            dict_parameters[criterion_name][1]
        dict_test_results["input_parameters"][f'{intermediate_output_name}_{criterion_name}_max_possible_value_per_output_block'] = \
            output_bit_size
        dict_test_results["input_parameters"][f'{intermediate_output_name}_{criterion_name}_min_possible_value_per_output_block'] = 0
        dict_test_results["input_parameters"][f'{intermediate_output_name}_{criterion_name}_expected_value_per_output_block'] = \
            output_bit_size * dict_parameters[criterion_name][1]
        dict_test_results["test_results"][input_name][intermediate_output_name][criterion_name] = []


    def _calculate_regular_difference(self, criterion_name, dict_criterion, dict_intermediate_output_names, dict_parameters,
                                     dict_test_results, input_name, intermediate_output_name):
        all_output_vectors = {}
        dict_largest_round_criterion_not_satisfied = {}
        for index_input_diff in range(len(dict_criterion[input_name][intermediate_output_name])):
            output_vectors = []
            for nb_occurence in range(len(dict_criterion[input_name][intermediate_output_name][index_input_diff])):
                tmp_dict = {
                    "vector": dict_criterion[input_name][intermediate_output_name][index_input_diff][nb_occurence][
                        criterion_name],
                    "round": dict_criterion[input_name][intermediate_output_name][index_input_diff][nb_occurence]["round"]}
                tmp_dict["total"] = sum(tmp_dict["vector"])
                expected_value_per_output_block = dict_test_results["input_parameters"][(f'{intermediate_output_name}_'
                                                    f'{criterion_name}_expected_value_per_output_block')]
                threshold = dict_parameters[criterion_name][2]
                if expected_value_per_output_block - threshold <= tmp_dict[
                        "total"] <= expected_value_per_output_block + threshold:
                    tmp_dict["criterion_satisfied"] = True
                else:
                    tmp_dict["criterion_satisfied"] = False
                    dict_largest_round_criterion_not_satisfied[index_input_diff] = tmp_dict["round"]
                tmp_dict["output_component_id"] = dict_intermediate_output_names[intermediate_output_name][2][nb_occurence]
                if tmp_dict["round"] not in all_output_vectors:
                    all_output_vectors[tmp_dict["round"]] = []
                all_output_vectors[tmp_dict["round"]].append(tmp_dict["vector"])
                output_vectors.append(tmp_dict)

            output_dict = {
                "input_difference_value": hex(1 << index_input_diff),
                "vectors": [vector["vector"] for vector in output_vectors],
                "total": [vector["total"] for vector in output_vectors],
                "satisfied_criterion": [vector["criterion_satisfied"] for vector in output_vectors],
                "component_ids": [vector["output_component_id"] for vector in output_vectors]
            }

            dict_test_results["test_results"][input_name][intermediate_output_name][criterion_name].append(output_dict)

        return all_output_vectors, dict_largest_round_criterion_not_satisfied


    def _calculate_average_difference(self, all_output_vectors, criterion_name, dict_parameters, dict_test_results, input_name,
                                     intermediate_output_name):
        dict_for_average_diff = {"input_difference_value": 'average'}
        output_vectors = []
        for current_round in all_output_vectors.keys():
            tmp_dict = {}
            average_vector = [
                 sum(vec) /
                dict_test_results["input_parameters"][(f'{intermediate_output_name}'
                            f'_{criterion_name}_input_bit_size')] for vec in zip(* all_output_vectors[current_round])]
            tmp_dict["vector"] = average_vector
            tmp_dict["total"] = sum(tmp_dict["vector"])
            expected_value_per_output_block = dict_test_results["input_parameters"][f'{intermediate_output_name}_{criterion_name}_expected_value_per_output_block']
            threshold = dict_parameters[criterion_name][2]
            if expected_value_per_output_block - \
                    threshold <= tmp_dict["total"] <= expected_value_per_output_block + threshold:
                tmp_dict["criterion_satisfied"] = True
            else:
                tmp_dict["criterion_satisfied"] = False
            tmp_dict["round"] = current_round
            tmp_dict["output_component_id"] = "None"
            output_vectors.append(tmp_dict["vector"])
        dict_for_average_diff["vectors"] = output_vectors
        dict_test_results["test_results"][input_name][intermediate_output_name][criterion_name].append(dict_for_average_diff)


    def _calculate_worst_input_differences(self, criterion_name, largest_round_criterion_not_satisfied,
                                          dict_test_results, input_name, intermediate_output_name):
        max_round_criterion_not_satisfied = max(
            largest_round_criterion_not_satisfied.values(), default=self._cipher.number_of_rounds)
        worst_input_diffs = [input_diff for input_diff, specific_round in
                             largest_round_criterion_not_satisfied.items()
                             if specific_round == max_round_criterion_not_satisfied]
        dict_test_results["test_results"][input_name][intermediate_output_name][criterion_name].append({'worst_input_differences': worst_input_diffs})

    def avalanche_probability_vectors(self, nb_samples):
        """
        Return the avalanche probability vectors of each input bit difference for each round.

        The inputs considered are plaintext, key, etc.

        The i-th component of the vector is the probability that i-th bit of the output
        flips due to the input bit difference.

        .. NOTE::

            apvs["key"]["round_output"][i][j]
            The vector returned corresponds to the probablity of flipping of each output bits after j+1 rounds when the
            difference is injected in position i in the key.

        INPUT:

        - ``nb_samples`` -- **integer**; used to compute the estimated probability of flipping

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher as speck
            sage: speck = speck(block_bit_size=16, key_bit_size=32, number_of_rounds=5)
            sage: from claasp.cipher_modules.avalanche_tests import AvalancheTests
            sage: test = AvalancheTests(speck)
            sage: apvs = test.avalanche_probability_vectors(100)
            sage: apvs["plaintext"]["round_output"][0][3] # random

        """

        intermediate_output_names = {}
        for component in self._cipher.get_all_components():
            if self._is_output(component):
                if component.description[0] not in list(intermediate_output_names.keys()):
                    intermediate_output_names[component.description[0]] = [0, component.output_bit_size]
                intermediate_output_names[component.description[0]][0] += 1

        # Structure of all_avalanche_probability_vectors:
        # Example :
        # all_avalanche_probability_vectors['key']['round_output'][i] = [apv_round_0,apv_round_1, ... , apv_round_(n-1)]
        # where the diff has been injected in position i
        all_avalanche_probability_vectors = {}
        for cipher_input in self._cipher.inputs:
            all_avalanche_probability_vectors[cipher_input] = {}
            for intermediate_output_name in list(intermediate_output_names.keys()):
                all_avalanche_probability_vectors[cipher_input][intermediate_output_name] = []

        inputs = self._generate_random_inputs(nb_samples)
        evaluated_inputs = evaluator.evaluate_vectorized(self._cipher, inputs, intermediate_output=True, verbosity=False)
        input_bits_to_analyse = self._cipher.get_all_inputs_bit_positions()
        for index_of_specific_input, specific_input in enumerate(self._cipher.inputs):  # where the diff is injected
            for input_diff in input_bits_to_analyse[specific_input]:
                intermediate_avalanche_probability_vectors = self._generate_avalanche_probability_vectors(
                    intermediate_output_names, inputs, evaluated_inputs, input_diff, index_of_specific_input)
                for intermediate_output_name in list(intermediate_output_names.keys()):
                    all_avalanche_probability_vectors[specific_input][intermediate_output_name].append(
                        intermediate_avalanche_probability_vectors[intermediate_output_name])

        return all_avalanche_probability_vectors


    def _generate_random_inputs(self, nb_samples):
        inputs = []
        for i in range(len(self._cipher.inputs)):
            inputs.append(np.random.randint(256,
                                            size=(math.ceil(self._cipher.inputs_bit_size[i] / 8), nb_samples),
                                            dtype=np.uint8))

        return inputs


    def _generate_avalanche_probability_vectors(self, dict_intermediate_output_names, inputs,
                                               evaluated_inputs, input_diff, index_of_specific_input):
        inputs_prime = self._generate_inputs_prime(index_of_specific_input, input_diff, inputs)
        evaluated_inputs_prime = evaluator.evaluate_vectorized(self._cipher, inputs_prime,
                                                               intermediate_output=True, verbosity=False)
        intermediate_avalanche_probability_vectors = {}
        for intermediate_output_name in list(dict_intermediate_output_names.keys()):
            intermediate_avalanche_probability_vectors[intermediate_output_name] = \
                [[0] * dict_intermediate_output_names[intermediate_output_name][1] for _ in range(
                    dict_intermediate_output_names[intermediate_output_name][0])]
            state = evaluated_inputs[intermediate_output_name]
            state_prime = evaluated_inputs_prime[intermediate_output_name]
            for occurence_index in range(dict_intermediate_output_names[intermediate_output_name][0]):
                c_diff = state[occurence_index] ^ state_prime[occurence_index]
                for position in list(range(dict_intermediate_output_names[intermediate_output_name][1])):
                    temporary_position = np.average((c_diff[:, position // 8] >> (7 - position % 8)) & 1)
                    intermediate_avalanche_probability_vectors[intermediate_output_name][occurence_index][position] = \
                        temporary_position

        return intermediate_avalanche_probability_vectors


    def _generate_inputs_prime(self, index_of_specific_input, input_diff, inputs):
        inputs_prime = []
        for input_index in range(len(self._cipher.inputs)):
            if input_index == index_of_specific_input:
                diff = (1 << (self._cipher.inputs_bit_size[input_index] - 1 - input_diff))
                diff_vectorized = np.array(
                    np.frombuffer(int.to_bytes(diff, math.ceil(self._cipher.inputs_bit_size[input_index] / 8), byteorder='big'),
                                  dtype=np.uint8)).reshape((-1, 1))
                inputs_prime.append(inputs[input_index] ^ diff_vectorized)
            else:
                inputs_prime.append(inputs[input_index])

        return inputs_prime


    def compute_criterion_from_avalanche_probability_vectors(self, all_avalanche_probability_vectors,
                                                             avalanche_dependence_uniform_bias):
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

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=5)
            sage: from claasp.cipher_modules.avalanche_tests import AvalancheTests
            sage: test = AvalancheTests(speck)
            sage: apvs = test.avalanche_probability_vectors(100)
            sage: d = test.compute_criterion_from_avalanche_probability_vectors(apvs, 0.2) # random

        """
        intermediate_output_names = self._add_intermediate_output_rounds_id_to_dictionary()
        criterion = {}
        for input_tag in all_avalanche_probability_vectors.keys():
            criterion[input_tag] = {}
            for output_tag in all_avalanche_probability_vectors[input_tag].keys():
                criterion[input_tag][output_tag] = {}
                for input_diff in range(len(all_avalanche_probability_vectors[input_tag][output_tag])):
                    criterion[input_tag][output_tag][input_diff] = {}
                    for number_of_occurrence in range(
                            len(all_avalanche_probability_vectors[input_tag][output_tag][input_diff])):
                        criterion[input_tag][output_tag][input_diff][number_of_occurrence] = {}
                        criterion[input_tag][output_tag][input_diff][number_of_occurrence]["round"] = \
                            intermediate_output_names[output_tag][1][number_of_occurrence]
                        vector = all_avalanche_probability_vectors[input_tag][output_tag][input_diff][number_of_occurrence]
                        self._set_vector_dependence(criterion, input_diff, input_tag, number_of_occurrence, output_tag, vector)
                        self._set_vector_dependence_uniform(avalanche_dependence_uniform_bias, criterion, input_diff,
                                                      input_tag, number_of_occurrence, output_tag, vector)
                        self._set_vector_weight(criterion, input_diff, input_tag, number_of_occurrence, output_tag, vector)
                        self._set_vector_entropy(criterion, input_diff, input_tag, number_of_occurrence, output_tag, vector)

        return criterion


    def _set_vector_entropy(self, criterion, input_diff, input_tag, number_of_occurrence, output_tag, vector):
        vector_entropy = [round((-proba * log(proba, 2)) - (1 - proba) *
                                log(1 - proba, 2), 5) if proba not in [0, 1] else 0 for proba in vector]
        criterion[input_tag][output_tag][input_diff][number_of_occurrence][
            "avalanche_entropy_vectors"] = vector_entropy


    def _set_vector_weight(self, criterion, input_diff, input_tag, number_of_occurrence, output_tag, vector):
        criterion[input_tag][output_tag][input_diff][number_of_occurrence]["avalanche_weight_vectors"] = vector


    def _set_vector_dependence_uniform(self, avalanche_dependence_uniform_bias, criterion, input_diff,
                                      input_tag, number_of_occurrence, output_tag, vector):
        bias = avalanche_dependence_uniform_bias
        vector_dependence_uniform = [1 if 1 / 2 - bias <= proba <= 1 / 2 + bias else 0 for proba in vector]
        criterion[input_tag][output_tag][input_diff][number_of_occurrence][
            "avalanche_dependence_uniform_vectors"] = vector_dependence_uniform


    def _set_vector_dependence(self, criterion, input_diff, input_tag, number_of_occurrence, output_tag, vector):
        vector_dependence = [1 if proba != 0 else 0 for proba in vector]
        criterion[input_tag][output_tag][input_diff][number_of_occurrence][
            "avalanche_dependence_vectors"] = vector_dependence

    def _add_intermediate_output_rounds_id_to_dictionary(self):
        dict_intermediate_output_names = {}
        for cipher_round in self._cipher.rounds_as_list:
            for component in cipher_round.components:
                if self._is_output(component):
                    if component.description[0] not in list(dict_intermediate_output_names.keys()):
                        number_of_occurrences = 0
                        rounds_id = []
                        dict_intermediate_output_names[component.description[0]] = [number_of_occurrences, rounds_id]
                    number_of_occurrences_position = 0
                    dict_intermediate_output_names[component.description[0]][number_of_occurrences_position] += 1
                    rounds_id_position = 1
                    dict_intermediate_output_names[component.description[0]][rounds_id_position].append(cipher_round.id)

        return dict_intermediate_output_names

    def generate_3D_plot(self, number_of_samples=100, criterion="avalanche_weight_vectors"):
        r"""
        Return an object that can be plot to visualize the results of the avalanche properties in a 3D graph.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: cipher = SpeckBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=5)
            sage: from claasp.cipher_modules.avalanche_tests import AvalancheTests
            sage: plot = AvalancheTests(cipher).generate_3D_plot(number_of_samples=100)
            sage: type(plot)
            <class 'module'>

            sage: from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation
            sage: cipher = ChachaPermutation(number_of_rounds=5)
            sage: from claasp.cipher_modules.avalanche_tests import AvalancheTests
            sage: plot = AvalancheTests(cipher).generate_3D_plot(number_of_samples=100)
            sage: type(plot)
            <class 'module'>

        """
        if criterion not in ["avalanche_weight_vectors", "avalanche_dependence_vectors", "avalanche_dependence_uniform_vectors", "avalanche_entropy_vectors"]:
            print('criterion must be one of the following: "avalanche_weight_vectors", "avalanche_dependence_vectors", "avalanche_dependence_uniform_vectors", "avalanche_entropy_vectors"')
            return False

        nb_rounds = self._cipher.number_of_rounds
        results = self.avalanche_tests(number_of_samples)
        fig = plt.figure()
        ax = fig.add_subplot(111, projection='3d')

        plaintext_index = self._cipher.inputs.index("plaintext")
        input_bit_size = self._cipher.inputs_bit_size[plaintext_index]

        x = np.zeros(input_bit_size * nb_rounds)
        y = np.zeros(input_bit_size * nb_rounds)
        z = np.zeros(input_bit_size * nb_rounds)
        # add intermediate rounds
        for bit_position in range(input_bit_size):
            for r in range(nb_rounds - 1):
                x[r * input_bit_size + bit_position] = bit_position
                y[r * input_bit_size + bit_position] = r
                z[r * input_bit_size + bit_position] = results["test_results"]["plaintext"]["round_output"][criterion][-2]["vectors"][r][bit_position]
        # add last round
        for bit_position in range(input_bit_size):
            x[(nb_rounds - 1) * input_bit_size + bit_position] = bit_position
            y[(nb_rounds - 1) * input_bit_size + bit_position] = (nb_rounds - 1)
            z[(nb_rounds - 1) * input_bit_size + bit_position] = results["test_results"]["plaintext"]["cipher_output"][criterion][-2]["vectors"][0][bit_position]

        # Define a custom colormap from red to green based on z values
        cmap = LinearSegmentedColormap.from_list('RedGreen', [(1, 0, 0), (0, 1, 0)])
        scatter = ax.scatter(x, y, z, c=z, cmap=cmap, marker='.', label='Data points')

        # Add a color bar to show the mapping of z values to colors
        cbar = fig.colorbar(scatter)
        # cbar.set_label('Avalanche Weight')

        s = ""
        for w in criterion.split("_")[:-1]:
            s += w
            s += " "
        # Customize the plot as needed
        ax.set_xlabel('Output Bit Position')
        ax.set_ylabel('Round')
        ax.set_zlabel(f"Average value of {s}")
        ax.set_title(f"3D {s}plot")

        # Show the plot
        # plt.show()
        print("graph can be plot with the build-in method plot.show()")
        return plt



