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

import numpy as np
from decimal import Decimal
from multiprocessing import Pool

from claasp.cipher_modules import evaluator
from claasp.cipher_modules.generic_functions_continuous_diffusion_analysis import (get_sbox_precomputations,
                                                                                   get_mix_column_precomputations)
from claasp.utils.utils import (merging_list_of_lists, aggregate_list_of_dictionary, generate_sample_from_gf_2_n,
                                group_list_by_key, point_pair, signed_distance)


class ContinuousDiffusionAnalysis:
    def __init__(self, cipher):
        self.cipher = cipher

    def _compute_conditional_expected_value_for_continuous_metric(self, lambda_value, number_of_samples, tag_input):
        def _create_list_fixing_some_inputs(_tag_input):
            max_bias = [-1, 1]
            index_of_tag_input = self.cipher.inputs.index(_tag_input)
            lst_input = []
            i = 0
            for _ in self.cipher.inputs:
                if i == index_of_tag_input:
                    lst_input.append([])
                else:
                    import secrets
                    lst_input.append(
                        [Decimal(max_bias[secrets.choice([0, 1])]) for _ in range(self.cipher.inputs_bit_size[i])])
                i += 1

            return lst_input

        sbox_components = ContinuousDiffusionAnalysis._get_graph_representation_components_by_type(
            self.cipher.as_python_dictionary(), 'sbox'
        )
        sbox_precomputations = get_sbox_precomputations(sbox_components)
        mix_column_components = ContinuousDiffusionAnalysis._get_graph_representation_components_by_type(
            self.cipher.as_python_dictionary(), 'mix_column')
        sbox_precomputations_mix_columns = get_mix_column_precomputations(mix_column_components)
        pool = Pool()
        results = []
        for _ in range(number_of_samples):
            list_of_inputs = _create_list_fixing_some_inputs(tag_input)
            results.append(pool.apply_async(
                self._compute_sample_for_continuous_avalanche_factor,
                args=(lambda_value, list_of_inputs, sbox_precomputations, sbox_precomputations_mix_columns))
            )
        pool.close()
        pool.join()
        continuous_diffusion_tests = {tag_input: {}}
        join_results = [result.get() for result in results]
        flattened_results = merging_list_of_lists(join_results)
        flattened_results_by_tag_output = group_list_by_key(flattened_results)
        for tag_output in flattened_results_by_tag_output.keys():
            agg_by_round_and_tag_output = group_list_by_key(
                merging_list_of_lists(flattened_results_by_tag_output[tag_output])
            )
            values = []
            continuous_diffusion_tests[tag_input][tag_output] = {}
            for round_tag in agg_by_round_and_tag_output.keys():
                value_object = {"round": round_tag, "value": float(
                    sum(agg_by_round_and_tag_output[round_tag]) / Decimal(number_of_samples * 1.0)
                )}
                value_object["value"] = \
                    round(float(value_object["value"] / self.cipher.output_bit_size * 1.0), 3)
                values.append(value_object)

            continuous_diffusion_tests[tag_input][tag_output]["continuous_avalanche_factor"] = {}
            value_list = [X['value'] for X in values]
            continuous_diffusion_tests[tag_input][tag_output]["continuous_avalanche_factor"]["values"] = value_list

        return continuous_diffusion_tests

    def _compute_conditional_expected_value_for_continuous_neutrality_measure(self, input_bit, beta,
                                                                              number_of_samples, tag_input,
                                                                              output_dict):
        def _create_list_fixing_tag_input(_tag_input):
            max_bias = [-1, 1]
            index_of_tag_input = self.cipher.inputs.index(_tag_input)
            lst_input = []
            ii = 0

            for _ in self.cipher.inputs:
                input_size = self.cipher.inputs_bit_size[ii]
                if ii == index_of_tag_input:
                    lst_input.append([])
                else:
                    import secrets
                    lst_input.append([
                        Decimal(max_bias[secrets.choice([0, 1])]) for _ in range(input_size)
                    ])
                ii += 1

            return lst_input

        def compute_vectorized_bias(x):
            return (2 * x - 1).astype('float16')

        def compute_vectorized_psi(x, _input_bit, _beta):
            x[:, _input_bit] *= _beta

        def _create_gf_samples(_number_of_samples, _beta, input_bit):
            _gf_samples = {}
            for input_bit_key in input_bit.keys():
                sample_of_gf_2_n = generate_sample_from_gf_2_n(
                    self.cipher.inputs_bit_size[
                        self.cipher.inputs.index(input_bit_key)],
                    _number_of_samples
                )
                bias_of_sample_of_gf_2_n = compute_vectorized_bias(sample_of_gf_2_n)
                compute_vectorized_psi(bias_of_sample_of_gf_2_n, input_bit[input_bit_key], _beta)
                _gf_samples[input_bit_key] = bias_of_sample_of_gf_2_n

            return _gf_samples

        gf_samples = _create_gf_samples(number_of_samples, beta, input_bit)

        sbox_components = ContinuousDiffusionAnalysis._get_graph_representation_components_by_type(
            self.cipher.as_python_dictionary(), 'sbox')
        sbox_precomputations = get_sbox_precomputations(sbox_components)
        mix_column_components = ContinuousDiffusionAnalysis._get_graph_representation_components_by_type(
            self.cipher.as_python_dictionary(), 'mix_column')
        sbox_precomputations_mix_columns = get_mix_column_precomputations(mix_column_components)

        results = []
        for i in range(number_of_samples):
            list_of_inputs = _create_list_fixing_tag_input(tag_input)
            results.append(
                self._compute_sample_for_continuous_neutrality_measure(
                    list_of_inputs, sbox_precomputations,
                    sbox_precomputations_mix_columns, output_dict,
                    [Decimal(float(gf_sample)) for gf_sample in gf_samples[tag_input][i]]
                )
            )

        continuous_diffusion_tests = {tag_input: {}}
        flattened_results = merging_list_of_lists(results)
        flattened_results_by_tag_output = group_list_by_key(flattened_results)
        for tag_output in flattened_results_by_tag_output.keys():
            agg_by_round_and_tag_output = group_list_by_key(
                merging_list_of_lists(flattened_results_by_tag_output[tag_output])
            )
            values = []
            continuous_diffusion_tests[tag_input][tag_output] = {}
            for round_tag in agg_by_round_and_tag_output.keys():
                value_object = {
                    "round": round_tag, "value": float(sum(agg_by_round_and_tag_output[round_tag]))
                }
                value_object["value"] = round(float(value_object["value"]), 3)
                values.append(value_object)
            #
            continuous_diffusion_tests[tag_input][tag_output]["continuous_neutrality_measure"] = {}
            continuous_diffusion_tests[tag_input][tag_output]["continuous_neutrality_measure"]["values"] = values

        return continuous_diffusion_tests

    def _compute_sample_for_continuous_avalanche_factor(self, lambda_value, lst_input,
                                                        sbox_precomputations, sbox_precomputations_mix_columns):
        index_of_variable_input_size = lst_input.index([])
        x, y = point_pair(lambda_value, self.cipher.inputs_bit_size[index_of_variable_input_size])
        x_inputs = [x if input_element == [] else input_element for input_element in lst_input]
        y_inputs = [y if input_element == [] else input_element for input_element in lst_input]
        sum_by_round = []
        output_evaluated_continuous_diffusion_analysis_x = \
            evaluator.evaluate_with_intermediate_outputs_continuous_diffusion_analysis(
                self.cipher, x_inputs,
                sbox_precomputations, sbox_precomputations_mix_columns)[1]
        output_evaluated_continuous_diffusion_analysis_y = \
            evaluator.evaluate_with_intermediate_outputs_continuous_diffusion_analysis(
                self.cipher, y_inputs,
                sbox_precomputations, sbox_precomputations_mix_columns
            )[1]

        for tag_output in output_evaluated_continuous_diffusion_analysis_x.keys():
            obj = {}
            xc_list = output_evaluated_continuous_diffusion_analysis_x[tag_output]
            yc_list = output_evaluated_continuous_diffusion_analysis_y[tag_output]
            obj[tag_output] = [{} for _ in range(len(xc_list))]
            for j in range(len(xc_list)):
                xc = xc_list[j]['intermediate_output']
                yc = yc_list[j]['intermediate_output']
                signed_distance_xc_yc = signed_distance(xc, yc)
                if str(xc_list[j]['round']) not in obj[tag_output][j]:
                    obj[tag_output][j][str(xc_list[j]['round'])] = signed_distance_xc_yc
                else:
                    obj[tag_output][j][str(xc_list[j]['round'])] += signed_distance_xc_yc
            sum_by_round.append(obj)

        return sum_by_round

    def _compute_sample_for_continuous_neutrality_measure(self, lst_input, sbox_precomputations,
                                                          sbox_precomputations_mix_columns, output_dict, x):
        def mag(xx):
            if xx > 0:
                inner_log = xx.log10().copy_abs()
                outer_log = (inner_log + Decimal('1')).ln() / Decimal('2').ln()
                return outer_log
            return 0

        x_inputs = [
            x if input_element == [] else input_element for input_element in lst_input
        ]
        sum_by_round = []

        output_evaluated_continuous_diffusion_analysis_x = \
            evaluator.evaluate_with_intermediate_outputs_continuous_diffusion_analysis(
                self.cipher, x_inputs, sbox_precomputations, sbox_precomputations_mix_columns)[1]

        if output_dict is None:
            output_dict = {}
        for tag_output in output_evaluated_continuous_diffusion_analysis_x.keys():
            obj = {}
            x_c_list = output_evaluated_continuous_diffusion_analysis_x[tag_output]
            obj[tag_output] = [{} for _ in range(len(x_c_list))]

            for j in range(len(x_c_list)):
                x_c = x_c_list[j]['intermediate_output']
                output_bits_sum = sum([mag(x_c[idx]) for idx in output_dict[tag_output]])
                if str(x_c_list[j]['round']) not in obj[tag_output][j]:
                    obj[tag_output][j][str(x_c_list[j]['round'])] = output_bits_sum
                else:
                    obj[tag_output][j][str(x_c_list[j]['round'])] += output_bits_sum
            sum_by_round.append(obj)

        return sum_by_round

    @staticmethod
    def _get_graph_representation_components_by_type(graph_representation, type_name):
        cipher_rounds = sum(graph_representation["cipher_rounds"], [])
        components_by_type = list(filter(lambda d: d['type'] in [type_name], cipher_rounds))
        return components_by_type

    @staticmethod
    def _get_graph_representation_tag_output_sizes(graph_representation):
        temp_components = {}
        component_descriptions = []
        cipher_rounds = graph_representation["cipher_rounds"]
        for cipher_round in cipher_rounds:
            for component in cipher_round:
                if (component["type"] == "intermediate_output" or component["type"] == "cipher_output") and \
                        component["description"] not in component_descriptions:
                    component_descriptions.append(component["description"])

                    temp_components[component["description"][0]] = list(range(component["output_bit_size"]))

        return temp_components

    def continuous_avalanche_factor(self, lambda_value, number_of_samples):
        """
        Continuous generalization of the metric Avalanche Factor. This method implements Definition 14 of [MUR2020]_.

        INPUT:

        - ``lambda_value`` --  **float**; threshold value used to express the input difference
        - ``number_of_samples`` --  **integer**; number of samples used to compute the continuous avalanche factor

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher as speck
            sage: from claasp.cipher_modules.continuous_diffusion_analysis import ContinuousDiffusionAnalysis
            sage: speck_cipher = speck(number_of_rounds=2)
            sage: cda = ContinuousDiffusionAnalysis(speck_cipher)
            sage: result = cda.continuous_avalanche_factor(0.001, 10)
            sage: result['plaintext']['round_key_output']['continuous_avalanche_factor']['values'][0]
            0.0
        """
        input_tags = self.cipher.inputs
        final_dict = {}
        for input_tag in input_tags:
            continuous_avalanche_factor_by_tag_input_dict = \
                self._compute_conditional_expected_value_for_continuous_metric(
                    lambda_value, number_of_samples, input_tag)
            final_dict = {**final_dict, **continuous_avalanche_factor_by_tag_input_dict}

        return final_dict

    def continuous_diffusion_factor(self, beta_number_of_samples, gf_number_samples):
        """
        Continuous Diffusion Factor. This method implements Definition 16 of [MUR2020]_.

        INPUT:

        - ``beta_number_of_samples`` -- **integer**; number of samples used to compute the continuous measure metric
        - ``gf_number_samples`` -- **integer**;  number of vectors used to approximate gf_2

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher as speck
            sage: from claasp.cipher_modules.continuous_diffusion_analysis import ContinuousDiffusionAnalysis
            sage: speck_cipher = speck(number_of_rounds=2) # long time
            sage: cda = ContinuousDiffusionAnalysis(speck_cipher) # doctest: +SKIP
            sage: output = cda.continuous_diffusion_factor(5, 20) # long time # doctest: +SKIP
            sage: output['plaintext']['cipher_output']['diffusion_factor']['values'][0] > 0 # long time # doctest: +SKIP
            True
        """
        output_tags = list(ContinuousDiffusionAnalysis._get_graph_representation_tag_output_sizes(
            self.cipher.as_python_dictionary()).keys())
        continuous_neutrality_measures = {input_tag: {ot: {"diffusion_factor": {"values": []}} for ot in output_tags}
                                          for input_tag in self.cipher.inputs}

        for i, cipher_input_size in enumerate(self.cipher.inputs_bit_size):
            input_tag = self.cipher.inputs[i]
            for input_bit in range(cipher_input_size):
                continuous_neutrality_measures_output = self.continuous_neutrality_measure_for_bit_j(
                    beta_number_of_samples, gf_number_samples, input_bit={input_tag: input_bit})
                for output_tag in output_tags:
                    continuous_neutrality_measures_values = \
                        continuous_neutrality_measures_output[input_tag][output_tag][
                            "continuous_neutrality_measure"]["values"]
                    if not continuous_neutrality_measures[input_tag][output_tag]["diffusion_factor"]["values"]:
                        continuous_neutrality_measures[input_tag][output_tag]["diffusion_factor"]["values"] = [{} for _
                                                                                                               in
                                                                                                               continuous_neutrality_measures_values]
                    ContinuousDiffusionAnalysis._incrementing_counters(
                        continuous_neutrality_measures_values,
                        continuous_neutrality_measures,
                        cipher_input_size, input_tag,
                        output_tag, input_bit
                    )

        # Simplify the aggregation of values
        for it, outs in continuous_neutrality_measures.items():
            for out, data in outs.items():
                values = data['diffusion_factor']['values']
                flattened_values = [value for sublist in values for value in sublist.values()]
                continuous_neutrality_measures[it][out]['diffusion_factor']['values'] = flattened_values

        return continuous_neutrality_measures

    @staticmethod
    def _incrementing_counters(continuous_neutrality_measures_output_values_, continuous_neutrality_measures_,
                               cipher_input_size_, input_tag_, output_tag_, input_bit):
        df_values = continuous_neutrality_measures_[input_tag_][output_tag_]["diffusion_factor"]["values"]
        for index in range(len(continuous_neutrality_measures_output_values_)):
            for key in continuous_neutrality_measures_output_values_[index]:
                if any(key in d for d in df_values):
                    if input_bit == cipher_input_size_ - 1:
                        df_values[index][key] /= cipher_input_size_
                    else:
                        df_values[index][key] += continuous_neutrality_measures_output_values_[index][key]
                else:
                    df_values[index][key] = 0.0

    @staticmethod
    def _merge_dictionaries(continuous_diffusion_factor_output, continuous_avalanche_factor_output,
                            continuous_neutrality_measure_output, is_continuous_avalanche_factor,
                            is_continuous_neutrality_measure,
                            is_diffusion_factor):
        merged_dict = {}

        def merge_two_dicts(target, source):
            for k, v in source.items():
                if isinstance(v, dict):
                    target[k] = merge_two_dicts(target.get(k, {}), v)
                else:
                    if k in target and isinstance(target[k], list) and isinstance(v, list):
                        target[k] += v  # Extend if both are lists
                    else:
                        target[k] = v
            return target

        dict_of_outputs = [
            (continuous_diffusion_factor_output, is_diffusion_factor),
            (continuous_avalanche_factor_output, is_continuous_avalanche_factor),
            (continuous_neutrality_measure_output, is_continuous_neutrality_measure)
        ]

        for dict_output, flag in dict_of_outputs:
            if flag:
                merged_dict = merge_two_dicts(merged_dict, dict_output)

        return merged_dict

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
            sage: from claasp.cipher_modules.continuous_diffusion_analysis import ContinuousDiffusionAnalysis
            sage: speck_cipher = speck(number_of_rounds=1) # long time
            sage: cda = ContinuousDiffusionAnalysis(speck_cipher) # doctest: +SKIP
            sage: output = cda.continuous_diffusion_tests() # long time # doctest: +SKIP
            sage: output["test_results"]['plaintext']['round_key_output']['continuous_neutrality_measure'][0]['values'][0] == 0.0  # long time # doctest: +SKIP
            True
        """
        continuous_diffusion_tests = {"input_parameters": {
            'test_name': 'continuous_diffusion_tests',
            'cipher': self.cipher,
            'continuous_avalanche_factor_number_of_samples': continuous_avalanche_factor_number_of_samples,
            'threshold_for_avalanche_factor': threshold_for_avalanche_factor,
            'continuous_neutral_measure_beta_number_of_samples': continuous_neutral_measure_beta_number_of_samples,
            'continuous_neutral_measure_gf_number_samples': continuous_neutral_measure_gf_number_samples,
            'continuous_diffusion_factor_beta_number_of_samples': continuous_diffusion_factor_beta_number_of_samples,
            'continuous_diffusion_factor_gf_number_samples': continuous_diffusion_factor_gf_number_samples,
            'is_continuous_avalanche_factor': is_continuous_avalanche_factor,
            'is_continuous_neutrality_measure': is_continuous_neutrality_measure,
            'is_diffusion_factor': is_diffusion_factor
        },
            "test_results": {}}
        continuous_diffusion_factor_output = {}
        continuous_neutrality_measure_output = {}
        continuous_avalanche_factor_output = {}
        if is_diffusion_factor:
            continuous_diffusion_factor_output = self.continuous_diffusion_factor(
                continuous_diffusion_factor_beta_number_of_samples,
                continuous_diffusion_factor_gf_number_samples)
            inputs_tags = list(continuous_diffusion_factor_output.keys())
            output_tags = list(continuous_diffusion_factor_output[inputs_tags[0]].keys())
        if is_continuous_neutrality_measure:
            continuous_neutrality_measure_output = self.continuous_neutrality_measure_for_bit_j(
                continuous_neutral_measure_beta_number_of_samples,
                continuous_neutral_measure_gf_number_samples)
            inputs_tags = list(continuous_neutrality_measure_output.keys())
            output_tags = list(continuous_neutrality_measure_output[inputs_tags[0]].keys())
            for it in inputs_tags:
                for out in output_tags:
                    copy_values = [list(X.values()) for X in
                                   continuous_neutrality_measure_output[it][out]['continuous_neutrality_measure'][
                                       'values']]
                    copy_values = [value for round in copy_values for value in round]
                    continuous_neutrality_measure_output[it][out]['continuous_neutrality_measure'][
                        'values'] = copy_values
                    continuous_neutrality_measure_output[it][out]['continuous_neutrality_measure'].pop('input_bit')
                    continuous_neutrality_measure_output[it][out]['continuous_neutrality_measure'].pop('output_bits')
        if is_continuous_avalanche_factor:
            continuous_avalanche_factor_output = self.continuous_avalanche_factor(
                threshold_for_avalanche_factor, continuous_avalanche_factor_number_of_samples)
            inputs_tags = list(continuous_avalanche_factor_output.keys())
            output_tags = list(continuous_avalanche_factor_output[inputs_tags[0]].keys())

        continuous_diffusion_tests["test_results"] = ContinuousDiffusionAnalysis._merge_dictionaries(
            continuous_diffusion_factor_output, continuous_avalanche_factor_output,
            continuous_neutrality_measure_output, is_continuous_avalanche_factor,
            is_continuous_neutrality_measure,
            is_diffusion_factor)
        for input_tag in inputs_tags:
            for output_tag in output_tags:
                for test in continuous_diffusion_tests["test_results"][input_tag][output_tag].keys():
                    continuous_diffusion_tests["test_results"][input_tag][output_tag][test] = [
                        continuous_diffusion_tests["test_results"][input_tag][output_tag][test]]
        return continuous_diffusion_tests

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
            sage: from claasp.cipher_modules.continuous_diffusion_analysis import ContinuousDiffusionAnalysis
            sage: speck_cipher = speck(number_of_rounds=2)
            sage: cda = ContinuousDiffusionAnalysis(speck_cipher)
            sage: output = cda.continuous_neutrality_measure_for_bit_j(50, 200) # long time
            sage: output['plaintext']['cipher_output']['continuous_neutrality_measure']['values'][0]['2'] > 0 # long time
            True
        """
        if output_bits is None:
            output_bits = ContinuousDiffusionAnalysis._get_graph_representation_tag_output_sizes(
                self.cipher.as_python_dictionary())
        if input_bit is None:
            input_bit = self._init_input_bits()

        beta_sample_outputs = self._generate_beta_sample_output(beta_number_of_samples, gf_number_samples,
                                                                input_bit, output_bits)
        inputs_tags = list(beta_sample_outputs[0].keys())
        output_tags = list(beta_sample_outputs[0][inputs_tags[0]].keys())
        final_result = ContinuousDiffusionAnalysis._init_final_result_structure(
            input_bit, inputs_tags, output_bits, output_tags)
        final_result = ContinuousDiffusionAnalysis._add_beta_samples_to_final_result_from(beta_sample_outputs,
                                                                                          inputs_tags, output_tags,
                                                                                          final_result)

        for inputs_tag in inputs_tags:
            for output_tag in output_tags:
                values = merging_list_of_lists(
                    final_result[inputs_tag][output_tag]["continuous_neutrality_measure"]["values"])
                total_values_by_round = aggregate_list_of_dictionary(values, "round", ["value"])

                final_result[inputs_tag][output_tag]["continuous_neutrality_measure"]["values"] = []
                for key, item in total_values_by_round.items():
                    final_result[inputs_tag][output_tag]["continuous_neutrality_measure"]["values"].append(
                        {key: item["value"] / beta_number_of_samples / gf_number_samples / len(
                            output_bits[output_tag])})

        return final_result

    @staticmethod
    def _add_beta_samples_to_final_result_from(beta_sample_outputs, inputs_tags, output_tags, final_result):
        for beta_sample_output in beta_sample_outputs:
            for inputs_tag in inputs_tags:
                for output_tag in output_tags:
                    final_result[inputs_tag][output_tag]["continuous_neutrality_measure"]["values"].append(
                        beta_sample_output[inputs_tag][output_tag]["continuous_neutrality_measure"]["values"])

        return final_result

    @staticmethod
    def _init_final_result_structure(input_bit, inputs_tags, output_bits, output_tags):
        final_result = {}
        for inputs_tag in inputs_tags:
            final_result[inputs_tag] = {}
            for output_tag in output_tags:
                final_result[inputs_tag][output_tag] = {}
                final_result[inputs_tag][output_tag]["continuous_neutrality_measure"] = {}
                final_result_cnm = final_result[inputs_tag][output_tag]["continuous_neutrality_measure"]
                final_result_cnm["values"] = []
                final_result_cnm["input_bit"] = input_bit
                final_result_cnm["output_bits"] = output_bits[output_tag]

        return final_result

    def _generate_beta_sample_output(self, beta_number_of_samples, gf_number_samples, input_bit, output_bits):
        betas = np.random.uniform(low=-1.0, high=1.0, size=beta_number_of_samples)
        beta_sample_outputs_temp = []
        pool = Pool()
        for i in range(beta_number_of_samples):
            beta_sample_outputs_temp.append(
                pool.apply_async(self._continuous_neutrality_measure_for_bit_j_and_beta,
                                 args=(input_bit, float(betas[i]), gf_number_samples, output_bits)))
        pool.close()
        pool.join()
        beta_sample_outputs = [result.get() for result in beta_sample_outputs_temp]

        return beta_sample_outputs

    def _init_input_bits(self):
        input_bit = {}
        for cipher_input in self.cipher.inputs:
            input_bit[cipher_input] = 0

        return input_bit

    def _continuous_neutrality_measure_for_bit_j_and_beta(self, input_bit, beta, number_of_samples, output_bits):
        input_tags = input_bit.keys()
        continuous_diffusion_tests = {}
        for input_tag in input_tags:
            continuous_avalanche_factor_by_tag_input_dict = \
                self._compute_conditional_expected_value_for_continuous_neutrality_measure(input_bit,
                                                                                           beta, number_of_samples,
                                                                                           input_tag, output_bits)
            continuous_diffusion_tests = {
                **continuous_diffusion_tests, **continuous_avalanche_factor_by_tag_input_dict
            }

        return continuous_diffusion_tests
