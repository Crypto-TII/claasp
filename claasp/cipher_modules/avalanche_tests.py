
# ****************************************************************************
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


def avalanche_tests(cipher, number_of_samples=5, avalanche_dependence_uniform_bias=0.05,
                    avalanche_dependence_criterion_threshold=0, avalanche_dependence_uniform_criterion_threshold=0,
                    avalanche_weight_criterion_threshold=0.01, avalanche_entropy_criterion_threshold=0.01,
                    run_avalanche_dependence=True, run_avalanche_dependence_uniform=True,
                    run_avalanche_weight=True, run_avalanche_entropy=True):

    all_avalanche_probability_vectors = avalanche_probability_vectors(cipher, number_of_samples)
    criterion = compute_criterion_from_avalanche_probability_vectors(cipher, all_avalanche_probability_vectors,
                                                                     avalanche_dependence_uniform_bias)
    intermediate_output_names = add_intermediate_output_components_id_to_dictionary(cipher.get_all_components())
    diffusion_tests = {
        "input_parameters": {
            "number_of_samples": number_of_samples,
            "avalanche_dependence_uniform_bias": avalanche_dependence_uniform_bias,
            "avalanche_dependence_criterion_threshold": avalanche_dependence_criterion_threshold,
            "avalanche_dependence_uniform_criterion_threshold": avalanche_dependence_uniform_criterion_threshold,
            "avalanche_weight_criterion_threshold": avalanche_weight_criterion_threshold,
            "avalanche_entropy_criterion_threshold": avalanche_entropy_criterion_threshold}}

    test_results = init_dictionary_test_results(cipher, intermediate_output_names)

    parameters = {
        "avalanche_dependence_vectors": [run_avalanche_dependence, 1,
                                         avalanche_dependence_criterion_threshold],
        "avalanche_dependence_uniform_vectors": [run_avalanche_dependence_uniform, 1,
                                                 avalanche_dependence_uniform_criterion_threshold],
        "avalanche_weight_vectors": [run_avalanche_weight, 1 / 2, avalanche_weight_criterion_threshold],
        "avalanche_entropy_vectors": [run_avalanche_entropy, 1, avalanche_entropy_criterion_threshold]}

    for criterion_name in parameters.keys():
        for index, input_name in enumerate(cipher.inputs):
            for intermediate_output_name in list(intermediate_output_names.keys()):
                if parameters[criterion_name][0]:
                    add_intermediate_output_values_to_dictionary(cipher, criterion_name, intermediate_output_names,
                                                                 parameters, test_results, index, input_name,
                                                                 intermediate_output_name)
                    all_output_vectors, largest_round_criterion_not_satisfied = \
                        calculate_regular_difference(criterion_name, criterion, intermediate_output_names, parameters,
                                                     test_results, input_name, intermediate_output_name)
                    calculate_average_difference(all_output_vectors, criterion_name, parameters, test_results,
                                                 input_name, intermediate_output_name)
                    calculate_worst_input_differences(cipher, criterion_name, largest_round_criterion_not_satisfied,
                                                      test_results, input_name, intermediate_output_name)
    diffusion_tests["test_results"] = test_results

    return diffusion_tests


def init_dictionary_test_results(cipher, dict_intermediate_output_names):
    dict_test_results = {}
    for input_name in cipher.inputs:
        dict_test_results[input_name] = {}
        for intermediate_output_name in list(dict_intermediate_output_names.keys()):
            dict_test_results[input_name][intermediate_output_name] = {}

    return dict_test_results


def is_output(component):
    return component.type == INTERMEDIATE_OUTPUT or component.type == CIPHER_OUTPUT


def add_intermediate_output_components_id_to_dictionary(components):
    intermediate_output_names = {}
    for component in components:
        if is_output(component):
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


def add_intermediate_output_values_to_dictionary(cipher, criterion_name, dict_intermediate_output_names,
                                                 dict_parameters, dict_test_results, index,
                                                 input_name, intermediate_output_name):
    dict_test_results[input_name][intermediate_output_name][criterion_name] = {}
    dict_test_results[input_name][intermediate_output_name][criterion_name]["input_bit_size"] = \
        cipher.inputs_bit_size[index]
    output_bit_size = dict_intermediate_output_names[intermediate_output_name][0]
    dict_test_results[input_name][intermediate_output_name][criterion_name]["output_bit_size"] = output_bit_size
    dict_test_results[input_name][intermediate_output_name][criterion_name]["max_possible_value_per_bit"] = 1
    dict_test_results[input_name][intermediate_output_name][criterion_name]["min_possible_value_per_bit"] = 0
    dict_test_results[input_name][intermediate_output_name][criterion_name]["expected_value_per_bit"] = \
        dict_parameters[criterion_name][1]
    dict_test_results[input_name][intermediate_output_name][criterion_name]["max_possible_value_per_output_block"] = \
        output_bit_size
    dict_test_results[input_name][intermediate_output_name][criterion_name]["min_possible_value_per_output_block"] = 0
    dict_test_results[input_name][intermediate_output_name][criterion_name]["expected_value_per_output_block"] = \
        output_bit_size * dict_parameters[criterion_name][1]
    dict_test_results[input_name][intermediate_output_name][criterion_name]["differences"] = []


def calculate_regular_difference(criterion_name, dict_criterion, dict_intermediate_output_names, dict_parameters,
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
            expected_value_per_output_block = dict_test_results[input_name][intermediate_output_name][criterion_name][
                "expected_value_per_output_block"]
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
        dict_for_each_input_diff = {"input_difference_type": "regular",
                                    "input_difference_value": hex(1 << index_input_diff),
                                    "output_vectors": output_vectors}
        dict_test_results[input_name][intermediate_output_name][criterion_name]["differences"].append(
            dict_for_each_input_diff)

    return all_output_vectors, dict_largest_round_criterion_not_satisfied


def calculate_average_difference(all_output_vectors, criterion_name, dict_parameters, dict_test_results, input_name,
                                 intermediate_output_name):
    dict_for_average_diff = {"input_difference_type": "average", "input_difference_value": 0}
    output_vectors = []
    for current_round in all_output_vectors.keys():
        tmp_dict = {}
        average_vector = [
            sum(vec) /
            dict_test_results[input_name][intermediate_output_name][criterion_name][
                "input_bit_size"] for vec in zip(
                *
                all_output_vectors[current_round])]
        tmp_dict["vector"] = average_vector
        tmp_dict["total"] = sum(tmp_dict["vector"])
        expected_value_per_output_block = dict_test_results[input_name][
            intermediate_output_name][criterion_name]["expected_value_per_output_block"]
        threshold = dict_parameters[criterion_name][2]
        if expected_value_per_output_block - \
                threshold <= tmp_dict["total"] <= expected_value_per_output_block + threshold:
            tmp_dict["criterion_satisfied"] = True
        else:
            tmp_dict["criterion_satisfied"] = False
        tmp_dict["round"] = current_round
        tmp_dict["output_component_id"] = "None"
        output_vectors.append(tmp_dict)
    dict_for_average_diff["output_vectors"] = output_vectors
    dict_test_results[input_name][intermediate_output_name][criterion_name]["differences"].append(
        dict_for_average_diff)


def calculate_worst_input_differences(cipher, criterion_name, largest_round_criterion_not_satisfied,
                                      dict_test_results, input_name, intermediate_output_name):
    max_round_criterion_not_satisfied = max(
        largest_round_criterion_not_satisfied.values(), default=cipher.number_of_rounds)
    worst_input_diffs = [input_diff for input_diff, specific_round in
                         largest_round_criterion_not_satisfied.items()
                         if specific_round == max_round_criterion_not_satisfied]
    dict_test_results[input_name][intermediate_output_name][criterion_name]["worst_differences"] = worst_input_diffs


def avalanche_probability_vectors(cipher, nb_samples):

    intermediate_output_names = {}
    for component in cipher.get_all_components():
        if is_output(component):
            if component.description[0] not in list(intermediate_output_names.keys()):
                intermediate_output_names[component.description[0]] = [0, component.output_bit_size]
            intermediate_output_names[component.description[0]][0] += 1

    # Structure of all_avalanche_probability_vectors:
    # Example :
    # all_avalanche_probability_vectors['key']['round_output'][i] = [apv_round_0,apv_round_1, ... , apv_round_(n-1)]
    # where the diff has been injected in position i
    all_avalanche_probability_vectors = {}
    for cipher_input in cipher.inputs:
        all_avalanche_probability_vectors[cipher_input] = {}
        for intermediate_output_name in list(intermediate_output_names.keys()):
            all_avalanche_probability_vectors[cipher_input][intermediate_output_name] = []

    inputs = generate_random_inputs(cipher, nb_samples)
    evaluated_inputs = evaluator.evaluate_vectorized(cipher, inputs, intermediate_outputs=True, verbosity=False)
    input_bits_to_analyse = cipher.get_all_inputs_bit_positions()
    for index_of_specific_input, specific_input in enumerate(cipher.inputs):  # where the diff is injected
        for input_diff in input_bits_to_analyse[specific_input]:
            intermediate_avalanche_probability_vectors = generate_avalanche_probability_vectors(
                cipher, intermediate_output_names, inputs, evaluated_inputs, input_diff, index_of_specific_input)
            for intermediate_output_name in list(intermediate_output_names.keys()):
                all_avalanche_probability_vectors[specific_input][intermediate_output_name].append(
                    intermediate_avalanche_probability_vectors[intermediate_output_name])

    return all_avalanche_probability_vectors


def generate_random_inputs(cipher, nb_samples):
    inputs = []
    for i in range(len(cipher.inputs)):
        inputs.append(np.random.randint(256,
                                        size=(math.ceil(cipher.inputs_bit_size[i] / 8), nb_samples),
                                        dtype=np.uint8))

    return inputs


def generate_avalanche_probability_vectors(cipher, dict_intermediate_output_names, inputs,
                                           evaluated_inputs, input_diff, index_of_specific_input):
    inputs_prime = generate_inputs_prime(cipher, index_of_specific_input, input_diff, inputs)
    evaluated_inputs_prime = evaluator.evaluate_vectorized(cipher, inputs_prime,
                                                           intermediate_outputs=True, verbosity=False)
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


def generate_inputs_prime(cipher, index_of_specific_input, input_diff, inputs):
    inputs_prime = []
    for input_index in range(len(cipher.inputs)):
        if input_index == index_of_specific_input:
            diff = (1 << (cipher.inputs_bit_size[input_index] - 1 - input_diff))
            diff_vectorized = np.array(
                np.frombuffer(int.to_bytes(diff, math.ceil(cipher.inputs_bit_size[input_index] / 8), byteorder='big'),
                              dtype=np.uint8)).reshape((-1, 1))
            inputs_prime.append(inputs[input_index] ^ diff_vectorized)
        else:
            inputs_prime.append(inputs[input_index])

    return inputs_prime


def compute_criterion_from_avalanche_probability_vectors(cipher, all_avalanche_probability_vectors,
                                                         avalanche_dependence_uniform_bias):
    intermediate_output_names = add_intermediate_output_rounds_id_to_dictionary(cipher)
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
                    set_vector_dependence(criterion, input_diff, input_tag, number_of_occurrence, output_tag, vector)
                    set_vector_dependence_uniform(avalanche_dependence_uniform_bias, criterion, input_diff,
                                                  input_tag, number_of_occurrence, output_tag, vector)
                    set_vector_weight(criterion, input_diff, input_tag, number_of_occurrence, output_tag, vector)
                    set_vector_entropy(criterion, input_diff, input_tag, number_of_occurrence, output_tag, vector)

    return criterion


def set_vector_entropy(criterion, input_diff, input_tag, number_of_occurrence, output_tag, vector):
    vector_entropy = [round((-proba * log(proba, 2)) - (1 - proba) *
                            log(1 - proba, 2), 5) if proba not in [0, 1] else 0 for proba in vector]
    criterion[input_tag][output_tag][input_diff][number_of_occurrence][
        "avalanche_entropy_vectors"] = vector_entropy


def set_vector_weight(criterion, input_diff, input_tag, number_of_occurrence, output_tag, vector):
    criterion[input_tag][output_tag][input_diff][number_of_occurrence]["avalanche_weight_vectors"] = vector


def set_vector_dependence_uniform(avalanche_dependence_uniform_bias, criterion, input_diff,
                                  input_tag, number_of_occurrence, output_tag, vector):
    bias = avalanche_dependence_uniform_bias
    vector_dependence_uniform = [1 if 1 / 2 - bias <= proba <= 1 / 2 + bias else 0 for proba in vector]
    criterion[input_tag][output_tag][input_diff][number_of_occurrence][
        "avalanche_dependence_uniform_vectors"] = vector_dependence_uniform


def set_vector_dependence(criterion, input_diff, input_tag, number_of_occurrence, output_tag, vector):
    vector_dependence = [1 if proba != 0 else 0 for proba in vector]
    criterion[input_tag][output_tag][input_diff][number_of_occurrence][
        "avalanche_dependence_vectors"] = vector_dependence


def add_intermediate_output_rounds_id_to_dictionary(cipher):
    dict_intermediate_output_names = {}
    for cipher_round in cipher.rounds_as_list:
        for component in cipher_round.components:
            if is_output(component):
                if component.description[0] not in list(dict_intermediate_output_names.keys()):
                    number_of_occurrences = 0
                    rounds_id = []
                    dict_intermediate_output_names[component.description[0]] = [number_of_occurrences, rounds_id]
                number_of_occurrences_position = 0
                dict_intermediate_output_names[component.description[0]][number_of_occurrences_position] += 1
                rounds_id_position = 1
                dict_intermediate_output_names[component.description[0]][rounds_id_position].append(cipher_round.id)

    return dict_intermediate_output_names


def get_average_criteria_by_round_input_output(diffusion_tests_results, round_i, input_tag, output_tag):
    output_tag_dict = diffusion_tests_results['test_results'][input_tag][output_tag]
    avalanche_criterion = \
        output_tag_dict['avalanche_dependence_vectors']['differences'][-1]['output_vectors'][round_i]
    weight_criterion = \
        output_tag_dict['avalanche_weight_vectors']['differences'][-1]['output_vectors'][round_i]
    entropy_criterion = \
        output_tag_dict['avalanche_entropy_vectors']['differences'][-1]['output_vectors'][round_i]

    return avalanche_criterion, weight_criterion, entropy_criterion


def get_average_criteria_list_by_output_tag(diffusion_tests_results, output_tag):
    first_input_tag = list(diffusion_tests_results['test_results'].keys())[0]
    test_results_by_output_tag = diffusion_tests_results['test_results'][first_input_tag][output_tag]
    vectors_size = len(
        test_results_by_output_tag['avalanche_dependence_vectors']['differences'][-1]['output_vectors']
    )
    property_values_array = []
    for round_i in range(vectors_size):
        property_values = {}
        for input_tag in diffusion_tests_results['test_results'].keys():
            diffusion_tests_criteria = list(get_average_criteria_by_round_input_output(
                diffusion_tests_results, round_i, input_tag, output_tag
            ))
            avalanche_criterion = diffusion_tests_criteria[0]
            weight_criterion = diffusion_tests_criteria[1]
            entropy_criterion = diffusion_tests_criteria[2]
            property_values_temp = {
                'tag': output_tag,
                f'dependence {input_tag}': avalanche_criterion['total'],
                f'weight {input_tag}': weight_criterion['total'],
                f'entropy {input_tag}': entropy_criterion['total'],
            }
            property_values = {**property_values, **property_values_temp}
        property_values_array.append(
            {**{f'round {input_tag}': avalanche_criterion['round']}, **property_values}
        )

    return property_values_array


def generate_heatmap_graphs_for_avalanche_tests(cipher, avalanche_results,
                                                difference_positions=None, criterion_names=None):
    intermediate_output_names = get_intermediate_output_names(cipher)

    default_criteria = ["avalanche_dependence_vectors", "avalanche_dependence_uniform_vectors",
                        "avalanche_entropy_vectors", "avalanche_weight_vectors"]
    criteria = criterion_names if criterion_names else default_criteria

    step_divider = 2
    modulo_divider = 4
    if cipher.inputs_bit_size[0] >= 128:
        step_divider = 8
        modulo_divider = 16
    elif cipher.inputs_bit_size[0] <= 16:
        step_divider = 1
        modulo_divider = 1
    step = int(cipher.inputs_bit_size[0] / step_divider)
    modulo = int(cipher.inputs_bit_size[0] / modulo_divider)

    code = ["\\documentclass[12pt]{article}", "\\usepackage{tikz}", "\\usepackage{collcell}", "\\usepackage{diagbox}",
            "\\usepackage{rotating}", "\\usepackage{graphicx}", "\\usepackage{eqparbox} ",
            "\\usepackage[margin=0.5in]{geometry}\n", "\\renewcommand{\\arraystretch}{0}",
            "\\setlength{\\fboxsep}{2mm} % box size", "\\setlength{\\tabcolsep}{3pt}\n",
            "\\newcommand*{\\MinNumberEntropy}{0}", "\\newcommand*{\\MidNumberEntropy}{0.99}",
            "\\newcommand*{\\MaxNumberEntropy}{1}", "\\newcommand{\\ApplyGradientEntropy}[1]{",
            "\t\\ifdim #1 pt > \\MidNumberEntropy pt",
            "\t\t\\pgfmathsetmacro{\\PercentColor}{max(min(100.0*(#1 - \\MidNumberEntropy)/(\\MaxNumberEntropy-"
            "\\MidNumberEntropy),100.0),0.00)}",
            "\t\t\\hspace{-0.3em}\\colorbox{green!\\PercentColor!green}{#1} % add #1 in last "
            "paranthesis to print the value as well", "\t\\else",
            "\t\t\\pgfmathsetmacro{\\PercentColor}{max(min(100.0*(\\MidNumberEntropy - #1)/(\\MidNumberEntropy-"
            "\\MinNumberEntropy),100.0),0.00)}",
            "\t\t\\hspace{-0.3em}\\colorbox{red!\\PercentColor!green}{#1} % add #1 in last paranthesis to "
            "print the value as well", "\t\\fi\n}",
            "\\newcolumntype{E}{>{\\collectcell\\ApplyGradientEntropy}c<{\\endcollectcell}}",
            "\\newcommand*{\\MaxNumberDependance}{0.99}", "\\newcommand{\\ApplyGradientDependance}[1]{",
            "\t\\ifdim#1 pt > \\MaxNumberDependance pt", "\t\t\\hspace{-0.3em}\\colorbox{green}{#1}", "\t\\else",
            "\t\t\\hspace{-0.3em}\\colorbox{red}{#1}", "\t\\fi\n}",
            "\\newcolumntype{D}{>{\\collectcell\\ApplyGradientDependance}c<{\\endcollectcell}}",
            "\\newcommand*{\\MinNumberWeight}{0}", "\\newcommand*{\\MidNumberWeight}{0.5}",
            "\\newcommand*{\\MaxNumberWeight}{1}", "\\newcommand{\\ApplyGradientWeight}[1]{",
            "\t\\ifdim #1 pt > \\MidNumberWeight pt",
            "\t\t\\pgfmathsetmacro{\\PercentColor}{max(min(100.0*(#1 - \\MidNumberWeight)/(\\MaxNumberWeight-"
            "\\MidNumberWeight),100.0),0.00)}",
            "\t\t\\hspace{-0.3em}\\colorbox{red!\\PercentColor!green}{#1} % add #1 in last paranthesis to "
            "print the value as well", "\t\\else",
            "\t\t\\pgfmathsetmacro{\\PercentColor}{max(min(100.0*(\\MidNumberWeight - #1)/(\\MidNumberWeight-"
            "\\MinNumberWeight),100.0),0.00)}",
            "\t\t\\hspace{-0.3em}\\colorbox{red!\\PercentColor!green}{#1} % add #1 in last paranthesis to "
            "print the value as well", "\t\\fi\n}",
            "\\newcolumntype{W}{>{\\collectcell\\ApplyGradientWeight}c<{\\endcollectcell}}", "\\begin{document}\n"]

    for criterion in criteria:
        for cipher_input in cipher.inputs:
            for intermediate_output in list(intermediate_output_names.keys()):
                if intermediate_output == "round_output":  # remove if you want to analyse the other intermediate output
                    generate_graph_by_differences_positions(avalanche_results, code, criterion, difference_positions,
                                                            cipher_input, intermediate_output, modulo, step)

    code.append("\\end{document}")
    str_code = "\n".join(code)
    return str_code


def get_intermediate_output_names(cipher):
    dict_intermediate_output_names = {}
    for component in cipher.get_all_components():
        if component.type in [INTERMEDIATE_OUTPUT, CIPHER_OUTPUT]:
            dict_intermediate_output_names.setdefault(component.description[0], [component.output_bit_size, 0, []])
            dict_intermediate_output_names[component.description[0]][1] += 1
            dict_intermediate_output_names[component.description[0]][2].append(component.id)
    return dict_intermediate_output_names


def generate_graph_by_differences_positions(avalanche_results, code, criterion, difference_positions,
                                            input, intermediate_output, modulo, step):
    worst_diffs = avalanche_results[
        "test_results"][input][intermediate_output][criterion]["worst_differences"]
    differences_on_one_worst_diff = [worst_diffs[0]] + [-1] if len(worst_diffs) != 0 else [0, -1]
    differences = difference_positions if difference_positions else differences_on_one_worst_diff
    for diff in differences:
        output_bit_size = avalanche_results["test_results"][input][intermediate_output][criterion][
            "output_bit_size"]
        nb_occ = len(avalanche_results[
                         "test_results"][input][intermediate_output][criterion]["differences"][diff]["output_vectors"])
        code.append("\t\\begin{table}[h!]")
        code.append("\t\t\\begin{center}")
        code.append("\t\t\t\\scalebox{0.34}{")

        criteria_values = {'avalanche_entropy_vectors': 'E', 'avalanche_weight_vectors': 'W'}
        step_value = criteria_values.get(criterion, 'D')

        code.append("\t\t\t\\begin{tabular}{c | *{" + f'{step}' + "}{" + f"{step_value}" + "}}")
        code.append("\t\t\t\t&\\multicolumn{" + f"{step}" + "}{c}{state bit position}\\\\")
        code.append("\t\t\t\t\\hline")
        add_multicolumns_to_graph(avalanche_results, code, criterion, diff, input, intermediate_output, modulo, nb_occ,
                                  output_bit_size, step)
        code.append("\t\t\t\\end{tabular}}")
        code.append("\t\t\\end{center}")
        tmp_criterion = " ".join(criterion.split("_"))
        tmp_intermediate_output = " ".join(intermediate_output.split("_"))
        tmp_input = " ".join(input.split("_"))
        if diff != -1:
            code.append(
                "\t\t\\caption{" + f'{tmp_criterion} - difference injected in position {diff} of {tmp_input} - {tmp_intermediate_output} analyzed' + "}")
        else:
            code.append(
                "\t\t\\caption{" + f'{tmp_criterion} - average values - differences injected in {tmp_input} - {tmp_intermediate_output} analyzed' + "}")
        code.append("\t\\end{table}")
        code.append("\n")


def add_multicolumns_to_graph(avalanche_results, code, criterion, diff, input, intermediate_output, modulo, nb_occ,
                              output_bit_size, step):
    for i in range(0, output_bit_size, step):
        tmp = ['&\\multicolumn{1}{c}{}' if n % modulo != 0
               else '& \\multicolumn{1}{c}{' + f'{n}' + '}' for n in range(i, i + step)]
        tmp = ["\t\t\t\\\\[0.5em]\\multicolumn{1}{c|}{rounds}"] + tmp + ["\\\\[0.5em]"]
        code.append(" ".join(tmp))
        float_format = "&{:0.2f}"
        for occ in range(nb_occ):
            vector = avalanche_results[
                "test_results"][input][intermediate_output][criterion]["differences"][
                diff]["output_vectors"][occ]["vector"]
            round_index = avalanche_results[
                "test_results"][input][intermediate_output][criterion]["differences"][
                diff]["output_vectors"][occ]["round"]
            s = [float_format.format(float(n)) if n != float
                 else float_format.format(n) for n in vector[i:i + step]]
            s = [f"{round_index + 1}"] + s
            code.append(" ".join(s) + "\\\\")
        vector = avalanche_results[
            "test_results"][input]["cipher_output"][criterion]["differences"][
            diff]["output_vectors"][0]["vector"]
        s = [float_format.format(float(n)) if n != float
             else float_format.format(n) for n in vector[i:i + step]]
        s = [f"{round_index + 2}"] + s
        code.append(" ".join(s) + "\\\\")

