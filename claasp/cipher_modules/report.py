import itertools
import json
import os
import shutil
from datetime import datetime
from math import ceil

import pandas as pd
import plotly.graph_objects as go
from plotly import express as px
from plotly.subplots import make_subplots

from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
from claasp.cipher_modules.statistical_tests.dieharder_statistical_tests import DieharderTests
from claasp.cipher_modules.statistical_tests.nist_statistical_tests import NISTStatisticalTests


def _print_colored_state(state, verbose, file):
    for line in state:
        print('', end='', file=file)
        for x in line:
            print(f'{x} ', end='', file=file)

        occ = [i for i in range(len(line)) if line[i] != '_' and line[i] != '*' and line[i] != '0']
        if verbose:
            print(f'\tactive words positions = {occ}', file=file)
        else:
            print('', end='  ', file=file)


def _dict_to_latex_table(data_dict, header_list):
    if not data_dict:
        return "Empty dictionary."

    # Check if the values are dictionaries or lists
    is_nested = isinstance(next(iter(data_dict.values())), dict)

    num_columns = len(header_list)
    latex_code = "\\begin{longtable}{|" + "c|" * (num_columns) + "}\n"
    latex_code += "\\hline\n"

    for i in range(len(header_list)):
        if i == len(header_list) - 1:
            latex_code += header_list[i] + " "
        else:
            latex_code += header_list[i] + " & "

    latex_code += "\\\\\n"
    latex_code += "\\hline\n"

    # Determine the maximum number of rows needed
    max_rows = max(len(values) for values in data_dict.values()) if not is_nested else 1

    for row_index in range(max_rows):
        row_values = []

        for key, values in data_dict.items():
            if is_nested:
                # For nested dictionary
                row_values.append(str(values.get(header_list[row_index], "")))
            else:
                # For regular dictionary with lists as values
                if row_index < len(values):
                    row_values.append(str(values[row_index]))
                else:
                    row_values.append("")

        row = " & ".join(row_values) + " \\\\\n"
        latex_code += row
        latex_code += "\\hline\n"

    latex_code += "\\end{longtable}"
    return latex_code


def _latex_heatmap(table, table_string, bit_count):
    table_string += "\\hspace*{-4cm}\n\\begin{tikzpicture}[scale=1.1]\n\t\\foreach \\y [count=\\n] in {\n\t\t"
    for round in table:
        table_string += "{"
        for i in range(len(round)):
            if i == len(round) - 1:
                table_string += f"{float(round[i]):.3f}"
            else:
                table_string += f"{float(round[i]):.3f},"
        table_string += "},\n\t\t"
    table_string += ("} {\n\t%heatmap tiles\n\t\\foreach\\x [count=\\m] in \\y {\n\t\t\\pgfmathsetmacro{"
                     "\\colorgradient}{\\x * 100}\n\t\t\\node[fill=green!\\colorgradient!red, minimum size=6mm, "
                     "text=white] at (\\m,-\\n*0.6) {\\x};\n\t}\n\t}\n\t\t%rowlabels\n\\foreach \\a [count=\\i] in {")
    for i in range(len(table)):
        if i != len(table) - 1:
            table_string += "round" + str(i + 1) + ","
        else:
            table_string += "round" + str(i + 1) + "} {\n\t"

    table_string += "\\node[minimum size=6mm] at (0,-\\i*0.6) {\\a};}\n\t\t%column labels\n\t \\foreach \\a [count=\\i] in {"
    for i in range(bit_count[0], bit_count[1]):
        if i != bit_count[1] - 1:
            table_string += "bit" + str(i) + ","
        else:
            table_string += "bit" + str(i) + "} {\n\t"
    table_string += "\\node[minimum size=6mm] at (\\i,0) {\\a};}\n\\end{tikzpicture}\\newline\\newline\n"
    return table_string


class Report:

    def __init__(self, test_report):
        """
                Construct an instance of the Report class.

                This class is used to store reports of trail search functions and statistical tests.

                INPUT:

                - ``cipher`` -- **cipher**; the cipher object on which the test was performed
                - ``test_report`` -- **dict**: the output of the test function

                EXAMPLES::

                sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
                sage: from claasp.cipher_modules.models.utils import set_fixed_variables
                sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
                sage: from claasp.cipher_modules.report import Report
                sage: speck = SpeckBlockCipher(number_of_rounds=5)
                sage: sat = SatXorDifferentialModel(speck)
                sage: plaintext = set_fixed_variables(
                ....:         component_id='plaintext',
                ....:         constraint_type='not_equal',
                ....:         bit_positions=range(32),
                ....:         bit_values=(0,)*32)
                sage: key = set_fixed_variables(
                ....:         component_id='key',
                ....:         constraint_type='equal',
                ....:         bit_positions=range(64),
                ....:         bit_values=(0,)*64)
                sage: trail = sat.find_lowest_weight_xor_differential_trail(fixed_values=[plaintext, key])
                sage: report = Report(trail)

        """

        try:
            self.cipher = test_report['input_parameters']['cipher']
        except KeyError:
            self.cipher = test_report['cipher']
        self.test_report = test_report

        if 'test_name' in test_report.keys():
            self.test_name = test_report['test_name']

        try:
            self.input_parameters = test_report['input_parameters']
            self.test_name = test_report['input_parameters']['test_name']

        except KeyError:
            self.input_parameters = {}
            self.test_name = test_report['test_name'] if type(test_report) is dict else test_report[0]['test_name']

    def show(self, show_as_hex=False, test_name=None, fixed_input='plaintext', fixed_output='round_output',
             fixed_input_difference='average', word_size=1, state_size=1, key_state_size=1,
             verbose=False, show_word_permutation=False,
             show_var_shift=False, show_var_rotate=False, show_theta_xoodoo=False,
             show_theta_keccak=False, show_shift_rows=False, show_sigma=False, show_reverse=False,
             show_permuation=False, show_multi_input_non_linear_logical_operator=False,
             show_modular=False, show_modsub=False,
             show_constant=False, show_rot=False, show_sbox=False, show_mix_column=False,
             show_shift=False, show_linear_layer=False, show_xor=False, show_modadd=False,
             show_and=False,
             show_or=False, show_not=False, show_plaintext=True, show_key=True,
             show_intermediate_output=True, show_cipher_output=True, show_input=True, show_output=True,
             show_graph=True):

        if 'trail' in self.test_name:
            if show_as_hex == True and (word_size / 4).is_integer() == False:
                print("Incorrect word_size: if show_as_hex=True, word_size has to be a multiple of 4")
                return
            self._print_trail(show_as_hex, word_size, state_size, key_state_size, verbose, show_word_permutation,
                              show_var_shift, show_var_rotate, show_theta_xoodoo,
                              show_theta_keccak, show_shift_rows, show_sigma, show_reverse,
                              show_permuation, show_multi_input_non_linear_logical_operator,
                              show_modular, show_modsub,
                              show_constant, show_rot, show_sbox, show_mix_column,
                              show_shift, show_linear_layer, show_xor, show_modadd,
                              show_and,
                              show_or, show_not, show_plaintext, show_key,
                              show_intermediate_output, show_cipher_output, show_input, show_output, save_fig=False)
            return
        elif 'component_analysis' in self.test_name:
            Component_Analysis = CipherComponentsAnalysis(self.cipher)
            Component_Analysis.print_component_analysis_as_radar_charts(results=self.test_report['test_results'])
            return
        elif 'avalanche_tests' == self.test_name:
            test_list = list(self.test_report['test_results']['plaintext']['round_output'].keys())
            print(test_list)
            if test_name not in test_list:
                print(test_name)
                print('Error! Invalid test name. The report.show function requires a test_name input')
                print('test_name has to be one of the following : ', end='')
                print(test_list)
                return
            input_diff_values = [x['input_difference_value'] for x in
                                 self.test_report['test_results']['plaintext']['round_output'][test_name] if
                                 'input_difference_value' in x.keys()]
            if fixed_input_difference not in input_diff_values:
                print(
                    'Error! Invalid input difference value. The report.show() function requires a fixed_input_difference input')
                print('input_difference_value has to be one of the following :', end='')
                print(input_diff_values)
                return
        elif 'neural_network_differential_distinguisher' in self.test_name:
            input_diff_values = [x['input_difference_value'] for x in
                                 self.test_report['test_results']['plaintext']['round_output'][
                                     'neural_network_differential_distinguisher']]
            if fixed_input_difference not in input_diff_values:
                print(
                    'Error! Invalid input difference value. The report.show() function requires a fixed_input_difference input')
                print('The input difference value has to be one of the following :', end='')
                print(input_diff_values)
                return
        self._produce_graph(show_graph=show_graph, fixed_input=fixed_input, fixed_output=fixed_output,
                            fixed_input_difference=fixed_input_difference, test_name=test_name)

    def _export(self, file_format, output_dir, fixed_input=None, fixed_output=None, fixed_test=None):

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        if not os.path.exists(output_dir + '/' + self.cipher.id):
            os.makedirs(output_dir + '/' + self.cipher.id)

        if 'statistical' in self.test_name:

            if file_format == '.csv':
                df = pd.DataFrame.from_dict(self.test_report['test_results'])
                df.to_csv(output_dir + '/' + self.cipher.id + '/' + self.test_name + file_format)

            if file_format == '.json':
                with open(output_dir + '/' + self.cipher.id + '/' + self.test_name + file_format, 'w') as fp:
                    json.dump(self.test_report['test_results'], fp, default=lambda x: float(x))

            if file_format == '.tex':
                with open(output_dir + '/' + self.cipher.id + '/' + self.test_name + file_format, 'w') as fp:
                    fp.write(pd.DataFrame(self.test_report['test_results']).style.to_latex())

        elif 'component_analysis' in self.test_name:
            print('This method is not implemented yet for the component analysis test.')
            return
        elif 'trail' in self.test_name or 'algebraic' in self.test_name:

            if 'trail' in self.test_name:
                if not os.path.exists(output_dir + '/' + self.cipher.id + '/trail_search_results'):
                    os.makedirs(output_dir + '/' + self.cipher.id + '/trail_search_results')

                path = output_dir + '/' + self.cipher.id + '/trail_search_results'

            else:
                path = output_dir + '/' + self.cipher.id + '/' + self.test_name
                if not os.path.exists(path):
                    os.makedirs(path)

            if file_format == '.csv':

                df = pd.DataFrame.from_dict(
                    self.test_report["components_values" if 'trail' in self.test_name else "test_results"])
                df.to_csv(path + '/' + self.test_name + file_format)

            elif file_format == '.json':
                with open(path + '/' + self.test_name + file_format, 'w') as fp:
                    json.dump(self.test_report["components_values" if 'trail' in self.test_name else "test_results"],
                              fp, default=lambda x: float(x))
            elif file_format == '.tex':

                if 'algebraic' in self.test_name:
                    with open(path + '/' + self.test_name + '.tex', "w") as f:
                        f.write(_dict_to_latex_table(self.test_report["test_results"],
                                                     header_list=["number of variables", "number of equations",
                                                                  "number of monomials", "max degree of equation",
                                                                  "test passed"]).replace('_', '\\_'))
                else:
                    headers = ["Component_id", "Value", "Weight"]
                    with open(path + '/' + self.test_name + '.tex', "w") as f:
                        f.write(
                            _dict_to_latex_table(self.test_report["components_values"], header_list=headers).replace(
                                '_', '\\_'))

        else:

            if not os.path.exists(output_dir + '/' + self.cipher.id):
                os.makedirs(output_dir + '/' + self.cipher.id)

            for it in self.test_report["test_results"].keys() if fixed_input == None else [fixed_input]:
                if not os.path.exists(output_dir + '/' + self.cipher.id + '/' + self.test_report["input_parameters"][
                    "test_name"] + '_tables/' + it):
                    os.makedirs(output_dir + '/' + self.cipher.id + '/' + self.test_report["input_parameters"][
                        "test_name"] + '_tables/' + it)

                for out in self.test_report["test_results"][it].keys() if fixed_output == None else [fixed_output]:
                    if not os.path.exists(
                            output_dir + '/' + self.cipher.id + '/' + self.test_report["input_parameters"][
                                "test_name"] + '_tables/' + it + '/' + out):
                        os.makedirs(output_dir + '/' + self.cipher.id + '/' + self.test_report["input_parameters"][
                            "test_name"] + '_tables/' + it + '/' + out)

                    for test in self.test_report["test_results"][it][out].keys() if fixed_test == None else [
                        fixed_test]:
                        if not os.path.exists(
                                output_dir + '/' + self.cipher.id + '/' + self.test_report["input_parameters"][
                                    "test_name"] + '_tables/' + it + '/' + out + '/' + test):
                            os.makedirs(output_dir + '/' + self.cipher.id + '/' + self.test_report["input_parameters"][
                                "test_name"] + '_tables/' + it + '/' + out + '/' + test)

                        for result in self.test_report["test_results"][it][out][test]:
                            path = output_dir + '/' + self.cipher.id + '/' + self.test_report["input_parameters"][
                                "test_name"] + '_tables/' + it + '/' + out + '/' + test

                            try:
                                res_key = [x for x in result.keys() if x in ['values', 'vectors', 'accuracies']][0]
                            except IndexError:
                                continue

                            if file_format == '.csv':

                                elastic_dict = {}
                                rounds = []
                                if isinstance(result[res_key][0], list):
                                    for i in range(len(result[res_key])):
                                        rounds += ['round' + str(i)] * len(result[res_key][0])

                                    bits = ['bit' + str(i) for i in range(len(result[res_key][0]))]
                                    bits *= len(result[res_key])
                                    elastic_dict["Bits"] = bits
                                    elastic_dict["value"] = []
                                    for round_num in result[res_key]:
                                        for bit_value in round_num:
                                            elastic_dict["value"].append(bit_value)

                                    diff = str(result["input_difference_value"])

                                else:

                                    rounds = ['rounds' + str(i) for i in range(len(result[res_key]))]
                                    elastic_dict["value"] = result[res_key]
                                    diff = test
                                elastic_dict["Rounds"] = rounds
                                df = pd.DataFrame(elastic_dict)

                                df.to_csv(path + '/' + diff + file_format)

                            elif file_format == '.json':
                                elastic_dict = {}
                                rounds = []
                                if isinstance(result[res_key][0], list):
                                    for i in range(len(result[res_key])):
                                        rounds += ['round' + str(i)] * len(result[res_key][0])

                                    bits = ['bit' + str(i) for i in range(len(result[res_key][0]))]
                                    bits *= len(result[res_key])
                                    elastic_dict["Bits"] = bits
                                    elastic_dict["value"] = []
                                    for round_num in result[res_key]:
                                        for bit_value in round_num:
                                            elastic_dict["value"].append(bit_value)

                                    diff = str(result["input_difference_value"])

                                else:

                                    rounds = ['rounds' + str(i) for i in range(len(result[res_key]))]
                                    elastic_dict["value"] = result[res_key]
                                    diff = test
                                elastic_dict["Rounds"] = rounds

                                with open(path + '/' + diff + file_format, 'w') as fp:
                                    json.dump(elastic_dict, fp, default=lambda x: float(x))

                            elif file_format == '.tex':
                                if not isinstance(result[res_key][0], list):
                                    with open(path + '/' + self.test_name + '.tex', "w") as f:
                                        f.write(_dict_to_latex_table(dict(pd.DataFrame(result)),
                                                                     header_list=[res_key, "component_id"]).replace('_',
                                                                                                                    '\\_'))

                                else:
                                    table = result[res_key]
                                    table_count = ceil(len(table[0]) / 16)
                                    table_string = "\\begin{figure}[h]\n"
                                    for i in range(table_count):
                                        table_split = [bits[i * 16:(i + 1) * 16] for bits in table]
                                        bit_count = (i * 16, (i + 1) * 16)
                                        table_string = _latex_heatmap(table_split, table_string, bit_count)

                                    table_string += "\\caption{" + self.test_name.replace("_",
                                                                                          "-'") + "-" + it + "-" + out.replace(
                                        "_", "-") + "-" + test.replace("_", "-") + "-" + result[
                                                        "input_difference_value"] + ("}"
                                                                                     "\\label{fig:" + self.test_name.replace(
                                        "_", "-") + "-" + it + "-" + out.replace("_",
                                                                                 "-") + "-" + test.replace(
                                        "_",
                                        "-") + "-" +
                                                                                     result[
                                                                                         "input_difference_value"] + "}\n")
                                    table_string += "\\end{figure}"
                                    with open(path + '/' + str(result["input_difference_value"]) + file_format,
                                              'w') as fp:
                                        fp.write(table_string)

        print("Report saved in " + output_dir + '/' + self.cipher.id)

    def save_as_DataFrame(self, output_dir=os.getcwd() + '/test_reports', fixed_input=None, fixed_output=None,
                          fixed_test=None):
        self._export(file_format='.csv', output_dir=output_dir, fixed_input=fixed_input, fixed_output=fixed_output,
                     fixed_test=fixed_test)

    def save_as_latex_table(self, output_dir=os.getcwd() + '/test_reports', fixed_input=None, fixed_output=None,
                            fixed_test=None):
        self._export(file_format='.tex', output_dir=output_dir, fixed_input=fixed_input, fixed_output=fixed_output,
                     fixed_test=fixed_test)

    def save_as_json(self, output_dir=os.getcwd() + '/test_reports', fixed_input=None, fixed_output=None,
                     fixed_test=None):
        self._export(file_format='.json', output_dir=output_dir, fixed_input=fixed_input, fixed_output=fixed_output,
                     fixed_test=fixed_test)

    def _get_component_types(self):
        component_types = []
        show_key_flow = False
        for comp in list(self.test_report['components_values'].keys()):
            if 'key' == comp:
                show_key_flow = True
            if ('key' in comp or comp == 'plaintext') and comp not in component_types:
                if 'key' in comp and comp != 'key':
                    continue
                else:
                    component_types.append(comp)
            elif '_'.join(comp.split('_')[:-2]) not in component_types and comp[-2:] != "_i" and comp[-2:] != "_o":
                component_types.append('_'.join(comp.split('_')[:-2]))
            elif ('_'.join(comp.split('_')[:-3])) + '_' + ('_'.join(comp.split('_')[-1])) not in component_types and (
                    comp[-2:] == "_i" or comp[-2:] == "_o"):
                component_types.append(('_'.join(comp.split('_')[:-3])) + '_' + ('_'.join(comp.split('_')[-1])))

        return component_types, show_key_flow

    def _get_show_components(self, component_types, show_output, show_input, show_key, input_comps, var_choices):

        show_components = {}
        for comp, comp_choice in itertools.product(component_types, input_comps):
            if 'show_' + comp == comp_choice:
                show_components[comp] = var_choices[comp_choice]
            elif 'show_' + comp == comp_choice + '_o' and show_output:
                show_components[comp] = var_choices[comp_choice]
            elif 'show_' + comp == comp_choice + '_i' and show_input:
                show_components[comp] = var_choices[comp_choice]

        return show_components

    def _update_out_list(self, out_list, rel_prob, abs_prob, show_as_hex, comp_id, word_size, state_size,
                         key_state_size, key_flow, word_denominator):

        value = self.test_report['components_values'][comp_id]['value']
        truncated_symbol = '*' if '*' in value else '?' if '?' in value else 'None'
        if value[:2] == '0x':
            bin_list = list(format(int(value, 16), 'b').zfill(4 * len(value[2:])))
        elif value[:2] == '0b':
            bin_list = list(value[2:])
        elif self.test_report['solver_name'] == 'CADICAL_EXT':
            if truncated_symbol in value:
                bin_list = list(value)
            else:
                bin_list = list(format(int(value, 16), 'b').zfill(4 * len(value)))
        else:
            bin_list = list(value)

        if show_as_hex == False:
            word_list = [truncated_symbol if truncated_symbol in ''.join(
                bin_list[x:x + word_size]) else word_denominator if ''.join(
                bin_list[x:x + word_size]).count('1') > 0 else '_' for x in
                         range(0, len(bin_list), word_size)]
        else:
            word_list = [
                truncated_symbol if truncated_symbol in ''.join(bin_list[x:x + word_size]) else hex(
                    int(''.join(bin_list[x:x + word_size]), 2))[
                                                                                                2:].zfill(
                    int(word_size / 4)) for x
                in range(0, len(bin_list), word_size)]

        if ('intermediate' in comp_id or 'cipher' in comp_id) and comp_id not in key_flow:
            size = (state_size, len(word_list) // state_size)

        elif ('intermediate' in comp_id or 'cipher' in comp_id) and comp_id in key_flow and comp_id != 'key':
            size = (key_state_size, len(word_list) // key_state_size)

        else:
            size = (1, len(word_list))
        out_format = [[] for _ in range(size[0])]
        for i, j in itertools.product(range(size[0]), range(size[1])):
            if show_as_hex == False:
                if word_list[j + i * size[1]] == word_denominator:
                    out_format[i].append(f'\033[31;4m{word_list[j + i * size[1]]}\033[0m')
                else:
                    out_format[i].append(word_list[j + i * size[1]])
            else:
                if word_list[j + i * size[1]] == '0':
                    out_format[i].append(word_list[j + i * size[1]])
                else:
                    out_format[i].append(f'\033[31;4m{word_list[j + i * size[1]]}\033[0m')

        out_list[comp_id] = (out_format, rel_prob, abs_prob) if comp_id not in ["plaintext", "key"] else (
            out_format, 0, 0)

    def _get_comp_value_and_key_flow(self, comp_id, key_flow):

        if comp_id[-2:] == "_i" or comp_id[-2:] == "_o":
            input_links = self.cipher.get_component_from_id(comp_id[:-2]).input_id_links
            comp_value = ('_'.join(comp_id.split('_')[:-3])) + '_' + ('_'.join(comp_id.split('_')[-1]))
        else:
            input_links = self.cipher.get_component_from_id(comp_id).input_id_links
            comp_value = '_'.join(comp_id.split('_')[:-2])

        if (all(
                id_link in key_flow or 'constant' in id_link or id_link + '_o' in key_flow or id_link + '_i' in key_flow
                for id_link in input_links) or ('key' in comp_id and comp_id != 'key')):
            key_flow.append(comp_id)
            if 'linear' in self.test_name and 'differential' not in self.test_name:
                constants_i = [constant_id + '_i' for constant_id in input_links if 'constant' in constant_id]
                constants_o = [constant_id + '_o' for constant_id in input_links if 'constant' in constant_id]
                key_flow += constants_i + constants_o
            else:
                constants = [constant_id for constant_id in input_links if 'constant' in constant_id]
                key_flow += constants
        return comp_value, key_flow

    def _get_show_key_flow(self, key_flow, word_size, word_denominator):
        show_key_flow = False
        for key_comp in key_flow:
            key_value = self.test_report['components_values'][key_comp]['value']
            bin_list = list(format(int(key_value, 16), 'b').zfill(
                4 * len(key_value) if key_value[:2] != '0x' else 4 * len(
                    key_value[2:]))) if '*' not in key_value else list(
                key_value[2:])
            word_list = ['*' if '*' in ''.join(bin_list[x:x + word_size]) else word_denominator if ''.join(
                bin_list[x:x + word_size]).count('1') > 0 else '_' for x in
                         range(0, len(bin_list), word_size)]

            if word_list.count(word_denominator) > 0:
                show_key_flow = True
                break
        return show_key_flow

    def _print_plaintext_flow(self, out_list, key_flow, verbose, file, save_fig):
        for comp_id in [comp for comp in out_list.keys() if comp not in key_flow]:
            if comp_id == 'plaintext':
                if verbose == True:
                    print(f'{comp_id}\t', file=file)
                    _print_colored_state(out_list[comp_id][0], verbose, file)
                else:
                    _print_colored_state(out_list[comp_id][0], verbose, file)
                    print(f' {comp_id}\t', file=file)
            else:
                if verbose:
                    print(
                        f'{comp_id}        Input Links : {self.cipher.get_component_from_id(comp_id if comp_id[-2:] not in ["_i", "_o"] else comp_id[:-2]).input_id_links}',
                        file=file if save_fig else None)
                    _print_colored_state(out_list[comp_id][0], verbose, file)
                else:
                    _print_colored_state(out_list[comp_id][0], verbose, file)
                    print(f' {comp_id}', file=file)
            if verbose:
                print('local weight = ' + str(
                    out_list[comp_id][1]) + '\t' + 'total weight = ' + str(
                    out_list[comp_id][2]), file=file)
            print('', file=file)
        print('', file=file)
        print('total weight = ' + str(self.test_report['total_weight']), file=file)

    def _print_key_flow(self, key_flow, show_components, out_list, verbose, file):

        print('', file=file)
        print("KEY FLOW", file=file)
        print('', file=file)

        for comp_id in key_flow:
            if comp_id[-2:] == "_i" or comp_id[-2:] == "_o":
                comp_value = ('_'.join(comp_id.split('_')[:-3])) + '_' + ('_'.join(comp_id.split('_')[-1]))
            else:
                comp_value = '_'.join(comp_id.split('_')[:-2])
            if show_components[
                comp_value if (comp_id not in ['plaintext', 'cipher_output', 'cipher_output_o', 'cipher_output_i',
                                               'intermediate_output', 'intermediate_output_o',
                                               'intermediate_output_i'] and 'key' not in comp_id) else comp_id]:
                if 'key' in comp_id:
                    _print_colored_state(out_list[comp_id][0], verbose, file)
                    print(f'\t{comp_id}\t', file=file)
                else:
                    if verbose:
                        print(
                            f'{comp_id}       Input Links : {self.cipher.get_component_from_id(comp_id if comp_id[-2:] not in ["_i", "_o"] else comp_id[:-2]).input_id_links}',
                            file=file)
                        _print_colored_state(out_list[comp_id][0], verbose, file)
                    else:
                        _print_colored_state(out_list[comp_id][0], verbose, file)
                        print(f'{comp_id}\t', file=file)
                if verbose: print('local weight = ' + str(
                    out_list[comp_id][1]) + '\t' + 'total weight = ' + str(
                    out_list[comp_id][2]), file=file)
                print('', file=file)

    def _print_trail(self, show_as_hex, word_size, state_size, key_state_size, verbose, show_word_permutation,
                     show_var_shift, show_var_rotate, show_theta_xoodoo,
                     show_theta_keccak, show_shift_rows, show_sigma, show_reverse,
                     show_permuation, show_multi_input_non_linear_logical_operator,
                     show_modular, show_modsub,
                     show_constant, show_rot, show_sbox, show_mix_column,
                     show_shift, show_linear_layer, show_xor, show_modadd,
                     show_and,
                     show_or, show_not, show_plaintext, show_key,
                     show_intermediate_output, show_cipher_output, show_input, show_output, save_fig):

        if save_fig == True:
            if not os.path.exists(os.getcwd() + '/test_reports/'):
                os.makedirs(os.getcwd() + '/test_reports/')
            if not os.path.exists(os.getcwd() + '/test_reports/' + self.cipher.id):
                os.makedirs(os.getcwd() + '/test_reports/' + self.cipher.id)
            filename = os.getcwd() + '/test_reports/' + self.cipher.id + '/' + self.test_report[
                'solver_name'] + '_' + self.test_name + '.txt'
            if os.path.exists(filename):
                os.remove(filename)
            file = open(filename, 'a')
        else:
            file = None

        input_comps = list(locals().keys())

        component_types, show_key_flow = self._get_component_types()
        show_components = self._get_show_components(component_types, show_output, show_input, show_key, input_comps,
                                                    locals())

        out_list = {}

        key_flow = [key for key in self.cipher.inputs if key == 'key']

        abs_prob = 0
        rel_prob = 0
        word_denominator = '1' if word_size == 1 else 'A'

        for comp_id in self.test_report['components_values'].keys():
            if 'key' in comp_id and comp_id != 'key':
                continue
            if (comp_id != "plaintext" and comp_id != "key") and "key" not in comp_id:
                rel_prob = self.test_report['components_values'][comp_id]['weight']
                abs_prob += rel_prob

            # Check input links
            if comp_id != 'plaintext' and 'key' not in comp_id:
                comp_value, key_flow = self._get_comp_value_and_key_flow(comp_id, key_flow)

            if show_components[
                comp_value if (comp_id not in ['plaintext', 'cipher_output', 'cipher_output_o', 'cipher_output_i',
                                               'intermediate_output', 'intermediate_output_o',
                                               'intermediate_output_i'] and 'key' not in comp_id) else comp_id]:
                self._update_out_list(out_list, rel_prob, abs_prob, show_as_hex, comp_id, word_size, state_size,
                                      key_state_size, key_flow, word_denominator)

        self._print_plaintext_flow(out_list, key_flow, verbose, file, save_fig)

        show_key_flow = self._get_show_key_flow(key_flow, word_size, word_denominator)

        if show_key_flow:
            self._print_key_flow(key_flow, show_components, out_list, verbose, file)

    def create_heatmap_subplot(self, i, graph_data, cipher_rounds):
        z_data = [x[32 * i: min(len(x), 32 * (i + 1))] for x in list(graph_data.values())]
        yrange = list(graph_data.keys())
        xrange = list(range(i * 32, 32 * (i + 1)))
        fontsize = max(1, ceil(12 // len(yrange)))
        heatmap = go.Heatmap(
            z=z_data, coloraxis='coloraxis', texttemplate="%{text}",
            text=[['{:.2f}'.format(float(y)) for y in x] for x in z_data],
            textfont={'size': 2 * fontsize},
            x=xrange,
            y=yrange, zmin=0, zmax=1, zauto=False
        )

        layout_update = {
            f'xaxis{i + 1}': {
                'tickmode': 'array',
                'tickvals': xrange,
                'ticktext': [str(j) for j in range(i * 32, 32 * (i + 1))],
                'tickfont': {'size': 2 * fontsize}
            },
            f'yaxis{i + 1}': {
                'tickmode': 'array',
                'tickvals': yrange,
                'ticktext': [str(j) for j in range(1, cipher_rounds + 1)],
                'tickfont': {'size': 2 * fontsize},
                'autorange': 'reversed'
            }
        }
        return heatmap, layout_update

    def _produce_graph(self, output_directory=os.getcwd(), show_graph=False, fixed_input=None, fixed_output=None,
                       fixed_input_difference=None, test_name=None):

        if self.test_name == 'neural_distinguisher_test':
            df_scores = pd.DataFrame(
                self.test_report['test_results']['plaintext']['cipher_output']['differences_scores'],
                index=['scores']).T
            nr = self.test_report['test_results']['round_start']
            df_result = pd.DataFrame(
                self.test_report['test_results']['plaintext']['cipher_output']['neural_distinguisher_test'][0][
                    'accuracies'], index=['accuracy_round' + str(i) for i in range(nr, nr + len(
                    self.test_report['test_results']['plaintext']['cipher_output']['neural_distinguisher_test'][0][
                        'accuracies']))])

            if show_graph:
                print()
                print()
                print()
                print('RESULTS')
                print('plaintext_input_diff : ' + str(
                    self.test_report['test_results']['plaintext']['cipher_output']['neural_distinguisher_test'][0][
                        'plaintext_diff']))
                print('key_input_diff : ' + str(
                    self.test_report['test_results']['plaintext']['cipher_output']['neural_distinguisher_test'][0][
                        'key_diff']))
                print(df_result)
                print()
                print('//////')
                print()
                print('SCORES')
                print(df_scores)

            else:
                df_result.to_csv(output_directory + '/neural_distinguisher_test_results.csv')
                df_scores.to_csv(output_directory + '/neural_distinguisher_test_scores.csv')

        elif 'statistical' in self.test_name:
            if 'dieharder' in self.test_name:
                for dict in self.test_report['test_results']:
                    DieharderTests._generate_chart_round(dict,
                                                         output_directory,
                                                         show_graph=show_graph)
                DieharderTests._generate_chart_all(self.test_report['test_results'],
                                                   output_directory,
                                                   show_graph=show_graph)

            elif 'nist' in self.test_name:
                for dict in self.test_report['test_results']:
                    NISTStatisticalTests._generate_chart_round(dict,
                                                               output_directory,
                                                               show_graph=show_graph)
                NISTStatisticalTests._generate_chart_all(self.test_report['test_results'],
                                                         output_directory,
                                                         show_graph=show_graph)

        elif 'algebraic' in self.test_name:

            y = list(self.test_report['test_results'].keys())
            num_rounds = len(self.test_report['test_results']['number_of_equations'])
            x = [i + 1 for i in range(num_rounds)]
            z = [[1] * num_rounds] * len(self.test_report['test_results'].keys())
            z_text = []
            for test in self.test_report['test_results'].keys():
                z_text.append([str(x) for x in self.test_report['test_results'][test]])
            fig = px.imshow(z, x=x, y=y, color_continuous_scale='Viridis', aspect="auto")
            fig.update_traces(text=z_text, texttemplate="%{text}")
            fig.update(layout_coloraxis_showscale=False)
            fig.update_xaxes(side="top")

            if show_graph == False:
                print('saving image')
                fig.write_image(output_directory + '/test_results.png')
                print('image saved')
            if show_graph:
                fig.show(renderer='png')
                return
        else:

            inputs = list(self.test_report['test_results'].keys())
            for it in inputs if fixed_input == None else [fixed_input]:
                if not os.path.exists(
                        output_directory + '/' + it) and show_graph == False:
                    os.mkdir(output_directory + '/' + it)
                outputs = list(self.test_report['test_results'][it].keys())
                for out in outputs if fixed_input == None else [fixed_output]:
                    if out == 'cipher_output':
                        continue
                    if not os.path.exists(
                            output_directory + '/' + it + '/' + out) and show_graph == False:
                        os.mkdir(
                            output_directory + '/' + it + '/' + out)

                    results = list(self.test_report['test_results'][it][out].keys())

                    for res in results if test_name == None else [test_name]:
                        if not os.path.exists(
                                output_directory + '/' + it + '/' + out + '/' + res) and show_graph == False:
                            os.mkdir(
                                output_directory + '/' + it + '/' + out + '/' + res)

                        ### Make Graphs

                        data = self.test_report['test_results'][it][out][res]

                        for case in list(data):

                            try:
                                res_key = [x for x in case.keys() if x in ['values', 'vectors', 'accuracies']][0]
                            except IndexError:
                                continue
                            if out == 'round_output':
                                output_res = self.test_report['test_results'][it]['cipher_output'][res]
                                if 'worst_input_differences' in output_res[-1].keys():
                                    output_res = output_res[:-1]
                                if "input_difference_value" in case.keys():
                                    diff_key = case["input_difference_value"]
                                    output = [out for out in output_res if out["input_difference_value"] == diff_key][0]
                                    cipher_output = output[res_key][0]
                                else:
                                    cipher_output = output_res[0][res_key][0]

                                case[res_key].append(cipher_output)

                            graph_data = {}
                            for i in range(len(case[res_key])):
                                graph_data[i + 1] = [case[res_key][i]] if type(case[res_key][i]) != list else \
                                    case[res_key][i]

                            df = pd.DataFrame.from_dict(graph_data).T
                            if len(graph_data[1]) > 1:
                                if case[
                                    'input_difference_value'] != fixed_input_difference and fixed_input_difference != None:
                                    continue
                                num_subplots = int(ceil(len(graph_data[1]) / 32))
                                fig = make_subplots(num_subplots, 1)

                                fig.update_layout({
                                    'coloraxis': {'colorscale': 'rdylgn',
                                                  'cmin': 0,
                                                  'cmax': 1}})
                                for i in range(num_subplots):
                                    heatmap, layout_update = self.create_heatmap_subplot(i,
                                                                                         graph_data,
                                                                                         self.cipher.number_of_rounds)
                                    fig.add_trace(heatmap, i + 1, 1)
                                    fig.update_layout(layout_update)

                                if not show_graph:

                                    fig.write_image(
                                        f"{output_directory}/{it}/{out}/{res}/{res}_{case['input_difference_value']}.png",
                                        scale=1)
                                else:
                                    fig.show(renderer='png')
                                    return
                                fig.data = []
                                fig.layout = {}

                            else:
                                fig = px.line(df, range_x=[1, self.cipher.number_of_rounds],
                                              range_y=[0, 1])
                                fig.update_layout(xaxis_title="round", yaxis_title=res_key,
                                                  showlegend=False)

                                if show_graph == False:
                                    fig.write_image(output_directory + '/' + it + '/' + out + '/' + res +
                                                    '/' + str(res) + '.png',
                                                    scale=1)
                                else:
                                    fig.show(renderer='png')
                                    return
                                fig.data = []
                                fig.layout = {}

    def save_as_image(self, show_as_hex=False, test_name=None, fixed_input=None, fixed_output=None,
                      fixed_input_difference=None, word_size=1, state_size=1, key_state_size=1,
                      output_directory=os.getcwd() + '/test_reports',
                      verbose=False, show_word_permutation=False,
                      show_var_shift=False, show_var_rotate=False, show_theta_xoodoo=False,
                      show_theta_keccak=False, show_shift_rows=False, show_sigma=False, show_reverse=False,
                      show_permuation=False, show_multi_input_non_linear_logical_operator=False,
                      show_modular=False, show_modsub=False,
                      show_constant=False, show_rot=False, show_sbox=False, show_mix_column=False,
                      show_shift=False, show_linear_layer=False, show_xor=False, show_modadd=False,
                      show_and=False,
                      show_or=False, show_not=False, show_plaintext=True, show_key=True,
                      show_intermediate_output=True, show_cipher_output=True, show_input=True, show_output=True):

        """
            Prints the graphical representation of the Report.

            INPUT:

            ``word_size`` -- **integer**: the word_size to be used for the trail representation
            ``state_size``  -- **integer**: the state_size to be used for the trail representation
            ``key_state_size`` -- **integer**: the key_state_size to be used for the trail representation
            ``output_directory`` -- **string**: the directory in which to store the reports
            ``verbose`` -- **bool**: determines wether to print out a verbose output or not
            ``show_*`` -- **bool**: boolean value to determine wether to display each specific component when visualizing a trail

            EXAMPLES:

                sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
                sage: from claasp.cipher_modules.avalanche_tests import AvalancheTests
                sage: from claasp.cipher_modules.report import Report
                sage: speck = SpeckBlockCipher(number_of_rounds=5)
                sage: avalanche_test_results = AvalancheTests(speck).avalanche_tests()
                sage: report = Report(avalanche_test_results)
                sage: report.save_as_image(test_name='avalanche_weight_vectors', fixed_input='plaintext', fixed_output='round_output', fixed_input_difference='average') # random

        """
        time = '_date:' + 'time:'.join(str(datetime.now()).split(' '))
        test_directory = output_directory
        if 'component_analysis' in self.test_name:
            print('This method is not implemented yet for the component analysis test')
            return
        elif 'trail' in self.test_name:
            self._print_trail(show_as_hex, word_size, state_size, key_state_size, verbose, show_word_permutation,
                              show_var_shift, show_var_rotate, show_theta_xoodoo,
                              show_theta_keccak, show_shift_rows, show_sigma, show_reverse,
                              show_permuation, show_multi_input_non_linear_logical_operator,
                              show_modular, show_modsub,
                              show_constant, show_rot, show_sbox, show_mix_column,
                              show_shift, show_linear_layer, show_xor, show_modadd,
                              show_and,
                              show_or, show_not, show_plaintext, show_key,
                              show_intermediate_output, show_cipher_output, show_input, show_output, save_fig=True)
        else:
            if not os.path.exists(output_directory):
                os.mkdir(output_directory)

            if not os.path.exists(output_directory + '/' + self.cipher.id + time):
                os.mkdir(output_directory + '/' + self.cipher.id + time)

            if not os.path.exists(output_directory + '/' + self.cipher.id + time + '/' + self.test_name):
                os.mkdir(output_directory + '/' + self.cipher.id + time + '/' + self.test_name)

            test_directory = output_directory + '/' + self.cipher.id + time + '/' + self.test_name
            self._produce_graph(output_directory=test_directory, test_name=test_name, fixed_output=fixed_output,
                                fixed_input_difference=fixed_input_difference, fixed_input=fixed_input)
        print('Report saved in ' + test_directory)

    def clean_reports(self, output_dir=os.getcwd() + '/test_reports'):

        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)
        else:
            print("Directory " + output_dir + " not found")
            return
