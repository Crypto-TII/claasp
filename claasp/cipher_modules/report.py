import os
from math import ceil
from plotly.subplots import make_subplots
from plotly import express as px
import plotly.graph_objects as go
import pandas as pd
import json
import shutil


def _print_colored_state(state, verbose):
    for line in state:
        print('', end='')
        for x in line:
            print(f'{x} ', end='')

        occ = [i for i in range(len(line)) if line[i] != '_']
        if verbose:
            print(f'\tactive words positions = {occ}')
        else:
            print()


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
                table_string += str("{:.3f}".format(round[i]))
            else:
                table_string += str("{:.3f}".format(round[i])) + ","
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

    def __init__(self, cipher, test_report):
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
                sage: report = Report(speck, trail)

        """


        self.cipher = cipher
        self.test_report = test_report

        if 'test_name' in test_report.keys():
            self.test_name = test_report['test_name']

        try:
            self.input_parameters = test_report['input_parameters']
            self.test_name = test_report['input_parameters']['test_name']

        except KeyError:
            self.input_parameters = {}
            self.test_name = test_report['test_name'] if type(test_report) is dict else test_report[0]['test_name']

    def _export(self, file_format, output_dir):


        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        if not os.path.exists(output_dir + '/' + self.cipher.id):
            os.makedirs(output_dir + '/' + self.cipher.id)

        if 'statistical' in self.test_name:

            if file_format == '.csv':
                df = pd.DataFrame.from_dict(self.test_report["randomness_test"])
                df.to_csv(output_dir + '/' + self.cipher.id + '/' + self.test_name + file_format)

            if file_format == '.json':
                with open(output_dir + '/' + self.cipher.id + '/' + self.test_name + file_format, 'w') as fp:
                    json.dump(self.test_report["randomness_test"], fp, default=lambda x: float(x))

            if file_format == '.tex':
                with open(output_dir + '/' + self.cipher.id + '/' + self.test_name + file_format, 'w') as fp:
                    fp.write(pd.DataFrame(self.test_report["randomness_test"]).style.to_latex())

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

                df = pd.DataFrame.from_dict(self.test_report["components_values" if 'trail' in self.test_name else "test_results"])
                df.to_csv(path + '/' + self.test_name + file_format)

            elif file_format == '.json':
                with open(path + '/' + self.test_name + file_format, 'w') as fp:
                    json.dump(self.test_report["components_values" if 'trail' in self.test_name else "test_results"], fp, default=lambda x: float(x))
            elif file_format == '.tex':

                if 'algebraic' in self.test_name:
                    with open(path + '/' + self.test_name + '.tex', "w") as f:
                        f.write(_dict_to_latex_table(self.test_report["test_results"], header_list=["number of variables", "number of equations", "number of monomials", "max degree of equation", "test passed"]).replace('_','\\_'))
                else:
                    headers = ["Component_id", "Value", "Weight"]
                    with open(path + '/' + self.test_name + '.tex', "w") as f:
                        f.write(_dict_to_latex_table(self.test_report["components_values"], header_list=headers).replace('_','\\_'))

        else:

            if not os.path.exists(output_dir + '/' + self.cipher.id):
                os.makedirs(output_dir + '/' + self.cipher.id)

            for it in self.test_report["test_results"].keys():
                if not os.path.exists(output_dir + '/' + self.cipher.id + '/' + self.test_report["input_parameters"][
                    "test_name"] + '_tables/' + it):
                    os.makedirs(output_dir + '/' + self.cipher.id + '/' + self.test_report["input_parameters"][
                        "test_name"] + '_tables/' + it)

                for out in self.test_report["test_results"][it].keys():

                    if not os.path.exists(
                            output_dir + '/' + self.cipher.id + '/' + self.test_report["input_parameters"][
                                "test_name"] + '_tables/' + it + '/' + out):
                        os.makedirs(output_dir + '/' + self.cipher.id + '/' + self.test_report["input_parameters"][
                            "test_name"] + '_tables/' + it + '/' + out)

                    for test in self.test_report["test_results"][it][out].keys():

                        if not os.path.exists(
                                output_dir + '/' + self.cipher.id + '/' + self.test_report["input_parameters"][
                                    "test_name"] + '_tables/' + it + '/' + out + '/' + test):
                            os.makedirs(output_dir + '/' + self.cipher.id + '/' + self.test_report["input_parameters"][
                                "test_name"] + '_tables/' + it + '/' + out + '/' + test)

                        for result in self.test_report["test_results"][it][out][test]:
                            path = output_dir + '/' + self.cipher.id + '/' + self.test_report["input_parameters"][
                                "test_name"] + '_tables/' + it + '/' + out + '/' + test

                            res_key = [x for x in result.keys() if x in ['values', 'vectors', 'accuracies']][0]

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
                                        f.write(_dict_to_latex_table(dict(pd.DataFrame(result)),header_list=[res_key,"component_id"]).replace('_','\\_'))

                                else:
                                    table = result[res_key]
                                    table_count = ceil(len(table[0]) / 16)
                                    table_string = "\\begin{figure}[h]\n"
                                    for i in range(table_count):
                                        table_split = [bits[i * 16:(i + 1) * 16] for bits in table]
                                        bit_count = (i * 16, (i + 1) * 16)
                                        table_string = _latex_heatmap(table_split, table_string, bit_count)

                                    table_string += "\\caption{" + self.test_name.replace("_",
                                                                                         "\\_") + "\\_" + it + "\\_" + out.replace(
                                        "_", "\\_") + "\\_" + test.replace("_", "\\_") + "\\_" + result[
                                                        "input_difference_value"] + ("}"
                                                                                     "\\label{fig:" + self.test_name.replace(
                                        "_", "\\_") + "\\_" + it + "\\_" + out.replace("_", "\\_") + "\\_" + test.replace("_",
                                                                                                                     "\\_") + "\\_" +
                                                                                     result[
                                                                                         "input_difference_value"] + "}\n")
                                    table_string += "\\end{figure}"
                                    with open(path + '/' + str(result["input_difference_value"]) + file_format, 'w') as fp:
                                        fp.write(table_string)

        print("Report saved in " + output_dir + '/' + self.cipher.id)

    def save_as_DataFrame(self, output_dir=os.getcwd() + '/test_reports'):
        self._export(file_format='.csv', output_dir=output_dir)

    def save_as_latex_table(self, output_dir=os.getcwd() + '/test_reports'):
        self._export(file_format='.tex', output_dir=output_dir)

    def save_as_json(self, output_dir=os.getcwd() + '/test_reports'):
        self._export(file_format='.json', output_dir=output_dir)

    def _print_trail(self, word_size, state_size, key_state_size, verbose, show_word_permutation,
                     show_var_shift, show_var_rotate, show_theta_xoodoo,
                     show_theta_keccak, show_shift_rows, show_sigma, show_reverse,
                     show_permuation, show_multi_input_non_linear_logical_operator,
                     show_modular, show_modsub,
                     show_constant, show_rot, show_sbox, show_mix_column,
                     show_shift, show_linear_layer, show_xor, show_modadd,
                     show_and,
                     show_or, show_not, show_plaintext, show_key,
                     show_intermediate_output, show_cipher_output):

        input_comps = list(locals().keys())
        component_types = []

        for comp in list(self.test_report['components_values'].keys()):
            if (comp == 'key' or comp == 'plaintext') and comp not in component_types:
                component_types.append(comp)
            elif '_'.join(comp.split('_')[:-2]) not in component_types:
                component_types.append('_'.join(comp.split('_')[:-2]))

        show_components = {}

        for comp in component_types:
            for comp_choice in input_comps:
                if 'show_' + comp == comp_choice:
                    show_components[comp] = locals()[comp_choice]

        out_list = {}

        key_flow = ['key']

        abs_prob = 0

        word_denominator = '1' if word_size == 1 else 'A'

        for comp_id in self.test_report['components_values'].keys():

            if comp_id != "plaintext" and comp_id != "key":
                rel_prob = self.test_report['components_values'][comp_id]['weight']
                abs_prob += rel_prob

            # Check input links

            if 'plaintext' not in comp_id and 'key' not in comp_id:
                input_links = self.cipher.get_component_from_id(comp_id).input_id_links

                if all((id_link in key_flow or 'constant' in id_link) for id_link in input_links):
                    key_flow.append(comp_id)
                    key_flow = key_flow + [constant_id for constant_id in input_links if 'constant' in constant_id]

            if show_components['_'.join(comp_id.split('_')[:-2]) if comp_id not in ['plaintext', 'key', 'cipher_output',
                                                                                    'intermediate_output'] else comp_id]:

                value = self.test_report['components_values'][comp_id]['value']

                bin_list = list(format(int(value, 16), 'b').zfill(4 * len(value)))

                word_list = [word_denominator if ''.join(bin_list[x:x + word_size]).count('1') > 0 else '_' for x in
                             range(0, len(bin_list), word_size)]

                if ('intermediate' in comp_id or 'cipher' in comp_id) and comp_id not in key_flow:
                    size = (state_size, len(word_list) // state_size)

                elif ('intermediate' in comp_id or 'cipher' in comp_id) and comp_id in key_flow and comp_id != 'key':
                    size = (key_state_size, len(word_list) // key_state_size)

                else:
                    size = (1, len(word_list))
                out_format = [[] for _ in range(size[0])]
                for i in range(size[0]):
                    for j in range(size[1]):
                        if word_list[j + i * size[1]] == word_denominator:
                            out_format[i].append(f'\033[31;4m{word_list[j + i * size[1]]}\033[0m')
                        else:
                            out_format[i].append(word_list[j + i * size[1]])

                out_list[comp_id] = (out_format, rel_prob, abs_prob) if comp_id not in ["plaintext", "key"] else (out_format, 0, 0)

        for comp_id in out_list.keys():
            if comp_id not in key_flow:
                if comp_id == 'plaintext' or comp_id == 'key':
                    print(f'\t{comp_id}\t')
                else:
                    if verbose:
                        print(
                            f' \t{comp_id}        Input Links : {self.cipher.get_component_from_id(comp_id).input_id_links}')
                    else:
                        print(f' \t{comp_id}\t')
                _print_colored_state(out_list[comp_id][0], verbose)
                if verbose: print('  ' * len(out_list[comp_id][0][0]) + '\tlocal weight = ' + str(
                    out_list[comp_id][1]) + '\t' + 'total weight = ' + str(
                    out_list[comp_id][2]))
                print()
        print()
        print("KEY FLOW")
        print()

        for comp_id in key_flow:

            if show_components['_'.join(comp_id.split('_')[:-2]) if comp_id not in ['plaintext', 'key', 'cipher_output',
                                                                                    'intermediate_output'] else comp_id]:
                if comp_id == 'plaintext' or comp_id == 'key':
                    print(f'\t{comp_id}\t')
                else:
                    if verbose:
                        print(
                            f' \t{comp_id}       Input Links : {self.cipher.get_component_from_id(comp_id).input_id_links}')
                    else:
                        print(f' \t{comp_id}\t')
                _print_colored_state(out_list[comp_id][0], verbose)
                if verbose: print('  ' * len(out_list[comp_id][0][0]) + '\tlocal weight = ' + str(
                    out_list[comp_id][1]) + '\t' + 'total weight = ' + str(
                    out_list[comp_id][2]))
                print()

    def _produce_graph(self, output_directory):

        if 'statistical' in self.test_name:
            printable_dict = self.test_report
            printable_dict['data_type'] = 'random'
            printable_dict['cipher_name'] = self.cipher.family_name
            printable_dict['round'] = 1
            printable_dict['rounds'] = 1
            if 'dieharder' in self.test_name:
                from claasp.cipher_modules.statistical_tests.dieharder_statistical_tests import DieharderTests
                DieharderTests.generate_chart_round(printable_dict)
            elif 'nist' in self.test_name:
                from claasp.cipher_modules.statistical_tests.nist_statistical_tests import StatisticalTests
                StatisticalTests.generate_chart_round(printable_dict)

        elif 'algebraic' in self.test_name:
            print(self.test_report)
        else:

            inputs = list(self.test_report['test_results'].keys())
            for it in inputs:
                if not os.path.exists(
                        output_directory + '/' + self.cipher.id + '/' + self.test_name + '/' + it):
                    os.mkdir(output_directory + '/' + self.cipher.id + '/' + self.test_name + '/' + it)
                outputs = list(self.test_report['test_results'][it].keys())
                for out in outputs:
                    if out == 'cipher_output':
                        continue
                    if not os.path.exists(
                            output_directory + '/' + self.cipher.id + '/' + self.test_name + '/' + it + '/' + out):
                        os.mkdir(
                            output_directory + '/' + self.cipher.id + '/' + self.test_name + '/' + it + '/' + out)

                    results = list(self.test_report['test_results'][it][out].keys())

                    for res in results:
                        if not os.path.exists(output_directory + '/' +
                                              self.cipher.id + '/' + self.test_name + '/' + it + '/' + out + '/' + res):
                            os.mkdir(
                                output_directory + '/' + self.cipher.id + '/' + self.test_name + '/' + it + '/' + out + '/' + res)

                        ### Make Graphs

                        data = self.test_report['test_results'][it][out][res]

                        for case in list(data):
                            res_key = [x for x in case.keys() if x in ['values', 'vectors', 'accuracies']][0]

                            if out == 'round_output':
                                output_res = self.test_report['test_results'][it]['cipher_output'][res]
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
                                num_subplots = int(ceil(len(graph_data[1]) / 32))
                                fig = make_subplots(num_subplots, 1, vertical_spacing=0.08)
                                fig.update_layout({
                                    'coloraxis': {'colorscale': 'rdylgn',
                                                  'cmin': 0,
                                                  'cmax': 1}})
                                for i in range(num_subplots):
                                    z_data = [x[32 * i: min(len(x), 32 * (i + 1))] for x in list(graph_data.values())]
                                    fig.add_trace(go.Heatmap(z=z_data, coloraxis='coloraxis', texttemplate="%{text}",
                                                             text=[['{:.3f}'.format(float(y)) for y in x] for x in
                                                                   z_data],
                                                             x=list(range(i * 32, 32 * (i + 1))),
                                                             y=list(range(1,self.cipher.number_of_rounds+1)), zmin=0,
                                                             zmax=1, zauto=False),
                                                  i + 1, 1)
                                    fig.update_layout({
                                        'font': {'size': 8},
                                        'xaxis' + str(i + 1): {'tick0': 0, 'dtick': 1, 'nticks': len(z_data),
                                                               'tickfont': {'size': 8}},
                                        'yaxis' + str(i + 1): {'tick0': 0, 'dtick': 1,
                                                               'tickfont': {'size': 8}, 'autorange': 'reversed'}
                                    })
                                fig.write_image(output_directory + '/' +
                                                self.cipher.id + '/' + self.test_name + '/' + it + '/' + out + '/' + res + '/' + str(
                                    res) + '_' + str(case['input_difference_value']) + '.png', scale=4)
                                fig.data = []
                                fig.layout = {}

                            else:

                                fig = px.line(df, range_x=[1, self.cipher.number_of_rounds],
                                              range_y=[min(df[0]) - 1, max(df[0]) + 1])
                                fig.update_layout(xaxis_title="round", yaxis_title=res_key,
                                                  showlegend=False)
                                fig.write_image(output_directory + '/' +
                                                self.cipher.id + '/' + self.test_name + '/' + it + '/' + out + '/' + res +
                                                '/' + str(res) + '.png',
                                                scale=4)

                                fig.data = []
                                fig.layout = {}

        print("Results saved in " + output_directory)

    def print_report(self, word_size=1, state_size=1, key_state_size=1, output_directory=os.getcwd() + '/test_reports',
                     verbose=False, show_word_permutation=False,
                     show_var_shift=False, show_var_rotate=False, show_theta_xoodoo=False,
                     show_theta_keccak=False, show_shift_rows=False, show_sigma=False, show_reverse=False,
                     show_permuation=False, show_multi_input_non_linear_logical_operator=False,
                     show_modular=False, show_modsub=False,
                     show_constant=False, show_rot=False, show_sbox=False, show_mix_column=False,
                     show_shift=False, show_linear_layer=False, show_xor=False, show_modadd=False,
                     show_and=False,
                     show_or=False, show_not=False, show_plaintext=True, show_key=True,
                     show_intermediate_output=True, show_cipher_output=True):

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
                sage: from claasp.cipher_modules.report import Report
                sage: speck = SpeckBlockCipher(number_of_rounds=5)
                sage: avalanche_test_results = speck.diffusion_tests()
                sage: report = Report(speck, avalanche_test_results)
                sage: report.print_report()

        """


        if 'trail' in self.test_name:
            self._print_trail(word_size, state_size, key_state_size, verbose, show_word_permutation,
                              show_var_shift, show_var_rotate, show_theta_xoodoo,
                              show_theta_keccak, show_shift_rows, show_sigma, show_reverse,
                              show_permuation, show_multi_input_non_linear_logical_operator,
                              show_modular, show_modsub,
                              show_constant, show_rot, show_sbox, show_mix_column,
                              show_shift, show_linear_layer, show_xor, show_modadd,
                              show_and,
                              show_or, show_not, show_plaintext, show_key,
                              show_intermediate_output, show_cipher_output)
        else:
            if not os.path.exists(output_directory):
                os.mkdir(output_directory)

            if not os.path.exists(output_directory + '/' + self.cipher.id):
                os.mkdir(output_directory + '/' + self.cipher.id)

            if not os.path.exists(output_directory + '/' + self.cipher.id + '/' + self.test_name):
                os.mkdir(output_directory + '/' + self.cipher.id + '/' + self.test_name)
            self._produce_graph(output_directory)

    def clean_reports(self, output_dir=os.getcwd() + '/test_reports/reports'):

        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)
        else:
            print("Directory " + output_dir + " not found")
            return

