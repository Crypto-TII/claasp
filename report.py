
import os
from math import ceil
import numpy as np
from plotly.subplots import make_subplots
from plotly import express as px
import plotly.graph_objects as go
import pandas as pd
import matplotlib.pyplot as plt

class Report:

    def __init__(self,cipher, test_name, test_report):

        ########
        ########

        self.cipher = cipher
        self.test_report = test_report
        self.test_name = test_name

        try:
            self.input_parameters = test_report['input_parameters']
            self.test_results = test_report['test_results']

        except KeyError:
            self.input_parameters = {}
            self.test_results = test_report


    def print_colored_state(self, state):
        for line in state:
            print('', end='')
            for x in line:
                print(f'{x} ', end='')

            occ = [i for i in range(len(line)) if line[i] != '_']
            print(f'\tactive words positions = {occ}')
    def print_trail(self):

        component_types = []

        for comp in list(self.test_results['components_values'].keys()):
            if comp.split('_')[0] not in component_types + ['intermediate', 'cipher']:
                component_types.append(comp.split('_')[0])

        if self.cipher._type == 'hash_function':
            plaintext_value = self.test_results['components_values'][('key')]['value']
            block_size = self.cipher.inputs_bit_size[self.cipher._inputs.index('key')]

        else:
            plaintext_value = self.test_results['components_values'][('plaintext')]['value']
            block_size = self.cipher.inputs_bit_size[self.cipher._inputs.index('plaintext')]

        comp_choice = {'intermediate': 1, 'cipher': 1}

        for C in component_types:
            choice = input("do you want to visualize " + C + " components? (y/n)\n\n")
            while choice not in ['y', 'n']:
                choice = input("Error. Only answer using y (yes) or n (no)")
            comp_choice[C] = 1 if choice == 'y' else 0

        out_list = {}

        key_flow = ['key']

        abs_prob = 0

        word_size = int(input("Choose a word size for the cipher\n"))
        while self.cipher.output_bit_size % word_size != 0:
            word_size = int(input('Choose a valid word_size\n\n'))

        state_size = int(input("Choose a state size for the cipher\n"))
        while (self.cipher.output_bit_size // word_size) % state_size != 0:
            state_size = int(input('Choose a valid state_size\n\n'))

        word_denominator = '1' if word_size == 1 else 'A'

        for comp_id in self.test_results['components_values'].keys():

            rel_prob = self.test_results['components_values'][comp_id]['weight']
            abs_prob += rel_prob

            # Check input links

            if 'plaintext' not in comp_id and 'key' not in comp_id:
                input_links = self.cipher.get_component_from_id(comp_id).input_id_links

                if all((id_link in key_flow or 'constant' in id_link) for id_link in input_links):
                    key_flow.append(comp_id)
                    key_flow = key_flow + [constant_id for constant_id in input_links if 'constant' in constant_id]

            if comp_choice[comp_id.split('_')[0]]:

                value = self.test_results['components_values'][comp_id]['value']

                bin_list = list(format(int(value, 16), 'b').zfill(4 * len(value)))

                word_list = [word_denominator if ''.join(bin_list[x:x + word_size]).count('1') > 0 else '_' for x in
                             range(0, len(bin_list), word_size)]

                if 'intermediate' in comp_id or 'cipher' in comp_id:
                    size = (state_size, len(word_list) // state_size)
                else:
                    size = (1, len(word_list))

                out_format = [[] for _ in range(size[0])]

                for i in range(size[0]):
                    for j in range(size[1]):
                        if word_list[j + i * size[1]] == word_denominator:
                            out_format[i].append(f'\033[31;4m{word_list[j + i * size[1]]}\033[0m')
                        else:
                            out_format[i].append(word_list[j + i * size[1]])
                out_list[comp_id] = (out_format, rel_prob, abs_prob)

        ##Check KeyFlow

        for comp_id in out_list.keys():
            if comp_id not in key_flow:
                if comp_id == 'plaintext' or comp_id == 'key':
                    print(f' \t{comp_id}')
                else:
                    print(f' \t{comp_id}\tInput Links : {self.cipher.get_component_from_id(comp_id).input_id_links}')
                self.print_colored_state(out_list[comp_id][0])
                print('\t local weight = ' + str(out_list[comp_id][1]) + '\t' + 'total weight = ' + str(
                    out_list[comp_id][2]))
            print()

        print()
        print("KEY FLOW")
        print()

        for comp_id in key_flow:

            if comp_choice[comp_id.split('_')[0]]:
                if comp_id == 'plaintext' or comp_id == 'key':
                    print(f' \t{comp_id}')
                else:
                    print(f' \t{comp_id}\tInput Links : {self.cipher.get_component_from_id(comp_id).input_id_links}')
                self.print_colored_state(out_list[comp_id][0])
                print(' \tlocal weight = ' + str(out_list[comp_id][1]) + '\t' + 'total weight = ' + str(
                    out_list[comp_id][2]))
            print()
    def produce_graph(self):
        inputs = list(self.test_results.keys())

        for it in inputs:
            if not os.path.exists(self.cipher.id + "_results/" + self.test_name + '/' + it):
                os.mkdir(self.cipher.id + "_results/" + self.test_name + '/' + it)
            outputs = list(self.test_results[it].keys())
            for out in outputs:
                if out == 'cipher_output':
                    continue
                if not os.path.exists(self.cipher.id + "_results/" + self.test_name + '/' + it + '/' + out):
                    os.mkdir(self.cipher.id + "_results/" + self.test_name + '/' + it + '/' + out)

                results = list(self.test_results[it][out].keys())

                for res in results:
                    if not os.path.exists(self.cipher.id + "_results/" + self.test_name + '/' + it + '/' + out + '/' + res):
                        os.mkdir(self.cipher.id + "_results/" + self.test_name + '/' + it + '/' + out + '/' + res)

                    ### Make Graphs

                    data = self.test_results[it][out][res]

                    for case in list(data):
                        res_key = [x for x in case.keys() if x in ['values', 'vectors', 'accuracies']][0]

                        graph_data = {}
                        for i in range(len(case[res_key])):
                            graph_data[i + 1] = [case[res_key][i]] if type(case[res_key][i]) != list else case[res_key][
                                i]

                        df = pd.DataFrame.from_dict(graph_data).T

                        if len(graph_data[1]) > 1:
                            num_subplots = int(ceil(self.cipher.output_bit_size / 32))
                            fig = make_subplots(num_subplots, 1, vertical_spacing=0.08)
                            for i in range(num_subplots):
                                z_data = [x[32 * i: min(len(x), 32 * (i + 1))] for x in list(graph_data.values())]
                                fig.add_trace(go.Heatmap(z=z_data, coloraxis='coloraxis', texttemplate="%{text}",
                                                         text=[[str(round(y, 3)) for y in x] for x in z_data], xgap=3,
                                                         ygap=3, zmin=0, zmid=0.5, zmax=1), i + 1, 1)
                                fig.update_layout({
                                    'xaxis' + str(i + 1): {'nticks': 33, 'tickfont': {'size': 8}},
                                    'yaxis' + str(i + 1): {'nticks': 1 + len(list(graph_data)), 'tickfont': {'size': 8}}
                                })
                            fig.update_coloraxes(colorscale='rdylgn')
                            fig.write_image(
                                self.cipher.id + "_results/" + self.test_name + '/' + it + '/' + out + '/' + res + '/' + str(
                                    res) + '_' + str(case['input_difference_value']) + '.png', scale=4)
                            fig.data = []
                            fig.layout = {}

                        else:

                            fig = px.line(df, range_x=[1, self.cipher.number_of_rounds],
                                          range_y=[min(df[0]) - 1, max(df[0]) + 1])
                            fig.update_layout(xaxis_title="number_of_rounds", yaxis_title="test_result")
                            fig.write_image(self.cipher.id + "_results/" + self.test_name + '/' + it + '/' + out + '/' + res +
                                            '/' + str(res) + '.png',
                                            scale=4)

                            fig.data = []
                            fig.layout = {}


    def analyze_report(self):

        if not os.path.exists(os.getcwd()+'/Graph_Results'):
            os.mkdir(os.getcwd()+'/Graph_Results')

        if not os.path.exists(os.getcwd()+'/Graph_Results/' + self.cipher.id):
            os.mkdir(os.getcwd()+'/Graph_Results/' + self.cipher.id)

        if not os.path.exists(os.getcwd()+'/Graph_Results/' + self.cipher.id + '/' + self.test_name):
            os.mkdir(os.getcwd()+'/Graph_Results/' + self.cipher.id + '/' + self.test_name)

        try:
            self.print_trail()
        except KeyError:
            self.produce_graph()

