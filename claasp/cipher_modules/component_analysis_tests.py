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

from sage.crypto.sbox import SBox
from sage.matrix.special import identity_matrix
from sage.matrix.constructor import matrix, Matrix
from sage.rings.polynomial.pbori.pbori import BooleanPolynomialRing
from sage.rings.finite_rings.finite_field_constructor import FiniteField as GF
from sage.rings.polynomial.polynomial_ring_constructor import PolynomialRing

from claasp.component import linear_layer_to_binary_matrix
from claasp.cipher_modules.generic_functions import (SHIFT, ROTATE, mix_column_generalized)
from claasp.name_mappings import (SBOX, LINEAR_LAYER, MIX_COLUMN, WORD_OPERATION, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT,
                                  CONSTANT)

import matplotlib.pyplot as plt
from math import pi, log2


class CipherComponentsAnalysis:
    def __init__(self, cipher):
        self._cipher = cipher

    def component_analysis_tests(self):
        """
        Return a list of properties for all the operation used in a cipher

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: components_analysis = CipherComponentsAnalysis(fancy).component_analysis_tests()
            sage: len(components_analysis)
            9

        """
        all_variables_names = []
        for cipher_round in self._cipher.rounds_as_list:
            for component in cipher_round.components:
                for id_link, bit_positions in zip(component.input_id_links, component.input_bit_positions):
                    all_variables_names.extend([f'{id_link}_{i}' for i in bit_positions])
        all_variables_names = list(set(all_variables_names))
        boolean_polynomial_ring = BooleanPolynomialRing(len(all_variables_names), all_variables_names)

        cipher_operations = self.get_all_operations()
        components_analysis = []
        if "concatenate" in cipher_operations:
            cipher_operations.pop("concatenate")
        for op in cipher_operations:
            for same_op_different_param in cipher_operations[op]:
                result = self._select_properties_function(boolean_polynomial_ring, same_op_different_param)
                if result != {}:
                    components_analysis.append(result)

        output_dictionary = {
            'input_parameters': {
                'test_name': 'component_analysis'
            },
            'test_results': components_analysis
        }
        return output_dictionary

    def get_all_operations(self):
        """
        Return a dictionary for which the keys are all the operations that are used in the cipher.

        The attributes are a list containing:
          - a component with the operation under study;
          - number of occurrences of the operation;
          - list of ids of all the components with the same underlying operation.

        INPUT:

        - ``cipher`` -- **Cipher object**; a cipher instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: cipher_operations = CipherComponentsAnalysis(fancy).get_all_operations()
            sage: list(cipher_operations.keys())
            ['sbox', 'linear_layer', 'XOR', 'AND', 'MODADD', 'ROTATE', 'SHIFT']

        """
        tmp_cipher_operations = {}
        for component in self._cipher.get_all_components():
            self._collect_component_operations(component, tmp_cipher_operations)

        for operation in list(tmp_cipher_operations.keys()):
            if operation not in [LINEAR_LAYER, MIX_COLUMN, 'fsr']:
                tmp_cipher_operations[operation]["distinguisher"] = \
                    list(set(tmp_cipher_operations[operation]["distinguisher"]))
            if operation == 'fsr':
                tmp_list = []
                for item in tmp_cipher_operations[operation]["distinguisher"]:
                    if item not in tmp_list:
                        tmp_list.append(item)
                tmp_cipher_operations[operation]["distinguisher"] = tmp_list
            tmp_cipher_operations[operation]["types"] = \
                [[] for _ in range(len(tmp_cipher_operations[operation]["distinguisher"]))]
            self._collect_components_with_the_same_operation(operation, tmp_cipher_operations)
        cipher_operations = {}
        for operation in list(tmp_cipher_operations.keys()):
            self._add_attributes_to_operation(cipher_operations, operation, tmp_cipher_operations)
        return cipher_operations

    def print_component_analysis_as_radar_charts(self, results=None):
        """
        Return a graph that can be plot to visualize the properties of all the operations of a cipher in a spider graph

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: CipherComponentsAnalysis(fancy).print_component_analysis_as_radar_charts()

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=3)
            sage: from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
            sage: CipherComponentsAnalysis(speck).print_component_analysis_as_radar_charts()

        """
        if results==None:
            results = self.component_analysis_tests()['test_results']
        SMALL_SIZE = 10
        MEDIUM_SIZE = 11
        BIG_SIZE = 12

        plt.rc('font', size=BIG_SIZE)  # controls default text sizes
        plt.rc('axes', titlesize=SMALL_SIZE)  # fontsize of the axes title
        plt.rc('axes', labelsize=MEDIUM_SIZE)  # fontsize of the x and y labels
        plt.rc('xtick', labelsize=SMALL_SIZE)  # fontsize of the tick labels
        plt.rc('ytick', labelsize=SMALL_SIZE)  # fontsize of the tick labels
        plt.rc('legend', fontsize=BIG_SIZE)  # legend fontsize
        plt.rc('figure', titlesize=BIG_SIZE)  # fontsize of the figure title
        plt.rcParams['figure.figsize'] = [20, 20]

        # remove XOR from results
        results_without_xor = [results[i] for i in range(len(results)) if results[i]["description"][0] != "XOR"]
        results = self._remove_components_with_strings_as_values(results_without_xor)

        nb_plots = len(results)
        col = 2
        row = nb_plots // col
        if nb_plots % col != 0:
            row += nb_plots % col
        positions = {8: -0.7, 3: -0.4}

        for plot_number in range(nb_plots):
            categories = list(results[plot_number]["properties"].keys())
            values = self._plot_first_line_of_data_frame(categories, plot_number, results)
            values += values[:1]  # necessary to fill the area

            # What will be the angle of each axis in the plot? (we divide the plot / number of variable)
            N = len(categories)
            angles = [n / float(N) * 2 * pi for n in range(N)]
            angles += angles[:1]

            ax = plt.subplot(row, col, plot_number + 1, polar=True)
            self._initialise_spider_plot(plot_number, results)

            # Draw one axe per variable + add labels
            plt.xticks(angles[:-1], categories, color='grey', size=8)

            # Draw ylabels
            ax.set_rlabel_position(30)
            # Log version:
            # plt.yticks(list(range(max_value)), [str(i) for i in range(max_value)], color="grey", size=7)
            # plt.ylim(0, max_value)
            # Uniform version:
            plt.yticks([0, 1], ["0", "1"], color="grey", size=8)
            plt.ylim(0, 1)

            # Position of labels
            for label, rot in zip(ax.get_xticklabels(), angles):
                if 90 < (rot * 180. / pi) < 270:
                    label.set_rotation(rot * 180. / pi)
                    label.set_horizontalalignment("right")
                    label.set_rotation_mode("anchor")
                elif int(rot * 180. / pi) == 90 or int(rot * 180. / pi) == 270:
                    label.set_rotation(rot * 180. / pi)
                    label.set_horizontalalignment("center")
                    label.set_rotation_mode("anchor")
                else:
                    label.set_rotation(rot * 180. / pi)
                    label.set_horizontalalignment("left")
                    label.set_rotation_mode("anchor")

            # Plot data
            ax.plot(angles, values, linewidth=1, linestyle='solid')

            # Fill area
            ax.fill(angles, values, 'b', alpha=0.1)
            self._fill_area(ax, categories, plot_number, positions, results)

        # Show the graph
        plt.subplots_adjust(left=0.25, bottom=0.1, right=0.7, top=0.95, wspace=0, hspace=0.96)
        plt.show()
        #print("The radar chart can be plot with the build-in method plt.show()")

        #return plt


    def _AND_as_boolean_function(self, component, boolean_polynomial_ring):
        """
        Return a list of boolean polynomials corresponding to the output bits of a AND component.

        INPUT:

        - ``component`` -- **Component object**; a component from the cipher
        - ``boolean_polynomial_ring`` -- **Boolean Polynomial Ring object**; a boolean polynomial ring

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: and_component = fancy.get_component_from_id('and_0_8')
            sage: boolean_polynomial_ring = CipherComponentsAnalysis(fancy)._generate_boolean_polynomial_ring_from_cipher()
            sage: boolean_polynomials = CipherComponentsAnalysis(fancy)._AND_as_boolean_function(and_component, boolean_polynomial_ring)
            sage: len(boolean_polynomials)
            12

        """
        number_of_inputs = len(component.input_id_links)
        number_of_blocks = component.description[1]
        output_bit_size = component.output_bit_size
        variables_names = []
        variables_names_positions = {}
        for input_number in range(number_of_inputs):
            tmp = [component.input_id_links[input_number] + "_" + str(bit_position)
                   for bit_position in component.input_bit_positions[input_number]]
            variables_names += tmp
            if component.input_id_links[input_number] not in variables_names_positions:
                variables_names_positions[component.input_id_links[input_number]] = \
                    [tmp, component.input_bit_positions[input_number]]
            else:  # Keys are unique in a python dico, so need to handle 2 same entries in input_id_link !
                variables_names_positions[component.input_id_links[input_number]] = \
                    [variables_names_positions[component.input_id_links[input_number]][0] + tmp,
                     variables_names_positions[component.input_id_links[input_number]][1] +
                     component.input_bit_positions[input_number]]

        component_as_bf = []
        for input_number in range(output_bit_size):
            tmp = 1
            for block_number in range(number_of_blocks):
                tmp *= boolean_polynomial_ring(variables_names[input_number + output_bit_size * block_number])
            component_as_bf.append(tmp)

        return component_as_bf

    def _select_boolean_function(self, component, boolean_polynomial_ring):
        if component.description[0] == "XOR":
            return self._XOR_as_boolean_function(component, boolean_polynomial_ring)
        elif component.description[0] == "AND":
            return self._AND_as_boolean_function(component, boolean_polynomial_ring)
        elif component.description[0] == "MODADD":
            return self._MODADD_as_boolean_function(component, boolean_polynomial_ring)
        else:
            return "TODO(...)"


    def _MODADD_as_boolean_function(self, component, boolean_polynomial_ring):
        """
        Return a list of boolean polynomials corresponding to the output bits of a MODADD component.

        INPUT:

        - ``component`` -- **Component object**; a component from the cipher
        - ``boolean_polynomial_ring`` -- **Boolean Polynomial Ring object**; a boolean polynomial ring

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: modadd_component = fancy.get_component_from_id('modadd_1_9')
            sage: boolean_polynomial_ring = CipherComponentsAnalysis(fancy)._generate_boolean_polynomial_ring_from_cipher()
            sage: boolean_polynomials = CipherComponentsAnalysis(fancy)._MODADD_as_boolean_function(modadd_component, boolean_polynomial_ring)
            sage: len(boolean_polynomials)
            6

        """
        number_of_inputs = len(component.input_id_links)
        output_bit_size = component.output_bit_size
        number_of_blocks = component.description[1]
        variables_names = self._set_variables_names(component, number_of_inputs)

        if number_of_blocks == 2:
            component_as_boolean_function = self._calculate_carry_for_two_blocks(boolean_polynomial_ring, output_bit_size,
                                                                           variables_names)

        elif number_of_blocks == 3:
            component_as_boolean_function = self._calculate_carry_for_three_blocks(boolean_polynomial_ring, output_bit_size,
                                                                             variables_names)
        else:
            raise ValueError(
                f'Expression of the output bits of MODADD with {component.description[1]} inputs not implemented yet')

        return component_as_boolean_function


    def _calculate_carry_for_two_blocks(self, boolean_polynomial_ring, output_bit_size, variables_names):
        component_as_boolean_function = []
        two_first_blocks = variables_names
        carries = [0]
        for input_number in range(output_bit_size):
            tmp = 0
            carry_left_part = 1
            carry_right_part = 0
            for block_number in range(2):
                tmp += boolean_polynomial_ring(two_first_blocks[input_number + output_bit_size * block_number])
                carry_left_part *= \
                    boolean_polynomial_ring(two_first_blocks[input_number + output_bit_size * block_number])
                carry_right_part += \
                    boolean_polynomial_ring(two_first_blocks[input_number + output_bit_size * block_number])
            tmp += carries[input_number]
            component_as_boolean_function.append(tmp)
            carry = carry_left_part + carries[input_number] * carry_right_part
            carries.append(carry)

        return component_as_boolean_function


    def _calculate_carry_for_three_blocks(self, boolean_polynomial_ring, output_bit_size, variables_names):
        two_first_blocks = variables_names[:2 * output_bit_size]
        component_as_boolean_function = self._calculate_carry_for_two_blocks(boolean_polynomial_ring, output_bit_size,
                                                                       two_first_blocks)
        # Handling the MODADD of first 2 block with the last block
        two_remaining_blocks = component_as_boolean_function + variables_names[-output_bit_size:]
        component_as_boolean_function = self._calculate_carry_for_two_blocks(boolean_polynomial_ring, output_bit_size,
                                                                       two_remaining_blocks)

        return component_as_boolean_function


    def _set_variables_names(self, component, number_of_inputs):
        variables_names = []
        for input_number in range(number_of_inputs):
            temporary_variables_names = [component.input_id_links[input_number] + "_" + str(bit_position)
                                         for bit_position in component.input_bit_positions[input_number]]
            variables_names += temporary_variables_names

        return variables_names


    def _XOR_as_boolean_function(self, component, boolean_polynomial_ring):
        """
        Return a list of boolean polynomials corresponding to the output bits of a XOR component.

        INPUT:

        - ``component`` -- **Component object**; a component from the cipher
        - ``boolean_polynomial_ring`` -- **Boolean Polynomial Ring object**; a boolean polynomial ring

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: xor_component = fancy.get_component_from_id('xor_2_7')
            sage: boolean_polynomial_ring = CipherComponentsAnalysis(fancy)._generate_boolean_polynomial_ring_from_cipher()
            sage: boolean_polynomials = CipherComponentsAnalysis(fancy)._XOR_as_boolean_function(xor_component, boolean_polynomial_ring)
            sage: len(boolean_polynomials)
            12

        """
        number_of_inputs = len(component.input_id_links)
        number_of_blocks = component.description[1]
        output_bit_size = component.output_bit_size
        variables_names = []
        variables_names_positions = {}
        for i in range(number_of_inputs):
            tmp = [component.input_id_links[i] + "_" + str(j) for j in component.input_bit_positions[i]]
            variables_names += tmp
            if component.input_id_links[i] not in variables_names_positions:
                variables_names_positions[component.input_id_links[i]] = [tmp, component.input_bit_positions[i]]
            else:  # Keys are unique in a python dico, so need to handle 2 same entries in input_id_link !
                variables_names_positions[component.input_id_links[i]] = \
                    [variables_names_positions[component.input_id_links[i]][0] + tmp,
                     variables_names_positions[component.input_id_links[i]][1] + component.input_bit_positions[i]]

        component_as_bf = []
        for i in range(output_bit_size):
            tmp = 0
            for j in range(number_of_blocks):
                tmp += boolean_polynomial_ring(variables_names[i + output_bit_size * j])
            component_as_bf.append(tmp)

        return component_as_bf

    def _select_properties_function(self, boolean_polynomial_ring, operation):
        component = operation[0]
        if component.type == SBOX:
            return self._sbox_properties(operation)
        if (component.type == LINEAR_LAYER) or (component.type == MIX_COLUMN):
            return self._linear_layer_properties(operation)
        if (component.type == WORD_OPERATION) and (component.description[0] == "ROTATE"):
            return self._linear_layer_properties(operation)
        if (component.type == WORD_OPERATION) and (component.description[0] == "SHIFT"):
            return self._linear_layer_properties(operation)
        if (component.type == WORD_OPERATION) and (component.description[0] == "XOR"):
            return self._word_operation_properties(operation, boolean_polynomial_ring)
        if (component.type == WORD_OPERATION) and (component.description[0] == "AND"):
            return self._word_operation_properties(operation, boolean_polynomial_ring)
        if (component.type == WORD_OPERATION) and (component.description[0] == "MODADD"):
            return self._word_operation_properties(operation, boolean_polynomial_ring)
        if component.type == 'fsr':
            return self._fsr_properties(operation)

        if component.type == WORD_OPERATION:
            print(f"TODO : {component.description[0]}")
            return {}
        else:
            print(f"TODO : {component.type}")
            return {}

    def _is_mds(self, component):
        """
        A matrix is MDS if and only if all the minors (determinants of square submatrices) are non-zero

        INPUT:

        - ``component`` -- **Component object**; a component from the cipher

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.twofish_block_cipher import TwofishBlockCipher
            sage: from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
            sage: twofish = TwofishBlockCipher(number_of_rounds=2)
            sage: mix_column_component = twofish.get_component_from_id('mix_column_0_19')
            sage: CipherComponentsAnalysis(twofish)._is_mds(mix_column_component)
            True

            sage: from claasp.ciphers.block_ciphers.skinny_block_cipher import SkinnyBlockCipher
            sage: from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
            sage: skinny = SkinnyBlockCipher(block_bit_size=128, key_bit_size=384, number_of_rounds=40)
            sage: mix_column_component = skinny.get_component_from_id('mix_column_0_31')
            sage: CipherComponentsAnalysis(skinny)._is_mds(mix_column_component)
            False

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: mix_column_component = aes.get_component_from_id('mix_column_1_20')
            sage: CipherComponentsAnalysis(aes)._is_mds(mix_column_component)
            True

        """

        description = component.description
        final_mtr, _ = instantiate_matrix_over_correct_field(description[0], int(description[1]), int(description[2]),
                                                             component.input_bit_size, component.output_bit_size)

        num_rows, num_cols = final_mtr.dimensions()
        for size in range(1, min(num_rows, num_cols) + 1):
            for i in range(num_rows - size + 1):
                for j in range(num_cols - size + 1):
                    submatrix = final_mtr[i:i + size, j:j + size]
                    if submatrix.is_singular():
                        return False
        return True

    def _word_operation_properties(self, operation, boolean_polynomial_ring):
        """
        Return a dictionary containing some properties of word operation component.

        INPUT:

        - ``operation`` -- **list**; a list containing:

          * a component with the operation under study
          * number of occurrences of the operation
          * list of ids of all the components with the same underlying operation
        - ``boolean_polynomial_ring`` -- **Boolean Polynomial Ring object**; a boolean polynomial ring

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: modadd_component = fancy.component_from(1, 9)
            sage: operation = [modadd_component, 2, ['modadd_1_9', 'modadd_1_10']]
            sage: boolean_polynomial_ring = CipherComponentsAnalysis(fancy)._generate_boolean_polynomial_ring_from_cipher()
            sage: d = CipherComponentsAnalysis(fancy)._word_operation_properties(operation, boolean_polynomial_ring)
            sage: d["properties"]["degree"]["value"]
            4.5

        """
        component = operation[0]
        component_as_dictionary = {"type": component.type, "input_bit_size": component.input_bit_size,
                                   "output_bit_size": component.output_bit_size, "description": component.description,
                                   "number_of_occurrences": operation[1], "component_id_list": operation[2]}
        component_as_boolean_function = self._select_boolean_function(component, boolean_polynomial_ring)

        # Adding some properties of boolean function :
        degree_list = [f.degree() for f in component_as_boolean_function]
        degree_average = sum(degree_list) / len(degree_list)
        numbers_of_terms = [len(f.terms()) for f in component_as_boolean_function]
        numbers_of_terms_average = sum(numbers_of_terms) / len(numbers_of_terms)
        numbers_of_variables = [f.nvariables() for f in component_as_boolean_function]
        numbers_of_variables_average = sum(numbers_of_variables) / len(numbers_of_variables)
        component_as_dictionary["properties"] = {}
        component_as_dictionary["properties"]["degree"] = {
            "value": degree_average,
            "min_possible_value": 1,
            "max_possible_value": component.input_bit_size
        }
        component_as_dictionary["properties"]["nterms"] = {
            "value": numbers_of_terms_average,
            "min_possible_value": 1,
            "max_possible_value": max(numbers_of_terms)
        }
        component_as_dictionary["properties"]["nvariables"] = {
            "value": numbers_of_variables_average,
            "min_possible_value": 1,
            "max_possible_value": component.input_bit_size
        }

        return component_as_dictionary

    def _generate_boolean_polynomial_ring_from_cipher(self):
        """
        Return the boolean polynomial ring for which the variables correspond to all input bits of each cipher component.

        INPUT:

        - ``cipher`` -- **Cipher object**; a cipher instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: boolean_polynomial_ring = CipherComponentsAnalysis(fancy)._generate_boolean_polynomial_ring_from_cipher()
            sage: boolean_polynomial_ring.n_variables()
            372

        """
        all_variables_names = []
        for cipher_round in self._cipher.rounds_as_list:
            for component in cipher_round.components:
                for i in range(len(component.input_id_links)):
                    all_variables_names += [component.input_id_links[i] + "_" + str(bit_position)
                                            for bit_position in component.input_bit_positions[i]]

        all_variables_names = list(set(all_variables_names))

        return BooleanPolynomialRing(len(all_variables_names), all_variables_names)

    def _collect_components_with_the_same_operation(self, operation, tmp_cipher_operations):
        for component in tmp_cipher_operations[operation]["all"]:
            for index, distinguisher in enumerate(tmp_cipher_operations[operation]["distinguisher"]):
                if component.type == WORD_OPERATION:
                    tmp = (component.input_bit_size, component.description[1])
                elif component.type in [LINEAR_LAYER, MIX_COLUMN]:
                    tmp = component.description
                else:
                    tmp = tuple(component.description)
                if tmp == distinguisher:
                    tmp_cipher_operations[operation]["types"][index].append(component)

    def _add_attributes_to_operation(self, cipher_operations, operation, tmp_cipher_operations):
        for components in tmp_cipher_operations[operation]["types"]:
            base_component = components[0]
            number_of_occurrences = len(components)
            ids = [components[i].id for i in range(len(components))]
            if operation not in cipher_operations.keys():
                cipher_operations[operation] = []
            cipher_operations[operation].append([base_component, number_of_occurrences, ids])

    def _collect_component_operations(self, component, tmp_cipher_operations):
        if component.type == WORD_OPERATION:
            if component.description[0] not in list(tmp_cipher_operations.keys()):
                tmp_cipher_operations[component.description[0]] = {"all": [], "distinguisher": []}
            tmp_cipher_operations[component.description[0]]["all"].append(component)
            tmp_cipher_operations[component.description[0]]["distinguisher"].append(
                (component.input_bit_size, component.description[1]))
        elif component.type in [LINEAR_LAYER, MIX_COLUMN]:
            if component.type not in list(tmp_cipher_operations.keys()):
                tmp_cipher_operations[component.type] = {"all": [], "distinguisher": []}
            tmp_cipher_operations[component.type]["all"].append(component)
            if component.description not in tmp_cipher_operations[component.type]["distinguisher"]:
                tmp_cipher_operations[component.type]["distinguisher"].append(component.description)
        elif component.type not in [INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, CONSTANT]:
            if component.type not in list(tmp_cipher_operations.keys()):
                tmp_cipher_operations[component.type] = {"all": [], "distinguisher": []}
            tmp_cipher_operations[component.type]["all"].append(component)
            tmp_cipher_operations[component.type]["distinguisher"].append(tuple(component.description))

    def _linear_layer_properties(self, operation):
        """
        Return a dictionary containing some properties of the linear layer operation under study.

        INPUT:

        - ``operation`` -- **list**; a list containing:

          * a component with the operation under study
          * number of occurrences of the operation
          * list of ids of all the components with the same underlying operation

        EXAMPLES::

            sage: from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
            sage: from claasp.components.rotate_component import Rotate
            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: rot_component = Rotate(1, 11, ['sbox_1_1', 'sbox_1_2'], [[2, 3], [0, 1, 2, 3]], 6, -3)
            sage: operation = [rot_component, 1, ['rot_1_11']]
            sage: d = CipherComponentsAnalysis(fancy)._linear_layer_properties(operation)
            sage: d["properties"]["differential_branch_number"]["value"]
            2

        """
        component = operation[0]
        dictio = {"type": component.type, "input_bit_size": component.input_bit_size,
                  "output_bit_size": component.output_bit_size, "description": component.description,
                  "bin_matrix": binary_matrix_of_linear_component(component), "number_of_occurrences": operation[1],
                  "component_id_list": operation[2], "properties": {}}

        # Adding some properties of the linear layer :
        dictio["properties"]["order"] = {
            "value": self._order_of_linear_component(component),
            "min_possible_value": 1,
            "max_possible_value": pow(2, component.input_bit_size) - 1
        }
        if component.input_bit_size <= 32:
            dictio["properties"]["differential_branch_number"] = {"value": branch_number(component, 'differential', 'bit'),
                                                                  "min_possible_value": 0,
                                                                  "max_possible_value": component.input_bit_size}
            dictio["properties"]["linear_branch_number"] = {"value": branch_number(component, 'linear', 'bit'),
                                                            "min_possible_value": 0,
                                                            "max_possible_value": component.input_bit_size}
        else:
            dictio["properties"]["differential_branch_number"] = {
                "value": "input bit size too large",
                "min_possible_value": 0,
                "max_possible_value": component.input_bit_size
            }
            dictio["properties"]["linear_branch_number"] = {
                "value": "input bit size too large",
                "min_possible_value": 0,
                "max_possible_value": component.input_bit_size
            }

        return dictio

    def _order_of_linear_component(self, component):
        """
        Return the multiplicative order of a linear component

        INPUT:

        - ``component`` -- **Component object**; a component from the cipher

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: rot_component = fancy.get_component_from_id('rot_1_11')
            sage: CipherComponentsAnalysis(fancy)._order_of_linear_component(rot_component)
            2

        """
        binary_matrix = binary_matrix_of_linear_component(component)
        if not binary_matrix:
            raise TypeError(f'Cannot compute the binary matrix of {component.id}')
        try:
            return binary_matrix.multiplicative_order()
        except Exception:
            return 0

    def _sbox_properties(self, operation):
        """
        Return a dictionary containing some properties of Sbox component.

        INPUT:

        - ``operation`` -- **list**; a list containing:

          * a component with the operation under study
          * number of occurrences of the operation
          * list of ids of all the components with the same underlying operation

        EXAMPLES::

            sage: from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: from claasp.components.sbox_component import SBOX
            sage: sbox_component = SBOX(0, 0, ['plaintext'], [[0, 1, 2, 3]], 4, [0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15])
            sage: operation = [sbox_component, 12, ['sbox_0_0', 'sbox_0_1', 'sbox_0_2', 'sbox_0_3', 'sbox_0_4', 'sbox_0_5',
            ....: 'sbox_1_0', 'sbox_1_1', 'sbox_1_2', 'sbox_1_3', 'sbox_1_4', 'sbox_1_5']]
            sage: d = CipherComponentsAnalysis(fancy)._sbox_properties(operation)
            sage: d["properties"]["boomerang_uniformity"]["value"]
            16

        """
        component = operation[0]
        sbox_table = component.description
        sbox = SBox(sbox_table)
        dictio = {"type": component.type, "input_bit_size": component.input_bit_size,
                  "output_bit_size": component.output_bit_size, "description": component.description,
                  "number_of_occurrences": operation[1], "component_id_list": operation[2], "properties": {}}

        # Adding some properties of sbox :
        dictio["properties"]["boomerang_uniformity"] = {
            "value": sbox.boomerang_uniformity(),
            "min_possible_value": 2,
            "max_possible_value": pow(2, component.input_bit_size)
        }
        dictio["properties"]["differential_uniformity"] = {
            "value": sbox.differential_uniformity(),
            "min_possible_value": 2,
            "max_possible_value": pow(2, component.input_bit_size)
        }
        dictio["properties"]["is_apn"] = {
            "value": sbox.is_apn(),
            "min_possible_value": 0,
            "max_possible_value": 1
        }
        dictio["properties"]["is_balanced"] = {
            "value": sbox.is_balanced(),
            "min_possible_value": 0,
            "max_possible_value": 1
        }
        dictio["properties"]["differential_branch_number"] = {
            "value": sbox.differential_branch_number(),
            "min_possible_value": 0,
            "max_possible_value": component.input_bit_size
        }
        dictio["properties"]["linear_branch_number"] = {
            "value": sbox.linear_branch_number(),
            "min_possible_value": 0,
            "max_possible_value": component.input_bit_size
        }
        dictio["properties"]["nonlinearity"] = {
            "value": sbox.nonlinearity(),
            "min_possible_value": 0,
            "max_possible_value": pow(2, component.input_bit_size - 1)
        }
        dictio["properties"]["max_degree"] = {
            "value": sbox.max_degree(),
            "min_possible_value": 0,
            "max_possible_value": component.input_bit_size
        }

        return dictio

    def _fsr_properties(self, operation):
        """
        Return a dictionary containing some properties of fsr component.

        INPUT:

        - ``operation`` -- **list**; a list containing:

          * a component with the operation under study
          * number of occurrences of the operation
          * list of ids of all the components with the same underlying operation

        EXAMPLES::

            sage: from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: from claasp.components.fsr_component import FSR
            sage: fsr_component = FSR(0,0, ["input"],[[0,1,2,3]],4,[[[4, [[1,[0]],[3,[1]],[2,[2]]]]],4])
            sage: operation= [fsr_component, 1, ['fsr_0_0']]
            sage: dictionary = CipherComponentsAnalysis(fancy)._fsr_properties(operation)
            sage: dictionary['fsr_word_size'] == 4
            True
            sage: dictionary['lfsr_connection_polynomials'] == ['x^4 + (z4 + 1)*x^3 + z4*x^2 + 1']
            True

            sage: from claasp.ciphers.stream_ciphers.bluetooth_stream_cipher_e0 import BluetoothStreamCipherE0
            sage: from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
            sage: e0 = BluetoothStreamCipherE0(keystream_bit_len=2)
            sage: dictionary = CipherComponentsAnalysis(e0).component_analysis_tests()
            sage: assert dictionary[8]["number_of_registers"] == 4
            sage: dictionary[8]["lfsr_connection_polynomials"][0] == 'x^25 + x^20 + x^12 + x^8 + 1' # first lfsr
            True
            sage: dictionary[8]['lfsr_polynomials_are_primitive'] == [True, True, True, True]
            True

            sage: from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher
            sage: triv = TriviumStreamCipher(keystream_bit_len=1)
            sage: dictionary = CipherComponentsAnalysis(triv).component_analysis_tests()
            sage: dictionary[0]["type_of_registers"] == ['non-linear', 'non-linear', 'non-linear']
            True

        """
        component = operation[0]
        fsr_word_size = component.description[1]
        component_dict = {
            "type": component.type,
            "input_bit_size": component.input_bit_size,
            "output_bit_size": component.output_bit_size,
            "fsr_word_size": fsr_word_size,
            "description": component.description,
            "number_of_occurrences": operation[1],
            "component_id_list": operation[2]
        }

        desc = component.description
        registers_len = []
        registers_type = []
        registers_feedback_relation_deg = []
        lfsr_connection_polynomials = []
        lin_flag = False

        for r in desc[0]:
            registers_len.append(r[0])
            d = max(len(term) if fsr_word_size == 1 else len(term[1]) for term in r[1])
            registers_feedback_relation_deg.append(d)
            reg_type = 'non-linear' if d > 1 else 'linear'
            registers_type.append(reg_type)
            lin_flag = lin_flag or (reg_type == 'linear')

        component_dict.update({
            'number_of_registers': len(registers_len),
            'length_of_registers': registers_len,
            'type_of_registers': registers_type,
            'degree_of_feedback_relation_of_registers': registers_feedback_relation_deg
        })

        if lin_flag:
            lfsrs_primitive = []
            exp = 0
            R = GF(2)['x'] if fsr_word_size == 1 else GF(2 ** fsr_word_size)['x']
            x = R.gens()
            a = R.construction()[1].gen()

            for index, r in enumerate(desc[0]):
                exp = exp + registers_len[index]
                if registers_type[index] == 'linear':
                    p = R(1)
                    for term in r[1]:
                        if fsr_word_size == 1:
                            p = p + x[0] ** (exp - term[0])
                        else:  # case: word based LFSR
                            m = 0
                            cf = "{0:b}".format(term[0])
                            for i in range(len(cf)):
                                if cf[i] == '1':  m = m + pow(a, len(cf) - 1 - i)
                            m = m * x[0] ** (exp - term[1][0])
                            p += m
                    lfsr_connection_polynomials.append(str(p))
                    lfsrs_primitive.append(p.is_primitive())
            component_dict.update({
                "lfsr_connection_polynomials": lfsr_connection_polynomials,
                "lfsr_polynomials_are_primitive": lfsrs_primitive
            })
        return component_dict

    def _fill_area(self, ax, categories, plot_number, positions, results):
        text = ""
        for category in categories:
            if category in ["boomerang_uniformity", "differential_uniformity"]:
                text += f"{category} = {int(results[plot_number]['properties'][category]['value'])} " \
                        f"(best is {results[plot_number]['properties'][category]['min_possible_value']}, " \
                        f"worst is {results[plot_number]['properties'][category]['max_possible_value']})\n"
            else:
                text += f"{category} = {int(results[plot_number]['properties'][category]['value'])} " \
                        f"(best is {results[plot_number]['properties'][category]['max_possible_value']}, " \
                        f"worst is {results[plot_number]['properties'][category]['min_possible_value']})\n"
        plt.text(0, positions[len(categories)], text, transform=ax.transAxes, size="small")

    def _initialise_spider_plot(self, plot_number, results):
        is_component_word_operation = results[plot_number]["type"] == "word_operation"
        is_component_rotate_or_shift = results[plot_number]["description"][0] in ["ROTATE", "SHIFT"]
        if is_component_word_operation and is_component_rotate_or_shift:
            title = results[plot_number]["description"][0] + f" {results[plot_number]['description'][1]}" + \
                    f", {results[plot_number]['input_bit_size']} input bit size"
        elif is_component_word_operation and not is_component_rotate_or_shift:
            title = results[plot_number]["description"][0] + \
                    f", {results[plot_number]['description'][1]} inputs of {results[plot_number]['output_bit_size']} bits"
        else:
            title = results[plot_number]["type"] + f", {results[plot_number]['input_bit_size']} input bit size"
        title += f", {results[plot_number]['number_of_occurrences']} occurrences"
        plt.gca().set_title(title)

    def _plot_first_line_of_data_frame(self, categories, plot_number, results):
        # We need to repeat the first value to close the circular graph:
        values = []
        for category in categories:
            if isinstance(results[plot_number]["properties"][category]["value"], str):
                continue
            elif results[plot_number]["properties"][category]["value"] not in [False, True]:
                if category in ["boomerang_uniformity", "differential_uniformity"]:
                    values.append(1 - (log2(results[plot_number]["properties"][category]["value"]) / log2(
                        results[plot_number]["properties"][category]["max_possible_value"])))
                else:
                    values.append(log2(results[plot_number]["properties"][category]["value"]) / log2(
                        results[plot_number]["properties"][category]["max_possible_value"]))
            else:
                values.append(results[plot_number]["properties"][category]["value"] / results[plot_number][
                    "properties"][category]["max_possible_value"])
        return values

    def _remove_components_with_strings_as_values(self, results_without_xor):
        results = []
        str_in_list = []
        for i in range(len(results_without_xor)):
            for result_property in list(results_without_xor[i]["properties"].keys()):
                str_in_list.append(isinstance(results_without_xor[i]["properties"][result_property]["value"], str))
            if True not in str_in_list:
                results.append(results_without_xor[i])
        return results


def binary_matrix_of_linear_component(component):
    """
    Return the binary matrix of a linear component.

    INPUT:

    - ``component`` -- **Component object**; a component from the cipher

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher as fancy
        sage: from claasp.cipher_modules.component_analysis_tests import binary_matrix_of_linear_component
        sage: fancy = fancy(number_of_rounds=3)
        sage: rot_component = fancy.get_component_from_id('rot_1_11')
        sage: binary_matrix_of_linear_component(rot_component)
        [0 0 0 1 0 0]
        [0 0 0 0 1 0]
        [0 0 0 0 0 1]
        [1 0 0 0 0 0]
        [0 1 0 0 0 0]
        [0 0 1 0 0 0]

    """
    input_bit_size = component.input_bit_size
    output_bit_size = component.output_bit_size
    if component.type == WORD_OPERATION:
        list_specific_inputs = [component.description[1]]
        if component.description[0] == "SHIFT":
            return linear_layer_to_binary_matrix(SHIFT, input_bit_size, output_bit_size, list_specific_inputs)
        elif component.description[0] == "ROTATE":
            return linear_layer_to_binary_matrix(ROTATE, input_bit_size, output_bit_size, list_specific_inputs)
    elif component.type == MIX_COLUMN:
        list_specific_inputs = component.description
        return linear_layer_to_binary_matrix(mix_column_generalized, input_bit_size, output_bit_size,
                                             list_specific_inputs)
    elif component.type == LINEAR_LAYER:
        return matrix(GF(2), component.input_bit_size, component.description)
    else:
        print("TODO : {}".format(component.id))
        return False


def branch_number(component, type, format):
    """
    Compute the differential branch number of the given matrix.

    INPUT:

    - ``component`` -- **Component object**; a component from the cipher
    - ``type`` -- **string**; the type of branch_number we are looking for, 'linear' or 'differential'
    - ``format`` -- **string**; specifies if we are looking for 'bit' or 'word' branch number

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
        sage: from claasp.cipher_modules.component_analysis_tests import branch_number
        sage: aes = AESBlockCipher(number_of_rounds=3)
        sage: mix_column_component = aes.get_component_from_id('mix_column_1_20')
        sage: branch_number(mix_column_component, 'differential', 'word')
        5

    """
    if (component.type == "word_operation") and (component.description[0] == "ROTATE"):
        return 2
    if (component.type == "word_operation") and (component.description[0] == "SHIFT"):
        return 1
    elif component.type == "linear_layer":
        return min(calculate_weights_for_linear_layer(component, format, type))
    elif component.type == "mix_column":
        return min(calculate_weights_for_mix_column(component, format, type))


def get_inverse_matrix_in_integer_representation(component):
    """
    Returns the inverse matrix in its integer representation

    INPUT:

    - ``component`` -- **Component object**; a component from the cipher

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
        sage: from claasp.cipher_modules.component_analysis_tests import get_inverse_matrix_in_integer_representation
        sage: aes = AESBlockCipher(number_of_rounds=3)
        sage: mix_column_component = aes.get_component_from_id('mix_column_1_20')
        sage: get_inverse_matrix_in_integer_representation(mix_column_component)
        [14 11 13  9]
        [ 9 14 11 13]
        [13  9 14 11]
        [11 13  9 14]

        sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
        sage: from claasp.cipher_modules.component_analysis_tests import get_inverse_matrix_in_integer_representation
        sage: midori = MidoriBlockCipher(number_of_rounds=3)
        sage: mix_column_component = midori.get_component_from_id('mix_column_0_20')
        sage: m = get_inverse_matrix_in_integer_representation(mix_column_component)
        sage: m.dimensions()
        (16,16)

    """
    if component.type != MIX_COLUMN:
        raise Exception(f"Component is not of type {MIX_COLUMN}")

    description = component.description
    matrix, _ = instantiate_matrix_over_correct_field(description[0], int(description[1]), int(description[2]),
                                                      component.input_bit_size, component.output_bit_size)
    return field_element_matrix_to_integer_matrix(matrix.inverse())

def has_maximal_branch_number(component):
    """
    INPUT:

    - ``component`` -- **Component object**; a component from the cipher

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.twofish_block_cipher import TwofishBlockCipher
        sage: from claasp.cipher_modules.component_analysis_tests import has_maximal_branch_number
        sage: twofish = TwofishBlockCipher(number_of_rounds=2)
        sage: mix_column_component = twofish.get_component_from_id('mix_column_0_1')
        sage: has_maximal_branch_number(mix_column_component)
        True

        sage: from claasp.ciphers.block_ciphers.twofish_block_cipher import TwofishBlockCipher
        sage: from claasp.cipher_modules.component_analysis_tests import has_maximal_branch_number
        sage: twofish = TwofishBlockCipher(number_of_rounds=2)
        sage: mix_column_component = twofish.get_component_from_id('mix_column_0_19')
        sage: has_maximal_branch_number(mix_column_component)
        True

        sage: from claasp.ciphers.block_ciphers.skinny_block_cipher import SkinnyBlockCipher
        sage: from claasp.cipher_modules.component_analysis_tests import has_maximal_branch_number
        sage: skinny = SkinnyBlockCipher(block_bit_size=128, key_bit_size=384, number_of_rounds=40)
        sage: mix_column_component = skinny.get_component_from_id('mix_column_0_31')
        sage: has_maximal_branch_number(mix_column_component)
        False

        sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
        sage: from claasp.cipher_modules.component_analysis_tests import has_maximal_branch_number
        sage: aes = AESBlockCipher(number_of_rounds=3)
        sage: mix_column_component = aes.get_component_from_id('mix_column_1_20')
        sage: has_maximal_branch_number(mix_column_component)
        True

    """
    description = component.description
    word_size = int(description[2])
    output_word_size = component.output_bit_size // word_size

    if component.type == MIX_COLUMN:
        return branch_number(component, 'linear', 'word') == (output_word_size + 1)


def calculate_weights_for_mix_column(component, format, type):
    if format == 'word':
        description = component.description
        final_mtr, F = instantiate_matrix_over_correct_field(description[0], int(description[1]), int(description[2]),
                                                             component.input_bit_size, component.output_bit_size)
        if type == 'linear':
            final_mtr = final_mtr.transpose()
    if format == 'bit':
        final_mtr = binary_matrix_of_linear_component(component)
        if not final_mtr:
            raise TypeError(f'Cannot compute the binary matrix of {component.id}')
        if type == 'linear':
            final_mtr = final_mtr.transpose()
        F = final_mtr.base_ring()
    n = final_mtr.nrows()
    id_matrix = identity_matrix(F, n)
    weights = []
    generator_matrix = Matrix(F, [list(a) + list(b) for a, b in zip(id_matrix, final_mtr)])
    for i in range(n):
        weights.append(generator_matrix[i].hamming_weight())

    return weights


def calculate_weights_for_linear_layer(component, format, type):
    if format == 'word':
        print('format type cannot be \'word\' for a linear layer component')
    mtr = binary_matrix_of_linear_component(component)
    if not mtr:
        raise TypeError(f'Cannot compute the binary matrix of {component.id}')
    if type == 'linear':
        mtr = mtr.transpose()
    F = mtr.base_ring()
    n = mtr.nrows()
    id_matrix = identity_matrix(F, n)
    weights = []
    generator_matrix = Matrix(F, [list(a) + list(b) for a, b in zip(id_matrix, mtr)])
    for i in range(n):
        weights.append(generator_matrix[i].hamming_weight())

    return weights


def int_to_poly(integer_value, word_size, variable):
    z = 0
    for i in range(word_size + 1):
        if (integer_value >> i) & 1:
            z = z + pow(variable, i)

    return z

def instantiate_matrix_over_correct_field(matrix, polynomial_as_int, word_size, input_bit_size, output_bit_size):
    """
    Return a binary matrix based on the description of a component.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
        sage: from claasp.cipher_modules.component_analysis_tests import instantiate_matrix_over_correct_field
        sage: midori = MidoriBlockCipher(number_of_rounds=2)
        sage: mix_column_component = midori.get_component_from_id('mix_column_0_20')
        sage: description = mix_column_component.description
        sage: mc_matrix, _ = instantiate_matrix_over_correct_field(description[0], int(description[1]), int(description[2]),
                                                         mix_column_component.input_bit_size, mix_column_component.output_bit_size)

        sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
        sage: from claasp.cipher_modules.component_analysis_tests import instantiate_matrix_over_correct_field
        sage: midori = MidoriBlockCipher(number_of_rounds=2)
        sage: mix_column_component = midori.get_component_from_id('mix_column_0_21')
        sage: description = mix_column_component.description
        sage: mc_matrix, _ = instantiate_matrix_over_correct_field(description[0], int(description[1]), int(description[2]),
                                                         mix_column_component.input_bit_size, mix_column_component.output_bit_size)

    """
    G = PolynomialRing(GF(2), 'x')
    x = G.gen()
    irr_poly = int_to_poly(polynomial_as_int, word_size, x)
    if irr_poly:
        F = GF(2 ** word_size, name='a', modulus=irr_poly)
    else:
        F = GF(2 ** word_size)
    a = F.gen()
    input_word_size = input_bit_size // word_size
    output_word_size = output_bit_size // word_size
    mtr = [[0 for _ in range(input_word_size)] for _ in range(output_word_size)]

    for i in range(output_word_size):
        for j in range(input_word_size):
            mtr[i][j] = int_to_poly(matrix[i][j], word_size, a)
    final_mtr = Matrix(F, mtr)

    return final_mtr, F

def field_element_matrix_to_integer_matrix(matrix):
    """
    Converts a matrix of field elements to the corresponding integer matrix representation

    INPUT:

    - ``matrix`` -- **Matrix object**; a matrix whose entries are field elements

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
        sage: from claasp.cipher_modules.component_analysis_tests import instantiate_matrix_over_correct_field, field_element_matrix_to_integer_matrix
        sage: aes = AESBlockCipher(number_of_rounds=3)
        sage: mix_column_component = aes.get_component_from_id('mix_column_1_20')
        sage: description = mix_column_component.description
        sage: mc_matrix, _ = instantiate_matrix_over_correct_field(description[0], int(description[1]), int(description[2]),
                                                         mix_column_component.input_bit_size, mix_column_component.output_bit_size)
        sage: mc_matrix
        [    a a + 1     1     1]
        [    1     a a + 1     1]
        [    1     1     a a + 1]
        [a + 1     1     1     a]
        sage: field_element_matrix_to_integer_matrix(mc_matrix)
        [2 3 1 1]
        [1 2 3 1]
        [1 1 2 3]
        [3 1 1 2]

    """

    int_matrix = []
    for i in range(matrix.nrows()):
        for j in range(matrix.ncols()):
            int_matrix.append(matrix[i][j].integer_representation())

    return Matrix(matrix.nrows(), matrix.ncols(), int_matrix)