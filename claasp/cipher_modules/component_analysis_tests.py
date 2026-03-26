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
from claasp.cipher_modules.generic_functions import SHIFT, ROTATE, mix_column_generalized
from claasp.name_mappings import (
    CIPHER_OUTPUT,
    CONSTANT,
    INTERMEDIATE_OUTPUT,
    LINEAR_LAYER,
    MIX_COLUMN,
    SBOX,
    WORD_OPERATION,
)

import matplotlib.pyplot as plt
from math import pi, log2
from itertools import combinations, product
import re
import shutil
import subprocess
import tempfile
import warnings
from pathlib import Path


class CipherComponentsAnalysis:
    def __init__(self, cipher):
        self._cipher = cipher

    def component_analysis_tests(self):
        """
        Return a list of properties for all the operation used in a cipher

        EXAMPLES::

            sage: from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: components_analysis = CipherComponentsAnalysis(fancy).component_analysis_tests()
            sage: len(components_analysis['test_results'])
            9

        """
        all_variables_names = []
        for cipher_round in self._cipher.rounds_as_list:
            for component in cipher_round.components:
                for id_link, bit_positions in zip(component.input_id_links, component.input_bit_positions):
                    all_variables_names.extend([f"{id_link}_{i}" for i in bit_positions])
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
            "input_parameters": {"test_name": "component_analysis", "cipher": self._cipher},
            "test_results": components_analysis,
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

            sage: from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher
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
            if operation not in [LINEAR_LAYER, MIX_COLUMN, "fsr"]:
                tmp_cipher_operations[operation]["distinguisher"] = list(
                    set(tmp_cipher_operations[operation]["distinguisher"])
                )
            if operation == "fsr":
                tmp_list = []
                for item in tmp_cipher_operations[operation]["distinguisher"]:
                    if item not in tmp_list:
                        tmp_list.append(item)
                tmp_cipher_operations[operation]["distinguisher"] = tmp_list
            tmp_cipher_operations[operation]["types"] = [
                [] for _ in range(len(tmp_cipher_operations[operation]["distinguisher"]))
            ]
            self._collect_components_with_the_same_operation(operation, tmp_cipher_operations)
        cipher_operations = {}
        for operation in list(tmp_cipher_operations.keys()):
            self._add_attributes_to_operation(cipher_operations, operation, tmp_cipher_operations)
        return cipher_operations

    def print_component_analysis_as_radar_charts(self, results=None):
        """
        Return a graph that can be plot to visualize the properties of all the operations of a cipher in a spider graph

        EXAMPLES::

            sage: from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: CipherComponentsAnalysis(fancy).print_component_analysis_as_radar_charts()

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=3)
            sage: from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
            sage: CipherComponentsAnalysis(speck).print_component_analysis_as_radar_charts()

        """
        if results == None:
            results = self.component_analysis_tests()["test_results"]
        SMALL_SIZE = 10
        MEDIUM_SIZE = 11
        BIG_SIZE = 12

        plt.rc("font", size=BIG_SIZE)  # controls default text sizes
        plt.rc("axes", titlesize=SMALL_SIZE)  # fontsize of the axes title
        plt.rc("axes", labelsize=MEDIUM_SIZE)  # fontsize of the x and y labels
        plt.rc("xtick", labelsize=SMALL_SIZE)  # fontsize of the tick labels
        plt.rc("ytick", labelsize=SMALL_SIZE)  # fontsize of the tick labels
        plt.rc("legend", fontsize=BIG_SIZE)  # legend fontsize
        plt.rc("figure", titlesize=BIG_SIZE)  # fontsize of the figure title
        plt.rcParams["figure.figsize"] = [20, 20]

        # remove XOR from results
        # results_without_xor = [results[i] for i in range(len(results)) if results[i]["description"][0] != "XOR"]
        results_without_fsr = [results[i] for i in range(len(results)) if results[i]["type"] != "fsr"]
        # removed for now because the fsr dictionary does not follow the standard structure as the other components:
        # the keys properties, values, etc are not present.
        # results = self._remove_components_with_strings_as_values(results_without_xor)
        results = self._remove_components_with_strings_as_values(results_without_fsr)

        nb_plots = len(results)
        col = 2
        row = nb_plots // col
        if nb_plots % col != 0:
            row += nb_plots % col
        positions = {8: -0.7, 3: -0.4}  # positions of the text according to the numbers of properties

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
            plt.xticks(angles[:-1], categories, color="grey", size=8)

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
                if 90 < (rot * 180.0 / pi) < 270:
                    label.set_rotation(rot * 180.0 / pi)
                    label.set_horizontalalignment("right")
                    label.set_rotation_mode("anchor")
                elif int(rot * 180.0 / pi) == 90 or int(rot * 180.0 / pi) == 270:
                    label.set_rotation(rot * 180.0 / pi)
                    label.set_horizontalalignment("center")
                    label.set_rotation_mode("anchor")
                else:
                    label.set_rotation(rot * 180.0 / pi)
                    label.set_horizontalalignment("left")
                    label.set_rotation_mode("anchor")

            # Plot data
            ax.plot(angles, values, linewidth=1, linestyle="solid")

            # Fill area
            ax.fill(angles, values, "b", alpha=0.1)
            self._fill_area(ax, categories, plot_number, positions, results)

        # Show the graph
        if nb_plots >= 5:
            plt.subplots_adjust(left=0.02, bottom=0.1, right=0.7, top=0.95, wspace=1, hspace=0.96)
        else:
            plt.subplots_adjust(left=0.09, bottom=0.3, right=0.7, top=0.7, wspace=1, hspace=0.96)
        plt.show()
        # print("The radar chart can be plot with the build-in method plt.show()")
        # return plt

    def _AND_as_boolean_function(self, component, boolean_polynomial_ring):
        """
        Return a list of boolean polynomials corresponding to the output bits of a AND component.

        INPUT:

        - ``component`` -- **Component object**; a component from the cipher
        - ``boolean_polynomial_ring`` -- **Boolean Polynomial Ring object**; a boolean polynomial ring

        EXAMPLES::

            sage: from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher
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
            tmp = [
                component.input_id_links[input_number] + "_" + str(bit_position)
                for bit_position in component.input_bit_positions[input_number]
            ]
            variables_names += tmp
            if component.input_id_links[input_number] not in variables_names_positions:
                variables_names_positions[component.input_id_links[input_number]] = [
                    tmp,
                    component.input_bit_positions[input_number],
                ]
            else:  # Keys are unique in a python dico, so need to handle 2 same entries in input_id_link !
                variables_names_positions[component.input_id_links[input_number]] = [
                    variables_names_positions[component.input_id_links[input_number]][0] + tmp,
                    variables_names_positions[component.input_id_links[input_number]][1]
                    + component.input_bit_positions[input_number],
                ]

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
            return f"TODO: {component.id} not implemented yet"

    def _MODADD_as_boolean_function(self, component, boolean_polynomial_ring):
        """
        Return a list of boolean polynomials corresponding to the output bits of a MODADD component.

        INPUT:

        - ``component`` -- **Component object**; a component from the cipher
        - ``boolean_polynomial_ring`` -- **Boolean Polynomial Ring object**; a boolean polynomial ring

        EXAMPLES::

            sage: from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher
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
            component_as_boolean_function = self._calculate_carry_for_two_blocks(
                boolean_polynomial_ring, output_bit_size, variables_names
            )

        elif number_of_blocks == 3:
            component_as_boolean_function = self._calculate_carry_for_three_blocks(
                boolean_polynomial_ring, output_bit_size, variables_names
            )
        else:
            raise ValueError(
                f"Expression of the output bits of MODADD with {component.description[1]} inputs not implemented yet"
            )

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
                carry_left_part *= boolean_polynomial_ring(
                    two_first_blocks[input_number + output_bit_size * block_number]
                )
                carry_right_part += boolean_polynomial_ring(
                    two_first_blocks[input_number + output_bit_size * block_number]
                )
            tmp += carries[input_number]
            component_as_boolean_function.append(tmp)
            carry = carry_left_part + carries[input_number] * carry_right_part
            carries.append(carry)

        return component_as_boolean_function

    def _calculate_carry_for_three_blocks(self, boolean_polynomial_ring, output_bit_size, variables_names):
        two_first_blocks = variables_names[: 2 * output_bit_size]
        component_as_boolean_function = self._calculate_carry_for_two_blocks(
            boolean_polynomial_ring, output_bit_size, two_first_blocks
        )
        # Handling the MODADD of first 2 block with the last block
        two_remaining_blocks = component_as_boolean_function + variables_names[-output_bit_size:]
        component_as_boolean_function = self._calculate_carry_for_two_blocks(
            boolean_polynomial_ring, output_bit_size, two_remaining_blocks
        )

        return component_as_boolean_function

    def _set_variables_names(self, component, number_of_inputs):
        variables_names = []
        for input_number in range(number_of_inputs):
            temporary_variables_names = [
                component.input_id_links[input_number] + "_" + str(bit_position)
                for bit_position in component.input_bit_positions[input_number]
            ]
            variables_names += temporary_variables_names

        return variables_names

    def _XOR_as_boolean_function(self, component, boolean_polynomial_ring):
        """
        Return a list of boolean polynomials corresponding to the output bits of a XOR component.

        INPUT:

        - ``component`` -- **Component object**; a component from the cipher
        - ``boolean_polynomial_ring`` -- **Boolean Polynomial Ring object**; a boolean polynomial ring

        EXAMPLES::

            sage: from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher
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
                variables_names_positions[component.input_id_links[i]] = [
                    variables_names_positions[component.input_id_links[i]][0] + tmp,
                    variables_names_positions[component.input_id_links[i]][1] + component.input_bit_positions[i],
                ]

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
        if component.type == "fsr":
            return self._fsr_properties(operation)

        else:
            # print(f"TODO: not implemented yet")
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

            sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
            sage: from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
            sage: midori = MidoriBlockCipher()
            sage: mix_column_component = midori.get_component_from_id('mix_column_0_20')
            sage: CipherComponentsAnalysis(midori)._is_mds(mix_column_component)
            False

            sage: from claasp.ciphers.toys.toyaes_block_cipher import ToyAESBlockCipher
            sage: from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
            sage: aes = ToyAESBlockCipher(number_of_rounds=3)
            sage: mix_column_component = aes.get_component_from_id('mix_column_1_20')
            sage: CipherComponentsAnalysis(aes)._is_mds(mix_column_component)
            True

        """

        description = component.description
        final_mtr, _ = instantiate_matrix_over_correct_field(
            description[0],
            int(description[1]),
            int(description[2]),
            component.input_bit_size,
            component.output_bit_size,
        )

        num_rows, num_cols = final_mtr.dimensions()
        for size in range(1, min(num_rows, num_cols) + 1):
            for i in range(num_rows - size + 1):
                for j in range(num_cols - size + 1):
                    submatrix = final_mtr[i : i + size, j : j + size]
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

            sage: from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher
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
        component_as_dictionary = {
            "type": component.type,
            "input_bit_size": component.input_bit_size,
            "output_bit_size": component.output_bit_size,
            "description": component.description,
            "number_of_occurrences": operation[1],
            "component_id_list": operation[2],
        }
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
            "max_possible_value": component.input_bit_size,
        }
        component_as_dictionary["properties"]["nterms"] = {
            "value": numbers_of_terms_average,
            "min_possible_value": 1,
            "max_possible_value": max(numbers_of_terms),
        }
        component_as_dictionary["properties"]["nvariables"] = {
            "value": numbers_of_variables_average,
            "min_possible_value": 1,
            "max_possible_value": component.input_bit_size,
        }

        return component_as_dictionary

    def _generate_boolean_polynomial_ring_from_cipher(self):
        """
        Return the boolean polynomial ring for which the variables correspond to all input bits of each cipher component.

        INPUT:

        - ``cipher`` -- **Cipher object**; a cipher instance

        EXAMPLES::

            sage: from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher
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
                    all_variables_names += [
                        component.input_id_links[i] + "_" + str(bit_position)
                        for bit_position in component.input_bit_positions[i]
                    ]

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
                (component.input_bit_size, component.description[1])
            )
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
            sage: from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: rot_component = Rotate(1, 11, ['sbox_1_1', 'sbox_1_2'], [[2, 3], [0, 1, 2, 3]], 6, -3)
            sage: operation = [rot_component, 1, ['rot_1_11']]
            sage: d = CipherComponentsAnalysis(fancy)._linear_layer_properties(operation)
            sage: d["properties"]["differential_branch_number"]["value"]
            2

        """
        component = operation[0]
        dictio = {
            "type": component.type,
            "input_bit_size": component.input_bit_size,
            "output_bit_size": component.output_bit_size,
            "description": component.description,
            "bin_matrix": binary_matrix_of_linear_component(component),
            "number_of_occurrences": operation[1],
            "component_id_list": operation[2],
            "properties": {},
        }

        # Adding some properties of the linear layer :
        dictio["properties"]["order"] = {
            "value": self._order_of_linear_component(component),
            "min_possible_value": 1,
            "max_possible_value": pow(2, component.input_bit_size) - 1,
        }
        if component.input_bit_size <= 64:
            dictio["properties"]["differential_branch_number"] = {
                "value": branch_number(component, "differential", "bit"),
                "min_possible_value": 0,
                "max_possible_value": component.input_bit_size,
            }
            dictio["properties"]["linear_branch_number"] = {
                "value": branch_number(component, "linear", "bit"),
                "min_possible_value": 0,
                "max_possible_value": component.input_bit_size,
            }
        else:
            dictio["properties"]["differential_branch_number"] = {
                "value": "input bit size too large",
                "min_possible_value": 0,
                "max_possible_value": component.input_bit_size,
            }
            dictio["properties"]["linear_branch_number"] = {
                "value": "input bit size too large",
                "min_possible_value": 0,
                "max_possible_value": component.input_bit_size,
            }

        return dictio

    def _order_of_linear_component(self, component):
        """
        Return the multiplicative order of a linear component

        INPUT:

        - ``component`` -- **Component object**; a component from the cipher

        EXAMPLES::

            sage: from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: rot_component = fancy.get_component_from_id('rot_1_11')
            sage: CipherComponentsAnalysis(fancy)._order_of_linear_component(rot_component)
            2

        """
        binary_matrix = binary_matrix_of_linear_component(component)
        if not binary_matrix:
            raise TypeError(f"Cannot compute the binary matrix of {component.id}")
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
            sage: from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher
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
        dictio = {
            "type": component.type,
            "input_bit_size": component.input_bit_size,
            "output_bit_size": component.output_bit_size,
            "description": component.description,
            "number_of_occurrences": operation[1],
            "component_id_list": operation[2],
            "properties": {},
        }

        # Adding some properties of sbox :
        dictio["properties"]["boomerang_uniformity"] = {
            "value": sbox.boomerang_uniformity(),
            "min_possible_value": 2,
            "max_possible_value": pow(2, component.input_bit_size),
        }
        dictio["properties"]["differential_uniformity"] = {
            "value": sbox.differential_uniformity(),
            "min_possible_value": 2,
            "max_possible_value": pow(2, component.input_bit_size),
        }
        dictio["properties"]["is_apn"] = {"value": sbox.is_apn(), "min_possible_value": 0, "max_possible_value": 1}
        dictio["properties"]["is_balanced"] = {
            "value": sbox.is_balanced(),
            "min_possible_value": 0,
            "max_possible_value": 1,
        }
        dictio["properties"]["differential_branch_number"] = {
            "value": sbox.differential_branch_number(),
            "min_possible_value": 0,
            "max_possible_value": component.input_bit_size,
        }
        dictio["properties"]["linear_branch_number"] = {
            "value": sbox.linear_branch_number(),
            "min_possible_value": 0,
            "max_possible_value": component.input_bit_size,
        }
        dictio["properties"]["nonlinearity"] = {
            "value": sbox.nonlinearity(),
            "min_possible_value": 0,
            "max_possible_value": pow(2, component.input_bit_size - 1),
        }
        dictio["properties"]["max_degree"] = {
            "value": sbox.max_degree(),
            "min_possible_value": 0,
            "max_possible_value": component.input_bit_size,
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
            sage: from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher
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
            sage: dictionary = CipherComponentsAnalysis(e0).component_analysis_tests()['test_results']
            sage: assert dictionary[8]["number_of_registers"] == 4
            sage: dictionary[8]["lfsr_connection_polynomials"][0] == 'x^25 + x^20 + x^12 + x^8 + 1' # first lfsr
            True
            sage: dictionary[8]['lfsr_polynomials_are_primitive'] == [True, True, True, True]
            True

            sage: from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher
            sage: triv = TriviumStreamCipher(keystream_bit_len=1)
            sage: dictionary = CipherComponentsAnalysis(triv).component_analysis_tests()['test_results']
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
            "component_id_list": operation[2],
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
            reg_type = "non-linear" if d > 1 else "linear"
            registers_type.append(reg_type)
            lin_flag = lin_flag or (reg_type == "linear")

        component_dict.update(
            {
                "number_of_registers": len(registers_len),
                "length_of_registers": registers_len,
                "type_of_registers": registers_type,
                "degree_of_feedback_relation_of_registers": registers_feedback_relation_deg,
            }
        )

        if lin_flag:
            lfsrs_primitive = []
            exp = 0
            R = GF(2)["x"] if fsr_word_size == 1 else GF(2**fsr_word_size)["x"]
            x = R.gens()
            a = R.construction()[1].gen()

            for index, r in enumerate(desc[0]):
                exp = exp + registers_len[index]
                if registers_type[index] == "linear":
                    p = R(1)
                    for term in r[1]:
                        if fsr_word_size == 1:
                            p = p + x[0] ** (exp - term[0])
                        else:  # case: word based LFSR
                            m = 0
                            cf = "{0:b}".format(term[0])
                            for i in range(len(cf)):
                                if cf[i] == "1":
                                    m = m + pow(a, len(cf) - 1 - i)
                            m = m * x[0] ** (exp - term[1][0])
                            p += m
                    lfsr_connection_polynomials.append(str(p))
                    lfsrs_primitive.append(p.is_primitive())
            component_dict.update(
                {
                    "lfsr_connection_polynomials": lfsr_connection_polynomials,
                    "lfsr_polynomials_are_primitive": lfsrs_primitive,
                }
            )
        return component_dict

    def _fill_area(self, ax, categories, plot_number, positions, results):
        text = ""
        for category in categories:
            if category in ["boomerang_uniformity", "differential_uniformity"]:
                text += (
                    f"{category} = {int(results[plot_number]['properties'][category]['value'])} "
                    f"(best is {results[plot_number]['properties'][category]['min_possible_value']}, "
                    f"worst is {results[plot_number]['properties'][category]['max_possible_value']})\n"
                )
            else:
                text += (
                    f"{category} = {int(results[plot_number]['properties'][category]['value'])} "
                    f"(best is {results[plot_number]['properties'][category]['max_possible_value']}, "
                    f"worst is {results[plot_number]['properties'][category]['min_possible_value']})\n"
                )
        # plt.text(0, positions[len(categories)], text, transform=ax.transAxes, size="small")
        plt.text(2, 0, text, transform=ax.transAxes, size="small")

    def _initialise_spider_plot(self, plot_number, results):
        is_component_word_operation = results[plot_number]["type"] == "word_operation"
        is_component_rotate_or_shift = results[plot_number]["description"][0] in ["ROTATE", "SHIFT"]
        if is_component_word_operation and is_component_rotate_or_shift:
            title = (
                results[plot_number]["description"][0]
                + f" {results[plot_number]['description'][1]}"
                + f", {results[plot_number]['input_bit_size']} input bit size"
            )
        elif is_component_word_operation and not is_component_rotate_or_shift:
            title = (
                results[plot_number]["description"][0]
                + f", {results[plot_number]['description'][1]} inputs of {results[plot_number]['output_bit_size']} bits"
            )
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
                    values.append(
                        1
                        - (
                            log2(results[plot_number]["properties"][category]["value"])
                            / log2(results[plot_number]["properties"][category]["max_possible_value"])
                        )
                    )
                else:
                    values.append(
                        log2(results[plot_number]["properties"][category]["value"])
                        / log2(results[plot_number]["properties"][category]["max_possible_value"])
                    )
            else:
                values.append(
                    results[plot_number]["properties"][category]["value"]
                    / results[plot_number]["properties"][category]["max_possible_value"]
                )
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

        sage: from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher as fancy
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
        return linear_layer_to_binary_matrix(
            mix_column_generalized, input_bit_size, output_bit_size, list_specific_inputs
        )
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

        sage: from claasp.ciphers.toys.toyaes_block_cipher import ToyAESBlockCipher
        sage: from claasp.cipher_modules.component_analysis_tests import branch_number
        sage: aes = ToyAESBlockCipher(number_of_rounds=3)
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

        sage: from claasp.ciphers.toys.toyaes_block_cipher import ToyAESBlockCipher
        sage: from claasp.cipher_modules.component_analysis_tests import get_inverse_matrix_in_integer_representation
        sage: aes = ToyAESBlockCipher(number_of_rounds=3)
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
        (16, 16)

    """
    if component.type != MIX_COLUMN:
        raise Exception(f"Component is not of type {MIX_COLUMN}")

    description = component.description
    matrix, _ = instantiate_matrix_over_correct_field(
        description[0], int(description[1]), int(description[2]), component.input_bit_size, component.output_bit_size
    )
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

        sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
        sage: from claasp.cipher_modules.component_analysis_tests import has_maximal_branch_number
        sage: midori = MidoriBlockCipher()
        sage: mix_column_component = midori.get_component_from_id('mix_column_0_20')
        sage: has_maximal_branch_number(mix_column_component)
        False

        sage: from claasp.ciphers.toys.toyaes_block_cipher import ToyAESBlockCipher
        sage: from claasp.cipher_modules.component_analysis_tests import has_maximal_branch_number
        sage: aes = ToyAESBlockCipher(number_of_rounds=3)
        sage: mix_column_component = aes.get_component_from_id('mix_column_1_20')
        sage: has_maximal_branch_number(mix_column_component)
        True

    """
    description = component.description
    word_size = int(description[2])
    output_word_size = component.output_bit_size // word_size

    if component.type == MIX_COLUMN:
        return branch_number(component, "linear", "word") == (output_word_size + 1)


def calculate_weights_for_mix_column(component, format, type):
    if format == "bit":
        # Use faster direct computation for binary matrices
        binary_matrix = binary_matrix_of_linear_component(component)
        if not binary_matrix:
            raise TypeError(f"Cannot compute the binary matrix of {component.id}")
        # compute_branch_number_from_binary_matrix already returns the minimum weight
        # Return as list to maintain interface compatibility with word-level calls
        bn = compute_branch_number_from_binary_matrix(binary_matrix, type)
        return [bn]

    # Word-level computation
    description = component.description
    final_mtr, _ = instantiate_matrix_over_correct_field(
        description[0], int(description[1]), int(description[2]), component.input_bit_size, component.output_bit_size
    )
    if type == "linear":
        final_mtr = final_mtr.transpose()
    # The exact sage path now supports custom-modulus fields by remapping them
    # to an isomorphic Conway-defined field, but bounded enumeration is still
    # preferable here for performance on common cipher MixColumn matrices.
    bn = compute_branch_number_from_field_matrix(final_mtr, method="bounded")
    return [bn]


def _update_best_branch_number(candidate, best):
    """
    Helper to update best branch number and check for early exit.

    INPUT:

    - ``candidate`` -- **integer**; candidate branch number value
    - ``best`` -- **integer**; current best (minimum) branch number

    OUTPUT:

    - **tuple** (new_best, should_exit) where should_exit is True if best == 2
    """
    if candidate < best:
        best = candidate
        if best == 2:
            return best, True
    return best, False


def _map_matrix_to_conway_field(matrix):
    """
    Return an isomorphic copy of ``matrix`` over a Conway-defined finite field.

    This preserves the branch number while converting the matrix into a field
    representation that GAP can handle through Sage's ``LinearCode`` backend.
    """
    field = matrix.base_ring()
    if field.degree() == 1:
        return matrix

    conway_field = GF(field.order(), name="c")
    if field == conway_field:
        return matrix

    roots = field.modulus().roots(conway_field, multiplicities=False)
    if not roots:
        raise NotImplementedError(
            "Could not construct an isomorphism from the source field to a Conway-defined field."
        )

    homomorphism = field.hom([roots[0]], conway_field)
    return Matrix(
        conway_field,
        [[homomorphism(matrix[i][j]) for j in range(matrix.ncols())] for i in range(matrix.nrows())],
    )


def compute_branch_number_from_field_matrix_with_sage(matrix):
    """
    Compute the exact branch number of a field matrix using Sage's LinearCode.

    This function uses Sage's LinearCode.minimum_distance() to compute the exact
    branch number as the minimum distance of the linear code generated by ``[I | M]``,
    where ``I`` is the identity matrix.

    INPUT:

    - ``matrix`` -- Sage matrix over a finite field (GF(2^m) or similar)

    OUTPUT:

    - **integer** -- the exact branch number

    NOTE:

    If the source field is defined by a custom irreducible polynomial and GAP
    rejects that representation, the matrix is transparently remapped to an
    isomorphic Conway-defined field before the exact branch number is computed.

    EXAMPLES::

        sage: from sage.all import GF, Matrix
        sage: from claasp.cipher_modules.component_analysis_tests import compute_branch_number_from_field_matrix_with_sage
        sage: # GF(4) matrix: expected branch number is 3
        sage: F = GF(4, 'a')
        sage: M = Matrix(F, [[1, 1], [1, F.gen()]])
        sage: compute_branch_number_from_field_matrix_with_sage(M)
        3

    """
    if matrix.nrows() <= 0 or matrix.ncols() <= 0:
        raise ValueError("Branch number requires a non-empty matrix")

    input_size = matrix.nrows()
    F = matrix.base_ring()

    id_matrix = identity_matrix(F, input_size)
    rows = [matrix.row(i) for i in range(input_size)]
    generator_matrix = Matrix(F, [list(id_matrix[i]) + list(rows[i]) for i in range(input_size)])

    from sage.coding.linear_code import LinearCode
    try:
        return int(LinearCode(generator_matrix).minimum_distance())
    except NotImplementedError:
        mapped_matrix = _map_matrix_to_conway_field(matrix)
        mapped_field = mapped_matrix.base_ring()
        mapped_identity = identity_matrix(mapped_field, input_size)
        mapped_rows = [mapped_matrix.row(i) for i in range(input_size)]
        mapped_generator_matrix = Matrix(
            mapped_field,
            [list(mapped_identity[i]) + list(mapped_rows[i]) for i in range(input_size)],
        )
        return int(LinearCode(mapped_generator_matrix).minimum_distance())


def _initialize_field_enumeration(matrix, max_input_weight):
    if matrix.nrows() <= 0 or matrix.ncols() <= 0:
        raise ValueError("Branch number requires a non-empty matrix")
    if max_input_weight < 1:
        raise ValueError("max_input_weight must be at least 1")

    input_size = matrix.nrows()
    output_size = matrix.ncols()
    rows = [matrix.row(i) for i in range(input_size)]
    non_zero_elements = [element for element in matrix.base_ring() if element != 0]
    limit = min(max_input_weight, input_size)
    best = (input_size + output_size) + 1
    return rows, non_zero_elements, limit, best


def _search_field_weight_1(rows, best):
    for row in rows:
        candidate = 1 + row.hamming_weight()
        best, exit_early = _update_best_branch_number(candidate, best)
        if exit_early:
            return best, True
    return best, False


def _search_field_weight_2(rows, non_zero_elements, best):
    if 2 >= best:
        return best, True
    for i, j in combinations(range(len(rows)), 2):
        left = rows[i]
        right = rows[j]
        for coeff in non_zero_elements:
            candidate = 2 + (left + coeff * right).hamming_weight()
            best, exit_early = _update_best_branch_number(candidate, best)
            if exit_early:
                return best, True
    return best, False


def _search_field_weight_3(rows, non_zero_elements, best):
    if 3 >= best:
        return best, True
    for i, j, k in combinations(range(len(rows)), 3):
        first = rows[i]
        second = rows[j]
        third = rows[k]
        for coeff_second, coeff_third in product(non_zero_elements, repeat=2):
            candidate = 3 + (first + coeff_second * second + coeff_third * third).hamming_weight()
            best, exit_early = _update_best_branch_number(candidate, best)
            if exit_early:
                return best, True
    return best, False


def _evaluate_field_weight_4_plus_combination(base_row, remaining_rows, coeffs, weight, best):
    output = base_row
    for coeff, row in zip(coeffs, remaining_rows):
        output += coeff * row
    candidate = weight + output.hamming_weight()
    return _update_best_branch_number(candidate, best)


def _search_field_weight_4_plus(rows, non_zero_elements, limit, best):
    for weight in range(4, limit + 1):
        if weight >= best:
            break
        for indices in combinations(range(len(rows)), weight):
            base_row = rows[indices[0]]
            remaining_rows = [rows[i] for i in indices[1:]]
            for coeffs in product(non_zero_elements, repeat=weight - 1):
                best, exit_early = _evaluate_field_weight_4_plus_combination(
                    base_row, remaining_rows, coeffs, weight, best
                )
                if exit_early:
                    return best, True
    return best, False


def compute_branch_number_from_field_matrix_with_bounded_enumeration(matrix, max_input_weight=3):
    """
    Compute the branch number of a field matrix using bounded enumeration.

    This function enumerates all input vectors up to max_input_weight and computes
    the minimum output weight. Returns exact result if the minimizing input has weight
    ≤ max_input_weight, otherwise returns lower bound.

    This method is backend-independent and is used as a robust fallback when the
    ``method='sage'`` path cannot run on a specific field representation.

    INPUT:

    - ``matrix`` -- Sage matrix over a finite field (GF(2^m) or similar)
    - ``max_input_weight`` -- **integer** (default: ``3``); maximum Hamming weight to explore

    OUTPUT:

    - **integer** -- the branch number (exact if minimum at weight ≤ max_input_weight, lower bound otherwise)

    EXAMPLES::

        sage: from sage.all import GF, Matrix
        sage: from claasp.cipher_modules.component_analysis_tests import compute_branch_number_from_field_matrix_with_bounded_enumeration
        sage: F = GF(2)
        sage: M = Matrix(F, [[1, 0], [1, 1]])
        sage: compute_branch_number_from_field_matrix_with_bounded_enumeration(M, 3)
        2

    """
    rows, non_zero_elements, limit, best = _initialize_field_enumeration(matrix, max_input_weight)

    best, done = _search_field_weight_1(rows, best)
    if done:
        return best
    if limit == 1:
        return best

    best, done = _search_field_weight_2(rows, non_zero_elements, best)
    if done:
        return best
    if limit == 2 or 3 >= best:
        return best

    best, done = _search_field_weight_3(rows, non_zero_elements, best)
    if done:
        return best
    if limit == 3 or 4 >= best:
        return best

    best, _ = _search_field_weight_4_plus(rows, non_zero_elements, limit, best)

    return best


def _prepare_binary_matrix(binary_matrix, type):
    if hasattr(binary_matrix, "nrows"):
        matrix = binary_matrix.transpose() if type == "linear" else binary_matrix
    else:
        if not binary_matrix or not binary_matrix[0]:
            raise ValueError("binary_matrix must be a non-empty square matrix")
        base_matrix = binary_matrix
        if type == "linear":
            base_matrix = [list(row) for row in zip(*base_matrix)]
        matrix = Matrix(GF(2), base_matrix)

    n = matrix.nrows()
    ncols = matrix.ncols()
    if n != ncols:
        raise ValueError("Branch number requires a square binary matrix")
    return matrix, n


def _build_binary_column_masks(matrix, n):
    columns = []
    for col_idx in range(n):
        col_mask = 0
        for row_idx in range(n):
            col_mask |= (int(matrix[row_idx][col_idx]) & 1) << row_idx
        columns.append(col_mask)
    return columns


MZN_BRANCH_NUMBER_MODEL_GENERAL = r"""
int: n;
int: word_size;
constraint word_size >= 1 /\ n mod word_size = 0;

array [0..n-1, 0..n-1] of 0..1: M;

int: num_words = n div word_size;

array [0..n-1] of var bool: X;
array [0..n-1] of var bool: Y;

array [0..num_words-1] of var bool: X_active;
array [0..num_words-1] of var bool: Y_active;

var int: num_active_words_in;
var int: num_active_words_out;

constraint forall(i in 0..n-1)(
    Y[i] = xorall([X[j] | j in 0..n-1 where M[i, j] = 1])
);

constraint forall(w in 0..num_words-1)(
    X_active[w] = exists(X[w * word_size .. w * word_size + word_size - 1])
);

constraint forall(w in 0..num_words-1)(
    Y_active[w] = exists(Y[w * word_size .. w * word_size + word_size - 1])
);

constraint num_active_words_in = sum(X_active);
constraint num_active_words_out = sum(Y_active);

var 1..2*num_words: obj = sum(X_active) + sum(Y_active);

solve minimize obj;

output [
  "Branch number: ", show(obj), "\\n",
  "Input: ", show(X), "\\n",
  "Output: ", show(Y), "\\n"
];
"""


MINIZINC_BRANCH_NUMBER_SOLVER_ORDER = ("ortools", "cbc", "coin-bc", "highs", "scip", "chuffed", "gecode")


def _to_dzn_matrix_literal_from_binary_matrix(binary_matrix, original_word_size):
    bit_n = len(binary_matrix)
    if bit_n == 0 or any(len(row) != bit_n for row in binary_matrix):
        raise ValueError("binary_matrix must be non-empty and square")
    if bit_n % original_word_size != 0:
        raise ValueError(
            "binary matrix size must be a multiple of original_word_size "
            f"(got size={bit_n}, original_word_size={original_word_size})"
        )

    flat = ", ".join(str(v) for row in binary_matrix for v in row)
    return (
        f"n = {bit_n};\n"
        f"word_size = {original_word_size};\n"
        f"M = array2d(0..n-1, 0..n-1, [{flat}]);\n"
    )


def _parse_branch_number_from_minizinc_stdout(stdout):
    match = re.search(r"Branch number:\s*(\d+)", stdout)
    if not match:
        raise RuntimeError(
            "Could not parse branch number from MiniZinc output.\n"
            f"MiniZinc output was:\n{stdout}"
        )
    return int(match.group(1))


def _candidate_minizinc_solvers(primary_solver):
    ordered = [primary_solver]
    for solver in MINIZINC_BRANCH_NUMBER_SOLVER_ORDER:
        if solver != primary_solver:
            ordered.append(solver)
    return ordered


def _run_minizinc_branch_number(minizinc_bin, solver, model_path, data_path, timeout_seconds, threads):
    command = [minizinc_bin, "--solver", solver, "--free-search", str(model_path), str(data_path)]
    solver_key = solver.replace("-", "").lower()
    if threads and solver_key in ("ortools", "chuffed", "gecode"):
        command.extend(["-p", str(threads)])
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )


def _compute_branch_number_from_expanded_binary_matrix_with_minizinc(
    binary_matrix,
    original_word_size,
    solver="ortools",
    minizinc_bin="minizinc",
    timeout_seconds=None,
    threads=2,
):
    """
    Solve branch number from a bit-level matrix while preserving original field word grouping.

    INPUT:

    - ``binary_matrix`` -- expanded GF(2) matrix (square, 0/1 entries)
    - ``original_word_size`` -- **integer**; word grouping used in MiniZinc objective

    NOTE:

    This helper is shared by:
      * native binary matrices (``original_word_size=1``), and
      * GF(2^w) matrices after expansion to GF(2) (``original_word_size=w``).
    """
    if shutil.which(minizinc_bin) is None:
        raise FileNotFoundError(f"MiniZinc executable '{minizinc_bin}' was not found in PATH")

    with tempfile.TemporaryDirectory(prefix="branch_bn_mzn_general_") as tmpdir:
        tmp_path = Path(tmpdir)
        model_path = tmp_path / "branch_number_general.mzn"
        data_path = tmp_path / "instance.dzn"

        model_path.write_text(MZN_BRANCH_NUMBER_MODEL_GENERAL, encoding="utf-8")
        data_path.write_text(
            _to_dzn_matrix_literal_from_binary_matrix(
                binary_matrix,
                original_word_size=original_word_size,
            ),
            encoding="utf-8",
        )

        attempts = []
        for candidate_solver in _candidate_minizinc_solvers(solver):
            try:
                result = _run_minizinc_branch_number(
                    minizinc_bin=minizinc_bin,
                    solver=candidate_solver,
                    model_path=model_path,
                    data_path=data_path,
                    timeout_seconds=timeout_seconds,
                    threads=threads,
                )
            except subprocess.TimeoutExpired:
                attempts.append((candidate_solver, None))
                continue

            attempts.append((candidate_solver, result))

            if result.returncode == 0:
                return _parse_branch_number_from_minizinc_stdout(result.stdout)

            if candidate_solver == "gecode" and "libGL.so.1" in result.stderr:
                continue

        failure_lines = ["MiniZinc failed for all attempted solvers:"]
        for used_solver, result in attempts:
            if result is None:
                failure_lines.append(f"- solver={used_solver}, timeout")
                continue
            failure_lines.append(f"- solver={used_solver}, exit_code={result.returncode}")
            if result.stderr.strip():
                failure_lines.append(f"  stderr: {result.stderr.strip()}")
            if result.stdout.strip():
                failure_lines.append(f"  stdout: {result.stdout.strip()}")
        raise RuntimeError("\n".join(failure_lines))


def _poly_over_gf2_to_int(polynomial):
    coeffs = polynomial.list()
    value = 0
    for idx, coeff in enumerate(coeffs):
        if int(coeff) & 1:
            value |= 1 << idx
    return value


def _validate_irreducible_polynomial(word_size, irreducible_polynomial):
    if word_size < 1:
        raise ValueError("word_size must be >= 1")

    if irreducible_polynomial <= 0:
        raise ValueError("irreducible_polynomial must be positive")

    if irreducible_polynomial.bit_length() != word_size + 1:
        raise ValueError(
            "irreducible_polynomial must have degree exactly word_size "
            f"(expected bit_length={word_size + 1}, got {irreducible_polynomial.bit_length()})."
        )

    if (irreducible_polynomial & 1) == 0:
        raise ValueError("irreducible_polynomial must have non-zero constant term")


def _gf2_mul_mod(a, b, word_size, mod_poly):
    mask = (1 << word_size) - 1
    aa = a & mask
    bb = b & mask
    res = 0

    for _ in range(word_size):
        if bb & 1:
            res ^= aa
        bb >>= 1
        carry = aa & (1 << (word_size - 1))
        aa = (aa << 1) & mask
        if carry:
            aa ^= mod_poly & mask

    return res & mask


def _gf2w_multiply_bit_matrix(a, word_size, irreducible_polynomial):
    block = [[0] * word_size for _ in range(word_size)]

    for j in range(word_size):
        basis = 1 << j
        product = _gf2_mul_mod(a, basis, word_size, irreducible_polynomial)
        for i in range(word_size):
            block[i][j] = (product >> i) & 1

    return block


def _expand_field_matrix_to_binary_matrix(matrix, word_size, irreducible_polynomial):
    n = len(matrix)
    bit_n = word_size * n
    bit_matrix = [[0] * bit_n for _ in range(bit_n)]

    for i in range(n):
        for j in range(n):
            block = _gf2w_multiply_bit_matrix(
                matrix[i][j],
                word_size=word_size,
                irreducible_polynomial=irreducible_polynomial,
            )
            for bi in range(word_size):
                for bj in range(word_size):
                    bit_matrix[i * word_size + bi][j * word_size + bj] = block[bi][bj]

    return bit_matrix


def _search_binary_weight_1(columns, best):
    for col in columns:
        candidate = 1 + col.bit_count()
        if candidate < best:
            best = candidate
    return best


def _search_binary_weight_2(columns, best):
    if 2 >= best:
        return best, True
    for i, j in combinations(range(len(columns)), 2):
        candidate = 2 + (columns[i] ^ columns[j]).bit_count()
        if candidate < best:
            best = candidate
            if best == 2:
                return best, True
    return best, False


def _search_binary_weight_3(columns, best):
    if 3 >= best:
        return best, True
    for i, j, k in combinations(range(len(columns)), 3):
        candidate = 3 + (columns[i] ^ columns[j] ^ columns[k]).bit_count()
        if candidate < best:
            best = candidate
            if best == 2:
                return best, True
    return best, False


def _search_binary_weight_4_plus(columns, limit, best):
    for weight in range(4, limit + 1):
        if weight >= best:
            break
        for indices in combinations(range(len(columns)), weight):
            output_mask = 0
            for index in indices:
                output_mask ^= columns[index]
            candidate = weight + output_mask.bit_count()
            if candidate < best:
                best = candidate
                if best == 2:
                    return best, True
    return best, False


def compute_branch_number_from_field_matrix_with_minizinc(
    matrix,
    solver="ortools",
    minizinc_bin="minizinc",
    timeout_seconds=None,
    threads=2,
):
    """
    Compute branch number of a GF(2^w) field matrix using MiniZinc.

    INPUT:

    - ``matrix`` -- Sage matrix over GF(2^w)
    - ``solver`` -- **string** (default: ``"ortools"``); preferred MiniZinc solver
    - ``minizinc_bin`` -- **string** (default: ``"minizinc"``); MiniZinc executable
    - ``timeout_seconds`` -- **integer** or ``None``; timeout for each solver attempt
    - ``threads`` -- **integer** (default: ``2``); thread count for supported solvers

    OUTPUT:

    - **integer** -- the exact branch number

    EXAMPLES::

        sage: import shutil
        sage: from sage.all import GF, Matrix
        sage: from claasp.cipher_modules.component_analysis_tests import compute_branch_number_from_field_matrix_with_minizinc
        sage: if shutil.which("minizinc") is None:
        ....:     print("MiniZinc not available")
        ....: else:
        ....:     F = GF(4, 'a')
        ....:     M = Matrix(F, [[1, 1], [1, F.gen()]])
        ....:     compute_branch_number_from_field_matrix_with_minizinc(M)
        3
    """
    if matrix.nrows() <= 0 or matrix.ncols() <= 0:
        raise ValueError("Branch number requires a non-empty matrix")
    if matrix.nrows() != matrix.ncols():
        raise ValueError("Branch number requires a square matrix")

    field = matrix.base_ring()
    if field.characteristic() != 2:
        raise ValueError("MiniZinc branch-number method supports only fields with characteristic 2")

    if field.order() == 2:
        binary_matrix = [[int(matrix[i][j]) for j in range(matrix.ncols())] for i in range(matrix.nrows())]
        return compute_branch_number_from_binary_matrix_with_minizinc(
            binary_matrix,
            type="differential",
            solver=solver,
            minizinc_bin=minizinc_bin,
            timeout_seconds=timeout_seconds,
            threads=threads,
        )

    word_size = field.degree()
    irreducible_polynomial = _poly_over_gf2_to_int(field.modulus())
    _validate_irreducible_polynomial(word_size, irreducible_polynomial)

    int_matrix = field_element_matrix_to_integer_matrix(matrix)
    normalized_matrix = [
        [int(int_matrix[i][j]) for j in range(int_matrix.ncols())]
        for i in range(int_matrix.nrows())
    ]
    binary_matrix = _expand_field_matrix_to_binary_matrix(
        normalized_matrix,
        word_size=word_size,
        irreducible_polynomial=irreducible_polynomial,
    )
    return _compute_branch_number_from_expanded_binary_matrix_with_minizinc(
        binary_matrix=binary_matrix,
        original_word_size=word_size,
        solver=solver,
        minizinc_bin=minizinc_bin,
        timeout_seconds=timeout_seconds,
        threads=threads,
    )


def compute_branch_number_from_field_matrix(matrix, max_input_weight=3, method="minizinc"):
    """
    Compute the branch number of a matrix over a finite field with selectable method.

    This is the main wrapper function that delegates to either the Sage LinearCode
    method or bounded enumeration approach based on the ``method`` parameter.

    This function computes the minimum Hamming weight of all non-zero vectors in the
    linear code generated by the augmented matrix ``[I | matrix]``, where ``I`` is the
    identity matrix. This is a fundamental metric for analyzing the diffusion properties
    of linear cryptographic components.

    INPUT:

    - ``matrix`` -- Sage matrix over a finite field (GF(2^m) or similar)
    - ``max_input_weight`` -- **integer** (default: ``3``); fallback search bound for bounded enumeration
    - ``method`` -- **string** (default: ``"minizinc"``); computation method:

            * ``"minizinc"`` -- tries MiniZinc exact computation first.
                If MiniZinc cannot run (missing executable/solver/runtime issue),
                falls back to ``"sage"`` and then to ``"bounded"``.
            * ``"sage"`` -- tries Sage's LinearCode for exact computation first.
                If the field representation is incompatible with GAP, the matrix
                is remapped to an isomorphic Conway-defined field transparently.
                If the exact path still fails for some other backend/runtime
                reason, the function falls back to ``"bounded"`` and emits a
                ``RuntimeWarning``.
            * ``"bounded"`` -- uses bounded enumeration up to max_input_weight.
              Recommended for cipher fields using custom irreducible polynomials.

    OUTPUT:

    - **integer** -- the branch number (minimum output weight over all non-zero inputs)

    EXAMPLES::

        sage: from sage.all import GF, Matrix
        sage: from claasp.cipher_modules.component_analysis_tests import compute_branch_number_from_field_matrix
        sage: # GF(4) matrix: expected branch number is 3
        sage: F = GF(4, 'a')
        sage: M = Matrix(F, [[1, 1], [1, F.gen()]])
        sage: compute_branch_number_from_field_matrix(M)  # default minizinc method
        3
        sage: compute_branch_number_from_field_matrix(M, method='bounded')
        3
        sage: # GF(2) matrix: delegates to fast binary algorithm
        sage: F2 = GF(2)
        sage: M2 = Matrix(F2, [[1, 0], [1, 1]])
        sage: compute_branch_number_from_field_matrix(M2)
        2

    COMPUTATION STRATEGY:

     1. **Exact path (primary):** Tries MiniZinc exact optimization first.
    2. **Exact Sage fallback:** If MiniZinc is unavailable or fails at runtime,
       tries Sage's LinearCode minimum_distance(), remapping to an isomorphic
       Conway field when required by GAP.
    3. **Fallback bounded enumeration:** When method="bounded" (or when exact
       backends fail), performs bounded search up to ``max_input_weight``.
       May return underestimate if minimum is at weight > max_input_weight.

    NOTE:

    For GF(2) matrices with method="sage", this function transparently uses the optimized
    binary version, which computes results via bitwise XOR and popcount operations.

    WARNING - BOUNDED SEARCH LIMITATION:

    When method="bounded" is used, the returned value is guaranteed exact ONLY if the
    minimizing input has Hamming weight ≤ max_input_weight. If the true minimum requires
    higher weight, the function returns a lower bound. Current default (max_input_weight=3)
    is appropriate for most ciphers but may miss minima at weight 4+.
    """
    if method == "minizinc":
        try:
            return compute_branch_number_from_field_matrix_with_minizinc(matrix)
        except (RuntimeError, ImportError, FileNotFoundError, subprocess.SubprocessError, OSError) as error:
            warnings.warn(
                f"MiniZinc method failed ({error}); falling back to Sage method.",
                RuntimeWarning,
                stacklevel=2,
            )
            return compute_branch_number_from_field_matrix(
                matrix,
                max_input_weight=max_input_weight,
                method="sage",
            )
    elif method == "sage":
        # Check if field is GF(2) and use optimized binary version
        F = matrix.base_ring()
        if F.order() == 2:
            input_size = matrix.nrows()
            output_size = matrix.ncols()
            binary_matrix = [[int(matrix[i][j]) for j in range(output_size)] for i in range(input_size)]
            return compute_branch_number_from_binary_matrix(binary_matrix, type="differential", method="sage")
        try:
            return compute_branch_number_from_field_matrix_with_sage(matrix)
        except (RuntimeError, ImportError) as error:
            warnings.warn(
                f"Sage method failed ({error}); falling back to bounded enumeration.",
                RuntimeWarning,
                stacklevel=2,
            )
            return compute_branch_number_from_field_matrix_with_bounded_enumeration(matrix, max_input_weight)
    elif method == "bounded":
        return compute_branch_number_from_field_matrix_with_bounded_enumeration(matrix, max_input_weight)
    else:
        raise ValueError(f"Unknown method '{method}'. Must be 'minizinc', 'sage' or 'bounded'.")


def calculate_weights_for_linear_layer(component, format, type):
    if format == "word":
        print("format type cannot be 'word' for a linear layer component")

    # Use faster direct computation for binary matrices
    binary_matrix = binary_matrix_of_linear_component(component)
    if not binary_matrix:
        raise TypeError(f"Cannot compute the binary matrix of {component.id}")
    # compute_branch_number_from_binary_matrix already returns the minimum weight
    # Return as list to maintain interface compatibility
    bn = compute_branch_number_from_binary_matrix(binary_matrix, type)
    return [bn]


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
        ....: mix_column_component.input_bit_size, mix_column_component.output_bit_size)

        sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
        sage: from claasp.cipher_modules.component_analysis_tests import instantiate_matrix_over_correct_field
        sage: midori = MidoriBlockCipher(number_of_rounds=2)
        sage: mix_column_component = midori.get_component_from_id('mix_column_0_21')
        sage: description = mix_column_component.description
        sage: mc_matrix, _ = instantiate_matrix_over_correct_field(description[0], int(description[1]), int(description[2]),
        ....: mix_column_component.input_bit_size, mix_column_component.output_bit_size)

    """
    G = PolynomialRing(GF(2), "x")
    x = G.gen()
    irr_poly = int_to_poly(polynomial_as_int, word_size, x)
    if irr_poly:
        F = GF(2**word_size, name="a", modulus=irr_poly)
    else:
        F = GF(2**word_size)
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

        sage: from claasp.ciphers.toys.toyaes_block_cipher import ToyAESBlockCipher
        sage: from claasp.cipher_modules.component_analysis_tests import instantiate_matrix_over_correct_field, field_element_matrix_to_integer_matrix
        sage: aes = ToyAESBlockCipher(number_of_rounds=3)
        sage: mix_column_component = aes.get_component_from_id('mix_column_1_20')
        sage: description = mix_column_component.description
        sage: mc_matrix, _ = instantiate_matrix_over_correct_field(description[0], int(description[1]), int(description[2]),
        ....: mix_column_component.input_bit_size, mix_column_component.output_bit_size)
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

    def _field_element_to_int(element):
        if hasattr(element, "to_integer"):
            return element.to_integer()
        if hasattr(element, "integer_representation"):
            return element.integer_representation()
        return int(element)

    int_matrix = []
    for i in range(matrix.nrows()):
        for j in range(matrix.ncols()):
            int_matrix.append(_field_element_to_int(matrix[i][j]))

    return Matrix(matrix.nrows(), matrix.ncols(), int_matrix)


def compute_branch_number_from_binary_matrix_with_sage(binary_matrix, type="differential"):
    """
    Compute the exact branch number of a binary matrix using Sage's LinearCode.

    This function uses Sage's LinearCode.minimum_distance() to compute the exact
    branch number as the minimum distance of the linear code generated by ``[I | M]``,
    where ``I`` is the identity matrix.

    INPUT:

    - ``binary_matrix`` -- Sage matrix over GF(2) or Python list of lists with entries in {0,1}
    - ``type`` -- **string** (default: ``"differential"``):

      * ``"differential"`` -- computes branch number on matrix as-is
      * ``"linear"`` -- transposes matrix before computing

    OUTPUT:

    - **integer** -- the exact branch number

    NOTE:

    This function is expected to work for GF(2) matrices, but if the Sage/GAP
    backend is unavailable or raises an internal runtime error, callers can use
    ``compute_branch_number_from_binary_matrix(..., method='sage')`` to get
    automatic fallback to bounded enumeration.

    EXAMPLES::

        sage: from sage.all import Matrix, GF
        sage: from claasp.cipher_modules.component_analysis_tests import compute_branch_number_from_binary_matrix_with_sage
        sage: F = GF(2)
        sage: matrix = Matrix(F, [[1, 0], [1, 1]])
        sage: compute_branch_number_from_binary_matrix_with_sage(matrix, 'differential')
        2
        sage: compute_branch_number_from_binary_matrix_with_sage(matrix, 'linear')
        2

    """
    if hasattr(binary_matrix, "nrows"):
        matrix = binary_matrix.transpose() if type == "linear" else binary_matrix
        n = matrix.nrows()
        ncols = matrix.ncols()
    else:
        if not binary_matrix or not binary_matrix[0]:
            raise ValueError("binary_matrix must be a non-empty square matrix")
        base_matrix = binary_matrix
        if type == "linear":
            base_matrix = [list(row) for row in zip(*base_matrix)]
        n = len(base_matrix)
        ncols = len(base_matrix[0])
        # Convert to Sage matrix
        matrix = Matrix(GF(2), base_matrix)

    if n != ncols:
        raise ValueError("Branch number requires a square binary matrix")

    from sage.coding.linear_code import LinearCode
    id_matrix = identity_matrix(GF(2), n)
    generator_matrix = Matrix(GF(2), [list(id_matrix[i]) + list(matrix[i]) for i in range(n)])
    return int(LinearCode(generator_matrix).minimum_distance())


def compute_branch_number_from_binary_matrix_with_bounded_enumeration(binary_matrix, type="differential", max_input_weight=3):
    """
    Compute the branch number of a binary matrix using bounded Hamming weight enumeration.

    This function enumerates all input vectors up to max_input_weight and computes
    the minimum output weight. Returns exact result if the minimizing input has weight
    ≤ max_input_weight, otherwise returns lower bound.

    This method is also used as a fallback by the wrapper function when the
    ``method='sage'`` backend is not available.

    INPUT:

    - ``binary_matrix`` -- Sage matrix over GF(2) or Python list of lists with entries in {0,1}
    - ``type`` -- **string** (default: ``"differential"``):

      * ``"differential"`` -- computes branch number on matrix as-is
      * ``"linear"`` -- transposes matrix before computing

    - ``max_input_weight`` -- **integer** (default: ``3``); maximum Hamming weight to explore

    OUTPUT:

    - **integer** -- the branch number (exact if minimum at weight ≤ max_input_weight, lower bound otherwise)

    EXAMPLES::

        sage: from sage.all import Matrix, GF
        sage: from claasp.cipher_modules.component_analysis_tests import compute_branch_number_from_binary_matrix_with_bounded_enumeration
        sage: F = GF(2)
        sage: matrix = Matrix(F, [[1, 0], [1, 1]])
        sage: compute_branch_number_from_binary_matrix_with_bounded_enumeration(matrix, 'differential', 3)
        2

    """
    matrix, n = _prepare_binary_matrix(binary_matrix, type)
    if max_input_weight < 1:
        raise ValueError("max_input_weight must be at least 1")

    limit = min(max_input_weight, n)
    columns = _build_binary_column_masks(matrix, n)

    best = (2 * n) + 1

    best = _search_binary_weight_1(columns, best)
    if best == 2 or limit == 1:
        return best

    best, done = _search_binary_weight_2(columns, best)
    if done:
        return best
    if limit == 2 or 3 >= best:
        return best

    best, done = _search_binary_weight_3(columns, best)
    if done:
        return best
    if limit == 3 or 4 >= best:
        return best

    best, _ = _search_binary_weight_4_plus(columns, limit, best)

    return best


def compute_branch_number_from_binary_matrix_with_minizinc(
    binary_matrix,
    type="differential",
    solver="ortools",
    minizinc_bin="minizinc",
    timeout_seconds=None,
    threads=2,
):
    """
    Compute exact branch number of a binary matrix using MiniZinc.

    INPUT:

    - ``binary_matrix`` -- Sage matrix over GF(2) or Python list of lists with entries in {0,1}
    - ``type`` -- **string** (default: ``"differential"``); ``"linear"`` uses transpose
    - ``solver`` -- **string** (default: ``"ortools"``); preferred MiniZinc solver
    - ``minizinc_bin`` -- **string** (default: ``"minizinc"``); MiniZinc executable
    - ``timeout_seconds`` -- **integer** or ``None``; timeout for each solver attempt
    - ``threads`` -- **integer** (default: ``2``); thread count for supported solvers

    OUTPUT:

    - **integer** -- the exact branch number

    NOTE:

    This function is for binary input matrices. For GF(2^w) matrices, use
    ``compute_branch_number_from_field_matrix_with_minizinc`` which expands the
    matrix to GF(2) and still preserves word grouping in the MiniZinc model.
    """
    matrix, n = _prepare_binary_matrix(binary_matrix, type)
    normalized = [[int(matrix[i][j]) for j in range(n)] for i in range(n)]
    return _compute_branch_number_from_expanded_binary_matrix_with_minizinc(
        binary_matrix=normalized,
        original_word_size=1,
        solver=solver,
        minizinc_bin=minizinc_bin,
        timeout_seconds=timeout_seconds,
        threads=threads,
    )


def compute_branch_number_from_binary_matrix(binary_matrix, type="differential", max_input_weight=3, method="minizinc"):
    """
    Compute the branch number of a binary matrix with selectable computation method.

    This is the main wrapper function that delegates to either the Sage LinearCode
    method or bounded enumeration approach based on the ``method`` parameter.

    INPUT:

    - ``binary_matrix`` -- Sage matrix over GF(2) or Python list of lists with entries in {0,1}
    - ``type`` -- **string** (default: ``"differential"``):

      * ``"differential"`` -- computes branch number on matrix as-is
      * ``"linear"`` -- transposes matrix before computing

    - ``max_input_weight`` -- **integer** (default: ``3``); fallback search bound for bounded enumeration
    - ``method`` -- **string** (default: ``"minizinc"``); computation method:

            * ``"minizinc"`` -- tries MiniZinc exact computation first.
                If MiniZinc cannot run (missing executable/solver/runtime issue),
                falls back to ``"sage"`` and then to ``"bounded"``.
            * ``"sage"`` -- tries Sage's LinearCode for exact computation first.
                If Sage raises a backend/runtime error, the function automatically
                falls back to ``"bounded"`` and emits a ``RuntimeWarning``.
            * ``"bounded"`` -- uses bounded enumeration up to max_input_weight

    OUTPUT:

    - **integer** -- the branch number

    EXAMPLES::

        sage: from sage.all import Matrix, GF
        sage: from claasp.cipher_modules.component_analysis_tests import compute_branch_number_from_binary_matrix
        sage: F = GF(2)
        sage: matrix = Matrix(F, [[1, 0], [1, 1]])
        sage: compute_branch_number_from_binary_matrix(matrix, 'differential')  # default minizinc method
        2
        sage: compute_branch_number_from_binary_matrix(matrix, 'differential', method='bounded')
        2
        sage: compute_branch_number_from_binary_matrix(matrix, 'linear', method='sage')
        2

    COMPUTATION STRATEGY:

        When method="minizinc" (default):
            - Tries MiniZinc exact optimization first
            - Falls back to Sage exact method, then bounded enumeration

    When method="sage":
            - Tries Sage's LinearCode.minimum_distance() for exact computation
            - Falls back to bounded enumeration if Sage backend fails

    When method="bounded":
      - Uses bounded enumeration up to max_input_weight
      - Faster for small max_input_weight but may underestimate if minimum is at weight > max_input_weight
      - Useful for testing and comparing performance

    """
    if method == "minizinc":
        try:
            return compute_branch_number_from_binary_matrix_with_minizinc(binary_matrix, type)
        except (RuntimeError, ImportError, FileNotFoundError, subprocess.SubprocessError, OSError) as error:
            warnings.warn(
                f"MiniZinc method failed ({error}); falling back to Sage method.",
                RuntimeWarning,
                stacklevel=2,
            )
            return compute_branch_number_from_binary_matrix(
                binary_matrix,
                type=type,
                max_input_weight=max_input_weight,
                method="sage",
            )
    elif method == "sage":
        try:
            return compute_branch_number_from_binary_matrix_with_sage(binary_matrix, type)
        except (RuntimeError, ImportError) as error:
            warnings.warn(
                f"Sage method failed ({error}); falling back to bounded enumeration.",
                RuntimeWarning,
                stacklevel=2,
            )
            return compute_branch_number_from_binary_matrix_with_bounded_enumeration(
                binary_matrix, type, max_input_weight
            )
    elif method == "bounded":
        return compute_branch_number_from_binary_matrix_with_bounded_enumeration(binary_matrix, type, max_input_weight)
    else:
        raise ValueError(f"Unknown method '{method}'. Must be 'minizinc', 'sage' or 'bounded'.")
