
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

import time
from gurobipy import *
from sage.crypto.sbox import SBox
from collections import Counter
from sage.rings.polynomial.pbori.pbori import BooleanPolynomialRing
from claasp.cipher_modules.graph_generator import create_networkx_graph_from_input_ids, _get_predecessors_subgraph
from claasp.cipher_modules.component_analysis_tests import binary_matrix_of_linear_component
from gurobipy import Model, GRB
import os
import secrets
from sage.all import GF

verbosity = False

class MilpMonomialPredictionModel():
    """

    Given a number of rounds of a chosen cipher and a chosen output bit, this module produces a model that can either:
    - find the ANF of this chosen output bit,
    - find an upper bound of this ANF,
    - find the exact degree of this ANF (slower),
    - find the superpoly of this ANF given a chosen cube.

    This module can only be used if the user possesses a Gurobi license.

    """

    def __init__(self, cipher):
        self._cipher = cipher
        self._variables = None
        self._model = None
        self._occurences = None
        self._used_variables = []
        self._variables_as_list = []
        self._unused_variables = []
        self._used_predecessors_sorted = None
        self._constants = {}

    def build_gurobi_model(self):
        if os.getenv('GUROBI_COMPUTE_SERVER') is not None:
            env = Env(empty=True)
            env.setParam('ComputeServer', os.getenv('GUROBI_COMPUTE_SERVER'))
            env.start()
            model = Model(env=env)
        else:
            model = Model()
        model.Params.LogToConsole = 0
        self._model = model

    def get_all_variables_as_list(self):
        for component_id in list(self._variables.keys())[:-1]:
            for bit_position in self._variables[component_id].keys():
                self._variables_as_list.append(self._variables[component_id][bit_position]["original"].VarName)
                copies = self._variables[component_id][bit_position]["copies"]
                for copy in copies:
                    self._variables_as_list.append(copy.VarName)

    def get_unused_variables(self):
        self.get_all_variables_as_list()
        for variable in self._variables_as_list:
            if variable not in self._used_variables:
                self._unused_variables.append(variable)

    def set_unused_variables_to_zero(self):
        self.get_unused_variables()
        for name in self._unused_variables:
            var = self._model.getVarByName(name)
            self._model.addConstr(var == 0)

    def set_as_used_variables(self, variables):
        self._model.update()
        for v in variables:
            try:
                if v.VarName not in self._used_variables:
                    self._used_variables.append(v.VarName)
                    if "copy" in v.VarName.split("_"):
                        i = v.VarName.split("_").index("copy")
                        tmp1 = v.VarName.split("_")[(i + 2):]
                        tmp2 = "_".join(tmp1)
                        self._used_variables.append(tmp2)
                self._unused_variables = [x for x in self._unused_variables if x != v.VarName]
            except:
                continue

    def create_all_copies(self):
        for name in list(self._variables.keys())[:-1]:
            for bit_position in self._variables[name].keys():
                copies = self._variables[name][bit_position]["copies"]
                original_var = self._variables[name][bit_position]["original"]

                if copies != []:
                    for i in range(len(copies)):
                        self._model.addConstr(original_var >= copies[i])
                    self._model.addConstr(sum(copies[i] for i in range(len(copies))) >= original_var)
                self._model.update()

    def get_anfs_from_sbox(self, component):
        anfs = []
        B = BooleanPolynomialRing(component.output_bit_size, 'x')
        C = BooleanPolynomialRing(component.output_bit_size, 'x')
        var_names = [f"x{i}" for i in range(component.output_bit_size)]
        d = {}
        for i in range(component.output_bit_size):
            d[B(var_names[i])] = C(var_names[component.output_bit_size - i - 1])

        sbox = SBox(component.description)
        for i in range(component.input_bit_size):
            anf = sbox.component_function(1 << i).algebraic_normal_form()
            anf = anf.subs(d)  # x0 was msb, now it is the lsb
            anfs.append(anf)
        anfs.reverse()
        return anfs

    def get_monomial_occurences(self, component):
        B = BooleanPolynomialRing(component.input_bit_size, 'x')
        anfs = self.get_anfs_from_sbox(component)

        anfs = [B(anfs[i]) for i in range(component.input_bit_size)]
        monomials = []
        for index, anf in enumerate(anfs):
            if index in list(self._occurences[component.id].keys()):
                monomials += anf.monomials()
        monomials_degree_based = {}
        sbox = SBox(component.description)
        for deg in range(sbox.max_degree() + 1):
            monomials_degree_based[deg] = dict(
                Counter([monomial for monomial in monomials if monomial.degree() == deg]))
            if deg >= 2:
                for monomial in monomials_degree_based[deg].keys():
                    deg1_monomials = monomial.variables()
                    for deg1_monomial in deg1_monomials:
                        if deg1_monomial not in monomials_degree_based[1].keys():
                            monomials_degree_based[1][deg1_monomial] = 0
                        monomials_degree_based[1][deg1_monomial] += monomials_degree_based[deg][monomial]

        sorted_monomials_degree_based = {1: {}}
        for xi in B.variable_names():
            if B(xi) not in monomials_degree_based[1].keys():
                sorted_monomials_degree_based[1][B(xi)] = 0
            else:
                sorted_monomials_degree_based[1][B(xi)] = monomials_degree_based[1][B(xi)]
        for deg in range(sbox.max_degree() + 1):
            if deg != 1:
                sorted_monomials_degree_based[deg] = monomials_degree_based[deg]

        return sorted_monomials_degree_based

    def create_gurobi_vars_sbox(self, component, input_vars_concat):
        monomial_occurences = self.get_monomial_occurences(component)
        B = BooleanPolynomialRing(component.input_bit_size, 'x')
        x = B.variable_names()

        copy_xi = {}
        for index, xi in enumerate(monomial_occurences[1].keys()):
            nb_occurence_xi = monomial_occurences[1][B(xi)]
            if nb_occurence_xi != 0:
                copy_xi[B(xi)] = self._model.addVars(list(range(nb_occurence_xi)), vtype=GRB.BINARY,
                                                     name="copy_" + input_vars_concat[index].VarName + "_as_" + str(xi))
                self._model.update()
                self.set_as_used_variables(list(copy_xi[B(xi)].values()))
                self.set_as_used_variables([input_vars_concat[index]])
                for i in range(nb_occurence_xi):
                    self._model.addConstr(input_vars_concat[index] >= copy_xi[B(xi)][i])
                self._model.addConstr(
                    sum(copy_xi[B(xi)][i] for i in range(nb_occurence_xi)) >= input_vars_concat[index])

        copy_monomials_deg = {}
        for deg in list(monomial_occurences.keys()):
            if deg >= 2:
                nb_monomials = sum(monomial_occurences[deg].values())
                copy_monomials_deg[deg] = self._model.addVars(list(range(nb_monomials)), vtype=GRB.BINARY)
                self._model.update()

        copy_monomials_deg[1] = copy_xi
        degrees = list(copy_monomials_deg.keys())
        for deg in degrees:
            if deg >= 2:
                copy_monomials_deg[deg]["current"] = 0
            elif deg == 1:
                monomials = list(copy_monomials_deg[1].keys())
                for monomial in monomials:
                    copy_monomials_deg[deg][monomial]["current"] = 0
        self._model.update()
        return copy_monomials_deg

    def add_sbox_constraints(self, component):
        output_vars = self.get_output_vars(component)
        input_vars_concat = self.get_input_vars(component)
        self._model.update()

        B = BooleanPolynomialRing(component.input_bit_size, 'x')
        x = B.variable_names()
        anfs = self.get_anfs_from_sbox(component)
        anfs = [B(anfs[i]) for i in range(component.input_bit_size)]

        copy_monomials_deg = self.create_gurobi_vars_sbox(component, input_vars_concat)

        for index, bit_pos in enumerate(list(self._occurences[component.id].keys())):
            constr = 0
            equality = True
            monomials = anfs[bit_pos].monomials()
            for monomial in monomials:
                deg = monomial.degree()
                if deg == 1:
                    current = copy_monomials_deg[deg][monomial]["current"]
                    constr += copy_monomials_deg[deg][monomial][current]
                    copy_monomials_deg[deg][monomial]["current"] += 1
                elif deg >= 2:
                    current = copy_monomials_deg[deg]["current"]
                    for deg1_monomial in monomial.variables():
                        current_deg1 = copy_monomials_deg[1][deg1_monomial]["current"]
                        self._model.addConstr(
                            copy_monomials_deg[deg][current] == copy_monomials_deg[1][deg1_monomial][current_deg1])
                        self.set_as_used_variables([copy_monomials_deg[deg][current]])
                        copy_monomials_deg[1][deg1_monomial]["current"] += 1
                    constr += copy_monomials_deg[deg][current]
                    copy_monomials_deg[deg]["current"] += 1
                elif deg == 0:
                    equality = False
            if equality:
                self._model.addConstr(output_vars[index] == constr)
            else:
                self._model.addConstr(output_vars[index] >= constr)
        self._model.update()

    def create_copies_for_linear_layer(self, binary_matrix, input_vars_concat):
        copies = {}
        for index, var in enumerate(input_vars_concat):
            column = [row[index] for row in binary_matrix]
            number_of_1s = list(column).count(1)
            if number_of_1s > 1:
                current = 1
            else:
                current = 0
            copies[index] = {}
            copies[index][0] = var
            copies[index]["current"] = current
            self.set_as_used_variables([var])
            new_vars = self._model.addVars(list(range(number_of_1s)), vtype=GRB.BINARY,
                                           name="copy_" + var.VarName)
            self._model.update()
            for i in range(number_of_1s):
                self._model.addConstr(var >= new_vars[i])
            self._model.addConstr(
                sum(new_vars[i] for i in range(number_of_1s)) >= var)
            self._model.update()
            for i in range(1, number_of_1s + 1):
                copies[index][i] = new_vars[i - 1]
        return copies

    def add_linear_layer_constraints(self, component):
        output_vars = self.get_output_vars(component)
        input_vars_concat = self.get_input_vars(component)

        if component.type == "linear_layer":
            binary_matrix = component.description
            binary_matrix = list(zip(*binary_matrix))
        else:
            binary_matrix = binary_matrix_of_linear_component(component)

        copies = self.create_copies_for_linear_layer(binary_matrix, input_vars_concat)
        for index_row, row in enumerate(binary_matrix):
            constr = 0
            for index_bit, bit in enumerate(row):
                if bit:
                    current = copies[index_bit]["current"]
                    constr += copies[index_bit][current]
                    copies[index_bit]["current"] += 1
                    self.set_as_used_variables([copies[index_bit][current]])
            self._model.addConstr(output_vars[index_row] == constr)
        self._model.update()

    def add_rotate_constraints(self, component):
        output_vars = self.get_output_vars(component)
        input_vars_concat = self.get_input_vars(component)
        self._model.update()

        rotate_offset = component.description[1]
        for index, bit_pos in enumerate(list(self._occurences[component.id].keys())):
            self._model.addConstr(
                output_vars[index] == input_vars_concat[(bit_pos - rotate_offset) % component.output_bit_size])
            self.set_as_used_variables([input_vars_concat[(bit_pos - rotate_offset) % component.output_bit_size]])
        self._model.update()

    def add_shift_constraints(self, component):
        output_vars = self.get_output_vars(component)
        input_vars_concat = self.get_input_vars(component)
        self._model.update()

        shift_offset = component.description[1]

        for index, bit_pos in enumerate(self._occurences[component.id].keys()):
            target = bit_pos - shift_offset

            if target < 0 or target >= component.output_bit_size:
                self._model.addConstr(output_vars[index] == 0)
            else:
                self._model.addConstr(output_vars[index] == input_vars_concat[target])
                self.set_as_used_variables([input_vars_concat[target]])

        self._model.update()

    def add_xor_constraints(self, component):
        output_vars = self.get_output_vars(component)
        output_size = component.output_bit_size

        var_inputs_per_bit = [[] for _ in range(output_size)]
        const_bits_per_bit = [[] for _ in range(output_size)]

        current_output_index = 0
        for input_idx, input_name in enumerate(component.input_id_links):
            bit_positions = component.input_bit_positions[input_idx]

            for local_idx, pos in enumerate(bit_positions):
                output_index = current_output_index % output_size

                if input_name.startswith("constant"):
                    const_comp = self._cipher.get_component_from_id(input_name)
                    value = (int(const_comp.description[0], 16) >>
                             (const_comp.output_bit_size - 1 - pos)) & 1
                    const_bits_per_bit[output_index].append(value)
                else:
                    copy_index = len(self._variables[input_name][pos]["copies"])
                    copy_var = self._model.addVar(
                        vtype=GRB.BINARY,
                        name=f"copy_{copy_index}_{input_name}[{pos}]"
                    )
                    self._variables[input_name][pos]["copies"].append(copy_var)
                    var_inputs_per_bit[output_index].append(copy_var)
                current_output_index += 1

        self._model.update()
        for bit_idx in range(output_size):
            vars_sum = sum(var_inputs_per_bit[bit_idx])
            for v in var_inputs_per_bit[bit_idx]:
                self.set_as_used_variables([v])
            const_val = sum(const_bits_per_bit[bit_idx]) % 2
            if const_val == 0:
                self._model.addConstr(output_vars[bit_idx] == vars_sum)
            else:
                self._model.addConstr(output_vars[bit_idx] >= vars_sum)
        self._model.update()

    def get_output_vars(self, component):
        output_vars = []
        tmp = list(self._occurences[component.id].keys())
        tmp.sort()
        for i in tmp:
            output_vars.append(self._model.getVarByName(f"{component.id}[{i}]"))
        self._model.update()
        return output_vars

    def get_input_vars(self, component):
        input_vars_concat = []
        for index, input_name in enumerate(component.input_id_links):
            for pos in component.input_bit_positions[index]:
                copy_index = len(self._variables[input_name][pos]["copies"])
                copy = self._model.addVar(vtype=GRB.BINARY, name=f"copy_{copy_index}_{input_name}[{pos}]")
                self._variables[input_name][pos]["copies"].append(copy)
                input_vars_concat.append(copy)
        self._model.update()
        return input_vars_concat

    def add_modadd_constraints(self, component):
        """
        Constraints are taken from https://eprint.iacr.org/2024/1335.pdf
        """
        output_vars = self.get_output_vars(component)
        input_vars_concat = self.get_input_vars(component)
        self._model.update()

        total = len(input_vars_concat)
        if total % 2 != 0:
            raise ValueError("add_modadd_constraints: input length not even")
        n = total // 2
        a_bits = input_vars_concat[:n]
        b_bits = input_vars_concat[n:2*n]
        z_bits = output_vars

        # Rerverse endianess : index 0 corresponds to LSB now
        a_bits = list(reversed(a_bits))
        b_bits = list(reversed(b_bits))
        z_bits = list(reversed(z_bits))

        # Create carry-out variables for bits 0..n-1
        carry_vars = [None] * n
        for i in range(n - 1):
            carry_vars[i] = self._model.addVar(vtype=GRB.BINARY,
                                               name=f"modadd_carry_{component.id}_{i}")
        # top carry fixed to 0
        carry_vars[n - 1] = self._model.addVar(vtype=GRB.BINARY, lb=0, ub=0,
                                               name=f"modadd_carry_{component.id}_{n-1}_zero")
        self._model.update()

        for i in range(n):
            ai = a_bits[i]
            bi = b_bits[i]
            zi = z_bits[i]

            # carry-in for bit i
            if i == 0:
                c_in = None  # no carry into LSB
            else:
                c_in = carry_vars[i - 1]

            s_i = self._model.addVar(vtype=GRB.INTEGER, lb=0, ub=3,
                                     name=f"modadd_sum_{component.id}_{i}")
            if c_in is not None:
                self._model.addConstr(s_i == ai + bi + c_in)
            else:
                self._model.addConstr(s_i == ai + bi)

            t_i = carry_vars[i]
            self._model.addConstr(zi + 2 * t_i == s_i)

            self.set_as_used_variables([ai, bi, zi, t_i, s_i])

        self._model.update()

    def add_and_constraints(self, component):
        output_vars = self.get_output_vars(component)
        input_vars_concat = self.get_input_vars(component)
        self._model.update()

        block_size = int(len(input_vars_concat) // component.description[1])
        for index, bit_pos in enumerate(list(self._occurences[component.id].keys())):
            self._model.addConstr(output_vars[index] == input_vars_concat[index])
            self._model.addConstr(output_vars[index] == input_vars_concat[index + block_size])
            self.set_as_used_variables([input_vars_concat[index], input_vars_concat[index + block_size]])
        self._model.update()

    def get_original_var(self, var_to_copy):
        name = var_to_copy.VarName
        l = name.split("_")
        l = l[2:]
        original_name = "_".join(l)
        index = original_name.split("[")[1].split("]")[0]
        original_name = original_name.split("[")[0]
        return original_name, int(index)

    def create_copies(self, nb_copies, var_to_copy):
        copies = self._model.addVars(list(range(nb_copies)), vtype=GRB.BINARY)
        for i in range(nb_copies):
            self._model.addConstr(var_to_copy >= copies[i])
        self._model.addConstr(sum(copies[i] for i in range(nb_copies)) >= var_to_copy)
        self._model.update()
        return list(copies.values())

    def add_fsr_constraints(self, component):
        output_bit_size = component.output_bit_size

        output_vars = {}
        tmp = list(self._occurences[component.id].keys())
        tmp.sort()
        for i in tmp:
            output_vars[i] = self._model.getVarByName(f"{component.id}[{i}]")

        input_vars_concat = self.get_input_vars(component)
        self._model.update()

        interm_input_vars = self._model.addVars(list(range(output_bit_size)), vtype=GRB.BINARY, name=f"interm_input")
        for i in range(output_bit_size):
            self._model.addConstr(interm_input_vars[i] == input_vars_concat[i])
            self.set_as_used_variables([input_vars_concat[i]])

        if len(component.description) == 2:
            number_of_initialization_clocks = 1
        else:
            number_of_initialization_clocks = component.description[-1]

        registers = component.description[0]
        registers_lengths = [registers[i][0] for i in range(len(registers))]
        registers_lengths_accumulated = [0]
        for value in registers_lengths:
            registers_lengths_accumulated.append(registers_lengths_accumulated[-1] + value)

        s = {}
        s[0] = list(interm_input_vars.values())

        for clock in range(number_of_initialization_clocks):
            tmp = s[clock][:]
            self._model.update()

            new_bits = []
            for register in registers:
                polynomial = 0
                monomials_indexes = register[1]
                for indexes in monomials_indexes:
                    if len(indexes) > 1:
                        a = self._model.addVar(vtype=GRB.BINARY)
                        self._model.update()
                        y = self._model.addVars(indexes, vtype=GRB.BINARY)
                        for index in indexes:
                            self._model.addConstr(y[index] <= tmp[index])
                            self._model.addConstr(a <= tmp[index])
                            self._model.addConstr(y[index] + a >= tmp[index])
                            tmp[index] = y[index]
                        monomial = a
                    else:
                        index = indexes[0]
                        if index not in registers_lengths_accumulated:
                            y = self._model.addVar(vtype=GRB.BINARY)
                            z = self._model.addVar(vtype=GRB.BINARY)
                            self._model.addConstr(y <= tmp[index])
                            self._model.addConstr(z <= tmp[index])
                            self._model.addConstr(y + z >= tmp[index])
                            monomial = z
                            tmp[index] = y
                        else:
                            monomial = tmp[index]
                    polynomial += monomial
                polynomial_var = self._model.addVar(vtype=GRB.BINARY, name=f"product_{register[0]}_clock_{clock}")
                self._model.update()
                self._model.addConstr(polynomial_var == polynomial)
                new_bits.append(polynomial_var)
            self._model.update()

            new_bits = new_bits[-1:] + new_bits[:-1]
            for index, length in enumerate(registers_lengths_accumulated[:-1]):
                tmp[length] = new_bits[index]

            self._model.update()
            s[clock + 1] = []
            for index in range(output_bit_size):
                s[clock + 1].append(tmp[(index + 1) % output_bit_size])

        interm_output_vars = self._model.addVars(list(range(output_bit_size)), vtype=GRB.BINARY,
                                                 name=f"interm_{component.id}_output")
        self._model.update()
        self._variables[f"interm_{component.id}_output"] = {}
        for index, var in enumerate(interm_output_vars.values()):
            self._variables[f"interm_{component.id}_output"][index] = {"original": var, "copies": []}

        for position in range(component.output_bit_size):
            self._model.addConstr(interm_output_vars[position] == s[number_of_initialization_clocks][position])

        self._model.update()
        for position in list(self._occurences[component.id].keys()):
            self._model.addConstr(output_vars[position] == interm_output_vars[position])
            self.set_as_used_variables([interm_output_vars[position]])

        self._model.update()

    def add_not_constraints(self, component):
        output_vars = self.get_output_vars(component)
        input_vars_concat = self.get_input_vars(component)
        self._model.update()

        for index, bit_pos in enumerate(list(self._occurences[component.id].keys())):
            self._model.addConstr(output_vars[index] >= input_vars_concat[index])
            self.set_as_used_variables([input_vars_concat[index]])
        self._model.update()

    def add_constant_constraints(self, component):
        self._constants[component.id] = {}
        output_vars = self.get_output_vars(component)

        if component.description[0].startswith("0b"):
            const = int(component.description[0], 2)
        elif component.description[0].startswith("0x"):
            const = int(component.description[0], 16)
        else:
            raise ValueError("Unknown format: must start with 0b or 0x")

        for i, bit_pos in enumerate(list(self._occurences[component.id].keys())):
            if (const >> (component.output_bit_size - 1 - i)) & 1 == 0:
                self._model.addConstr(output_vars[i] == 0)
                self._constants[component.id][i] = 0
            else:
                self._constants[component.id][i] = 1
        self._model.update()

    def add_or_constraints(self, component):
        """
        The OR operation is modeled as:
            y = OR(x1, x2, ..., xn)
        Then:
            - y >= xi  for each input xi
            - y <= sum(xi)
        """
        output_vars = self.get_output_vars(component)
        output_size = component.output_bit_size

        var_inputs_per_bit = [[] for _ in range(output_size)]

        for input_idx, input_name in enumerate(component.input_id_links):
            bit_positions = component.input_bit_positions[input_idx]

            for local_idx, pos in enumerate(bit_positions):
                output_index = pos % output_size

                copy_index = len(self._variables[input_name][pos]["copies"])
                copy_var = self._model.addVar(
                    vtype=GRB.BINARY,
                    name=f"copy_{copy_index}_{input_name}[{pos}]"
                )
                self._variables[input_name][pos]["copies"].append(copy_var)
                var_inputs_per_bit[output_index].append(copy_var)

        self._model.update()

        for bit_idx in range(output_size):
            input_vars = var_inputs_per_bit[bit_idx]
            output_var = output_vars[bit_idx]

            if not input_vars:
                continue

            for v in input_vars:
                self._model.addConstr(output_var >= v)
            self._model.addConstr(output_var <= sum(input_vars))
            self.set_as_used_variables(input_vars)
        self._model.update()

    def add_intermediate_output_constraints(self, component):
        output_vars = self.get_output_vars(component)
        input_vars_concat = self.get_input_vars(component)
        self._model.update()

        for index, bit_pos in enumerate(list(self._occurences[component.id].keys())):
            self._model.addConstr(output_vars[index] == input_vars_concat[bit_pos])
            self.set_as_used_variables([input_vars_concat[bit_pos]])
        self._model.update()

    def get_cipher_output_component_id(self):
        for component in self._cipher.get_all_components():
            if component.type == "cipher_output":
                return component.id

    def add_constraints(self, predecessors, input_id_link_needed, block_needed):
        self.build_gurobi_model()
        self.create_gurobi_vars_from_all_components(predecessors, input_id_link_needed, block_needed)

        used_predecessors_sorted = self.order_predecessors(list(self._occurences.keys()))
        self._used_predecessors_sorted = used_predecessors_sorted
        for component_id in used_predecessors_sorted:
            if component_id not in self._cipher.inputs:
                component = self._cipher.get_component_from_id(component_id)
                print(f"---> {component.id}") if verbosity else None
                if component.type == "sbox":
                    self.add_sbox_constraints(component)
                elif component.type == "fsr":
                    self.add_fsr_constraints(component)
                elif component.type == "constant":
                    self.add_constant_constraints(component)
                elif component.type in ["linear_layer", "mix_column"]:
                    self.add_linear_layer_constraints(component)
                elif component.type in ["cipher_output", "intermediate_output"]:
                    self.add_intermediate_output_constraints(component)
                elif component.type == "word_operation":
                    if component.description[0] == "XOR":
                        self.add_xor_constraints(component)
                    elif component.description[0] == "ROTATE":
                        self.add_rotate_constraints(component)
                    elif component.description[0] == "SHIFT":
                        self.add_shift_constraints(component)
                    elif component.description[0] == "AND":
                        self.add_and_constraints(component)
                    elif component.description[0] == "NOT":
                        self.add_not_constraints(component)
                    elif component.description[0] == "OR":
                        self.add_or_constraints(component)
                    elif component.description[0] == "MODADD":
                        self.add_modadd_constraints(component)
                    else:
                        raise NotImplementedError(f"Component {component.description[0]} is not yet implemented")
                else:
                    raise NotImplementedError(f"Component {component.description[0]} is not yet implemented")

        return self._model

    def get_where_component_is_used(self, predecessors, input_id_link_needed, block_needed):
        occurences = {}
        ids = self._cipher.inputs + predecessors
        for name in ids:
            for component_id in predecessors:
                component = self._cipher.get_component_from_id(component_id)
                if name in component.input_id_links:
                    indexes = [i for i, j in enumerate(component.input_id_links) if j == name]
                    if name not in occurences.keys():
                        occurences[name] = []
                    for index in indexes:
                        occurences[name].append(component.input_bit_positions[index])
        if input_id_link_needed in self._cipher.inputs:
            occurences[input_id_link_needed] = [block_needed]
        else:
            component = self._cipher.get_component_from_id(input_id_link_needed)
            occurences[input_id_link_needed] = [[i for i in range(component.output_bit_size)]]

        cipher_id = self.get_cipher_output_component_id()
        if input_id_link_needed == cipher_id:
            component = self._cipher.get_component_from_id(cipher_id)
            occurences[cipher_id] = [[i for i in range(component.output_bit_size)]]

        occurences_final = {}
        for component_id in occurences.keys():
            occurences_final[component_id] = self.find_copy_indexes(occurences[component_id])

        self._occurences = occurences_final
        return occurences_final

    def find_copy_indexes(self, input_bit_positions):
        l = {}
        for input_bit_position in input_bit_positions:
            for pos in input_bit_position:
                if pos not in l.keys():
                    l[pos] = 0
                l[pos] += 1
        return l

    def order_predecessors(self, used_predecessors):
        for component_id in self._cipher.inputs:
            if component_id in list(self._occurences.keys()):
                used_predecessors.remove(component_id)
        tmp = {}
        final = {}
        for r in range(self._cipher.number_of_rounds):
            tmp[r] = {}
            for component_id in used_predecessors:
                if int(component_id.split("_")[-2]) == r:
                    tmp[r][component_id] = int(component_id.split("_")[-1])
            final[r] = {k: v for k, v in sorted(tmp[r].items(), key=lambda item: item[1])}

        used_predecessors_sorted = []
        for r in range(self._cipher.number_of_rounds):
            used_predecessors_sorted += list(final[r].keys())

        l = []
        for component_id in self._cipher.inputs:
            if component_id in list(self._occurences.keys()):
                l.append(component_id)
        used_predecessors_sorted = l + used_predecessors_sorted
        return used_predecessors_sorted

    def create_gurobi_vars_from_all_components(self, predecessors, input_id_link_needed, block_needed):
        occurences = self.get_where_component_is_used(predecessors, input_id_link_needed, block_needed)
        all_vars = {}
        used_predecessors_sorted = self.order_predecessors(list(occurences.keys()))
        cipher_id = self.get_cipher_output_component_id()
        for component_id in used_predecessors_sorted:
            all_vars[component_id] = {}
            if component_id != cipher_id:
                for pos in list(occurences[component_id].keys()):
                    all_vars[component_id][pos] = {}
                    all_vars[component_id][pos]["original"] = self._model.addVar(vtype=GRB.BINARY,
                                                                                 name=component_id + f"[{pos}]")
                    all_vars[component_id][pos]["copies"] = []
            else:
                component = self._cipher.get_component_from_id(cipher_id)
                for pos in range(component.output_bit_size):
                    all_vars[component_id][pos] = {}
                    all_vars[component_id][pos]["original"] = self._model.addVar(vtype=GRB.BINARY,
                                                                                 name=component_id + f"[{pos}]")
                    all_vars[component_id][pos]["copies"] = []

        self._model.update()
        self._variables = all_vars

    def find_index_second_input(self):
        occurences = self._occurences
        return len(list(occurences[self._cipher.inputs[0]].keys()))

    def build_generic_model_for_specific_output_bit(self, output_bit_index, fixed_degree=None,
                                                    which_var_degree=None,
                                                    chosen_cipher_output=None):
        start = time.time()

        if chosen_cipher_output != None:
            input_id_link_needed = chosen_cipher_output
        else:
            input_id_link_needed = self.get_cipher_output_component_id()
        component = self._cipher.get_component_from_id(input_id_link_needed)
        block_needed = list(range(component.output_bit_size))
        output_bit_index_previous_comp = output_bit_index

        G = create_networkx_graph_from_input_ids(self._cipher)
        predecessors = list(_get_predecessors_subgraph(G, [input_id_link_needed]))
        for input_id in self._cipher.inputs + ['']:
            if input_id in predecessors:
                predecessors.remove(input_id)

        self.add_constraints(predecessors, input_id_link_needed, block_needed)

        var_from_block_needed = []
        for i in block_needed:
            var_from_block_needed.append(self._variables[input_id_link_needed][i]["original"])

        output_vars = self._model.addVars(list(range(len(block_needed))), vtype=GRB.BINARY, name="output")
        self._variables["output"] = output_vars
        output_vars = list(output_vars.values())
        self._model.update()

        for i in range(len(block_needed)):
            self._model.addConstr(output_vars[i] == var_from_block_needed[i])
            self.set_as_used_variables([output_vars[i], var_from_block_needed[i]])

        ks = self._model.addVar()
        self._model.addConstr(ks == sum(output_vars[i] for i in range(len(block_needed))))
        self._model.addConstr(ks == 1)
        self._model.addConstr(output_vars[output_bit_index_previous_comp] == 1)

        if fixed_degree is not None:
            if which_var_degree is not None:
                var_input_name = next(
                    (inp for inp in self._cipher.inputs if inp.startswith(which_var_degree)),
                    None
                )
                if var_input_name is None:
                    raise ValueError(f"No input found matching prefix '{which_var_degree}'")
            else:
                var_input_name = self._cipher.inputs[0]

            input_index = self._cipher.inputs.index(var_input_name)
            input_size = self._cipher.inputs_bit_size[input_index]

            vars_to_constrain = []
            for i in range(input_size):
                v = self._model.getVarByName(f"{var_input_name}[{i}]")
                if v is not None:
                    vars_to_constrain.append(v)

            self._model.addConstr(sum(vars_to_constrain) == fixed_degree,
                                  name=f"degree_{var_input_name}_{fixed_degree}")

        self.set_unused_variables_to_zero()
        self.create_all_copies()
        self._model.update()
        end = time.time()
        building_time = end - start
        if verbosity:
            print(f"########## building_time : {building_time}")
        self._model.update()

    def _prefix_for_input(self, name: str) -> str:
        return name[:1].lower()

    def get_solutions(self):
        start = time.time()
        solCount = self._model.SolCount
        inputs = []
        for prio, inp_name in enumerate(self._cipher.inputs):
            if inp_name not in self._variables:
                continue
            prefix = self._prefix_for_input(inp_name)
            for idx, d in self._variables[inp_name].items():
                inputs.append((prio, prefix, idx, d["original"]))
        inputs.sort(key=lambda t: (t[0], t[1], t[2]))

        mono_set = set()
        for sn in range(solCount):
            self._model.setParam(GRB.Param.SolutionNumber, sn)
            toks = []
            for _, prefix, idx, var in inputs:
                if var.Xn > 0.5:
                    toks.append(f"{prefix}{idx}")
            mono = "1" if not toks else "".join(toks)
            if mono in mono_set:
                mono_set.remove(mono)
            else:
                mono_set.add(mono)
        end = time.time()
        printing_time = end - start
        if verbosity:
            print('Number of solutions (might cancel each other) found: ' + str(solCount))
            print(f"########## printing_time : {printing_time}")
            print(f'Number of monomials found: {len(mono_set)}')
        monomials_list = sorted(mono_set)
        return self.anf_list_to_boolean_poly(monomials_list)

    def optimize_model(self):
        start = time.time()
        self._model.optimize()
        end = time.time()
        solving_time = end - start
        if verbosity:
            print(self._model)
            print(f"########## solving_time : {solving_time}")

    def anf_list_to_boolean_poly(self, anf_list):
        variables = []
        for index, input_name in enumerate(self._cipher.inputs):
            bit_size = self._cipher.inputs_bit_size[index]
            variables.extend([f"{input_name[0]}{i}" for i in range(bit_size)])

        B = BooleanPolynomialRing(names=variables)
        var_map = {str(v): B(str(v)) for v in variables}

        poly = B(0)
        for term in anf_list:
            if term == "1":
                term_poly = B(1)
            else:
                i = 0
                factors = []
                while i < len(term):
                    var = term[i]
                    i += 1
                    digits = ''
                    while i < len(term) and term[i].isdigit():
                        digits += term[i]
                        i += 1
                    factors.append(var_map[f"{var}{digits}"])
                term_poly = factors[0]
                for f in factors[1:]:
                    term_poly *= f
            poly += term_poly
        return poly

    def get_boolean_polynomial_ring(self):
        variables = []
        for index, input_name in enumerate(self._cipher.inputs):
            bit_size = self._cipher.inputs_bit_size[index]
            variables.extend([f"{input_name[0]}{i}" for i in range(bit_size)])
        R = BooleanPolynomialRing(names=variables)
        return R

    def var_list_to_input_positions(self, var_list):
        """
        Convert flat variable names (e.g., ``['p1', 'k8']``) into structured
        input references tied to the cipher's input components.

        Each variable name's first letter (e.g., ``'p'``, ``'k'``, ``'i'``)
        is mapped to its corresponding input (e.g., ``'plaintext'``, ``'key'``,
        ``'initialisation_vector'``), and its numeric suffix is treated as the bit index.
        For example, ``['p1', 'k8']`` → ``[('plaintext', 1), ('key', 8)]``.
        """
        input_map = {}
        for index, input_name in enumerate(self._cipher.inputs):
            bit_size = self._cipher.inputs_bit_size[index]
            prefix = input_name[0]  # e.g., 'p' for plaintext, 'k' for key
            input_map[prefix] = (input_name, bit_size)

        results = []
        for var in var_list:
            prefix = var[0]
            index = int(var[1:])
            input_name, bit_size = input_map[prefix]

            if index >= bit_size:
                raise ValueError(f"Index {index} out of range for input '{input_name}' (size {bit_size})")
            results.append((input_name, index))
        return results

    def re_init(self):
        self._variables = None
        self._model = None
        self._occurences = None
        self._used_variables = []
        self._variables_as_list = []
        self._unused_variables = []
        self._used_predecessors_sorted = None
        self._constants = {}


    def find_anf_of_specific_output_bit(self, output_bit_index, fixed_degree=None, which_var_degree=None, chosen_cipher_output=None):
        """
        Build and solve the MILP model to compute the Algebraic Normal Form (ANF)
        of a specific output bit of the cipher using the Monomial Prediction (MP) approach.

        By default, the model enumerates all possible monomials contributing to the selected output bit.
        Optionally, a degree constraint can be applied to restrict the search to monomials of a fixed degree.

        INPUT:

        - ``output_bit_index`` -- **integer**; index of the ciphertext bit whose ANF is to be computed.
        - ``fixed_degree`` -- **integer** (default: ``None``); if not ``None``, only monomials
          whose degree equals this value are returned.
        - ``which_var_degree`` -- **string** (default: ``None``); prefix or full name of the input
          variable on which the degree constraint (``fixed_degree``) is applied.
          Typical values include:
            * ``"p"`` or ``"plaintext"`` for plaintext variables
            * ``"k"`` or ``"key"`` for key variables
            * ``"i"`` for initialization vector variables
          If ``None``, defaults to the first input listed in ``self._cipher.inputs``.
        - ``chosen_cipher_output`` -- **string** (default: ``None``); specify a cipher component
          ID if you want to compute the ANF for an intermediate output instead of the final cipher output.

        EXAMPLES::

            # Example 1: Compute the ANF of the first ciphertext bit in SIMON (round 1)
            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: cipher = SimonBlockCipher(number_of_rounds=1)
            sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import MilpMonomialPredictionModel
            sage: milp = MilpMonomialPredictionModel(cipher)
            sage: and = milp.find_anf_of_specific_output_bit(0)
            sage: R = milp.get_boolean_polynomial_ring()
            sage: anf == R("p1*p8 + p2 + p16 + k48")
            True

            # Example 2: Restrict the analysis to degree-2 monomials on plaintext variables
            sage: anf = milp.find_anf_of_specific_output_bit(0, fixed_degree=2, which_var_degree="p")
            sage: anf == R("p1*p8")
            True

            # Example 3: Restrict the analysis to degree-1 monomials on key variables
            sage: milp.find_anf_of_specific_output_bit(0, fixed_degree=1, which_var_degree="k")
            sage: anf == R("k48")
            True
        """

        self.build_generic_model_for_specific_output_bit(output_bit_index, fixed_degree, which_var_degree, chosen_cipher_output)
        self._model.setParam("PoolSolutions",200000000)
        self._model.setParam(GRB.Param.PoolSearchMode, 2)

        self._model.write("division_trail_model.lp")
        self.optimize_model()
        return self.get_solutions()


    def check_anf_correctness(self, output_bit_index, num_tests=10, endian="msb"):
        """
        Verify the correctness of the computed Algebraic Normal Form (ANF)
        for a specific cipher output bit by random testing.

        This method compares the value of an output bit obtained from the
        cipher evaluation and from its ANF evaluation, across several
        random input assignments.

        INPUT:

        - ``output_bit_index`` -- **integer**; index (0-based) of the output bit to test.
          The indexing direction depends on the ``endian`` parameter.
        - ``num_tests`` -- **integer** (default: ``10``); number of random input assignments
          to test.
        - ``endian`` -- **string** (default: ``"msb"``); defines how bit positions are indexed
          and extracted:
            * ``"msb"`` : bit index 0 corresponds to the most significant bit (default)
            * ``"lsb"`` : bit index 0 corresponds to the least significant bit

        OUTPUT:

        - **bool**; returns ``True`` if the ANF output matches the cipher output
          for all tested input assignments, ``False`` otherwise.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: cipher = SimonBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import MilpMonomialPredictionModel
            sage: milp = MilpMonomialPredictionModel(cipher)
            sage: milp.check_anf_correctness(0, endian="msb")
            True
        """

        # 1) Generate random test vectors for all cipher inputs
        test_vectors = []
        for _ in range(num_tests):
            assignment = {}
            for inp, size in zip(self._cipher.inputs, self._cipher.inputs_bit_size):
                assignment[inp] = secrets.randbits(size)
            test_vectors.append(assignment)

        # 2) Compute the ANF for the specified output bit
        anf_poly = self.find_anf_of_specific_output_bit(output_bit_index)
        print("ANF:", anf_poly) if verbosity else None

        B = self.get_boolean_polynomial_ring()
        # 3) Helper: evaluate the ANF polynomial for a given input assignment
        def evaluate_poly(assignments):
            var_values = {}
            for inp, size in zip(self._cipher.inputs, self._cipher.inputs_bit_size):
                val = assignments[inp]
                for i in range(size):
                    if endian == "msb":
                        # MSB-first: inp0 = MSB, inp{n-1} = LSB
                        bit = (val >> (size - 1 - i)) & 1
                    elif endian == "lsb":
                        # LSB-first: inp0 = LSB, inp{n-1} = MSB
                        bit = (val >> i) & 1
                    else:
                        raise ValueError("Invalid endian value. Use 'msb' or 'lsb'.")
                    var_values[f"{inp[0]}{i}"] = bit
            return int(GF(2)(anf_poly(**var_values)))

        # 4) Evaluate and compare ANF vs cipher outputs
        output_size = self._cipher.output_bit_size
        for trial, assign in enumerate(test_vectors):
            print(f"trial = {trial}") if verbosity else None
            cipher_output = self._cipher.evaluate(
                [assign[inp] for inp in self._cipher.inputs]
            )
            if endian == "msb":
                real_index = output_size - 1 - output_bit_index
            else:
                real_index = output_bit_index

            expected_bit = (cipher_output >> real_index) & 1
            computed_bit = evaluate_poly(assign)

            if expected_bit != computed_bit:
                return False
        return True


    def find_superpoly_of_specific_output_bit(self, cube, output_bit_index, chosen_cipher_output=None):
        """
        Compute the superpoly of a specific cipher output bit under a given cube.

        INPUT:

        - ``cube`` -- **list of strings**; variable names forming the cube.
          Each variable follows the convention:
            * ``"i"`` prefix for IV bits
            * ``"p"`` prefix for plaintext bits
          Example: ``["i9", "i19", "i29", "i39", "i49", "i59", "i69", "i79"]``.
        - ``output_bit_index`` -- **integer**; index (0-based, counting from the most significant bit)
          of the cipher output bit for which the superpoly is computed.
        - ``chosen_cipher_output`` -- **string** (default: ``None``); specify a cipher component
          ID if the computation targets an intermediate output instead of the final cipher output.

        OUTPUT:

        - **BooleanPolynomial**; the resulting superpoly polynomial in the Boolean ring.

        EXAMPLES::

            sage: from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher
            sage: cipher = TriviumStreamCipher(keystream_bit_len=1, number_of_initialization_clocks=590)
            sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import MilpMonomialPredictionModel
            sage: milp = MilpMonomialPredictionModel(cipher)
            sage: cube = ["i9", "i19", "i29", "i39", "i49", "i59", "i69", "i79"]
            sage: superpoly = milp.find_superpoly_of_specific_output_bit(cube, output_bit_index=0)
            sage: R = milp.get_boolean_polynomial_ring()
            sage: superpoly == R("k20*i60*i61 + k20*i60*i74 + k20*i60 + k20*i73 + i8*i60*i61 + i8*i60*i74 + i8*i60 + i8*i73 + i60*i61*i71 + i60*i61*i72*i73 + i60*i71*i74 + i60*i71 + i60*i72*i73*i74 + i60*i72*i73 + i71*i73 + i72*i73")
            True
        """

        fixed_degree = None
        which_var_degree = None
        self.build_generic_model_for_specific_output_bit(output_bit_index, fixed_degree, which_var_degree, chosen_cipher_output)
        self._model.setParam("PoolSolutions", 200000000)
        self._model.setParam(GRB.Param.PoolSearchMode, 2)

        # Convert compact cube names like "i9" -> ("initialisation_vector", 9)
        cube_verbose = self.var_list_to_input_positions(cube)

        for term in cube_verbose:
            var_term = self._model.getVarByName(f"{term[0]}[{term[1]}]")
            self._model.update()
            self._model.addConstr(var_term == 1)

        self._model.update()
        self._model.write("division_trail_model.lp")

        self.optimize_model()
        poly = self.get_solutions()

        assignments = {v: 1 for v in cube}
        poly_sub = poly.subs(assignments)
        return poly_sub


    def find_upper_bound_degree_of_specific_output_bit(self, output_bit_index, which_var_degree=None, chosen_cipher_output=None):
        """
        Compute an upper bound on the algebraic degree of a specific cipher output bit
        with respect to a chosen input variable (e.g., key, IV, or plaintext).

        INPUT:

        - ``output_bit_index`` -- **integer**; index (0-based, counting from the most significant bit)
          of the cipher output bit to analyze.
        - ``which_var_degree`` -- **string** (default: ``None``); prefix identifying which
          input the algebraic degree should be computed over:
            * ``"k"`` → degree with respect to key bits
            * ``"p"`` → degree with respect to plaintext bits
            * ``"i"`` → degree with respect to IV bits
          If ``None`` (default), the first input listed in ``self._cipher.inputs`` is used.
        - ``chosen_cipher_output`` -- **string** (default: ``None``); specify a cipher component
          ID if the computation targets an intermediate output instead of the final cipher output.

        OUTPUT:

        - **integer**; upper bound on the algebraic degree of the selected output bit
          with respect to the chosen input variable group.

        EXAMPLES::

            sage: from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher
            sage: cipher = TriviumStreamCipher(keystream_bit_len=1, number_of_initialization_clocks=508)
            sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import MilpMonomialPredictionModel
            sage: milp = MilpMonomialPredictionModel(cipher)
            sage: milp.find_upper_bound_degree_of_specific_output_bit(0, which_var_degree="i")
            14
        """

        fixed_degree = None
        self.build_generic_model_for_specific_output_bit(output_bit_index, fixed_degree, which_var_degree, chosen_cipher_output)

        self._model.setParam(GRB.Param.PoolSearchMode, 0)  # single optimal solution (fastest)
        self._model.setParam("MIPGap", 0)
        self._model.Params.OutputFlag = 0

        if which_var_degree is None:
            target_inputs = [(self._cipher.inputs[0], self._cipher.inputs_bit_size[0])]
        else:
            target_inputs = [
                (inp, size)
                for inp, size in zip(self._cipher.inputs, self._cipher.inputs_bit_size)
                if inp.startswith(which_var_degree)
            ]

        vars_target = []
        for inp, size in target_inputs:
            for i in range(size):
                var = self._model.getVarByName(f"{inp}[{i}]")
                if var is not None:
                    vars_target.append(var)

        self._model.setObjective(sum(vars_target), GRB.MAXIMIZE)
        self._model.update()
        self._model.write("degree_upper_bound.lp")

        self.optimize_model()
        degree_upper_bound = int(round(self._model.getObjective().getValue()))
        return degree_upper_bound


    def find_exact_degree_of_specific_output_bit(self, output_bit_index, which_var_degree=None, chosen_cipher_output=None):
        """
        Compute the exact algebraic degree of a specific cipher output bit
        with respect to a chosen input variable group (e.g., key, IV, or plaintext).

        Unlike the upper-bound computation, this method enumerates all optimal MILP
        solutions corresponding to maximal-degree monomials and checks their parity
        (mod 2). The exact algebraic degree is the highest degree for which the number
        of monomials with that degree is odd.

        INPUT:

        - ``output_bit_index`` -- **integer**; index (0-based, counting from the most significant bit)
          of the cipher output bit to analyze.
        - ``which_var_degree`` -- **string** (default: ``None``); prefix identifying which
          input group the algebraic degree should be computed over:
            * ``"k"`` → degree with respect to key bits
            * ``"p"`` → degree with respect to plaintext bits
            * ``"i"`` → degree with respect to IV bits
          If ``None`` (default), the first input listed in ``self._cipher.inputs`` is used.
        - ``chosen_cipher_output`` -- **string** (default: ``None``); specify a cipher component
          ID if the computation targets an intermediate output instead of the final cipher output.

        OUTPUT:

        - **integer**; exact algebraic degree of the selected output bit with respect to
          the chosen input variable group.

        EXAMPLES::

            sage: from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher
            sage: cipher = TriviumStreamCipher(keystream_bit_len=1, number_of_initialization_clocks=508)
            sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import MilpMonomialPredictionModel
            sage: milp = MilpMonomialPredictionModel(cipher)
            sage: milp.find_exact_degree_of_specific_output_bit(0, which_var_degree="i")
            13
        """

        fixed_degree = None
        self.build_generic_model_for_specific_output_bit(output_bit_index, fixed_degree, which_var_degree, chosen_cipher_output)

        m = self._model
        m.Params.OutputFlag = 0
        m.setParam(GRB.Param.PoolSearchMode, 2)         # enumerate all optimal solutions
        m.setParam(GRB.Param.PoolSolutions, 200000000)  # large enough for enumeration
        m.setParam(GRB.Param.PoolGap, 0.0)              # ensure only optimal solutions are put in the Pool

        if which_var_degree is None:
            target_inputs = [(self._cipher.inputs[0], self._cipher.inputs_bit_size[0])]
        else:
            target_inputs = [
                (inp, size)
                for inp, size in zip(self._cipher.inputs, self._cipher.inputs_bit_size)
                if inp.startswith(which_var_degree)
            ]

        vars_target = []
        for inp, size in target_inputs:
            for i in range(size):
                var = m.getVarByName(f"{inp}[{i}]")
                if var is not None:
                    vars_target.append(var)

        m.setObjective(sum(vars_target), GRB.MAXIMIZE)
        m.update()
        m.optimize()

        if m.Status != GRB.OPTIMAL:
            print("Model infeasible or not optimal.")
            return 0

        d = int(round(m.ObjVal))
        if d <= 0:
            return 0

        # Gather all distinct monomials of degree d and compute parity
        monomial_parity = {}
        for s in range(m.SolCount):
            m.Params.SolutionNumber = s
            active_indices = tuple(i for i, v in enumerate(vars_target) if v.Xn > 0.5)
            if len(active_indices) == d:
                monomial_parity[active_indices] = monomial_parity.get(active_indices, 0) ^ 1

        if any(val == 1 for val in monomial_parity.values()):
            exact_degree = d
        else:
            exact_degree = d - 1
        return exact_degree


    def find_upper_bound_degree_of_all_output_bits(self, which_var_degree=None, chosen_cipher_output=None):
        """
        Compute the upper bound on the algebraic degree for all cipher output bits.

        INPUT:

        - ``which_var_degree`` -- **string** (default: ``None``); prefix indicating which
          variable group the degree should be computed over:
            * ``"k"`` → key bits
            * ``"p"`` → plaintext bits
            * ``"i"`` → IV bits
          If ``None`` (default), the degree is computed with respect to the first input
          listed in ``self._cipher.inputs``.
        - ``chosen_cipher_output`` -- **string** (default: ``None``); specify a cipher
          component ID if the computation targets an intermediate output (e.g., after a
          given round) instead of the final cipher output.

        OUTPUT:

        - **list of integers**; upper bounds on the algebraic degrees of all cipher output bits.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: cipher = SimonBlockCipher(number_of_rounds=4)
            sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import MilpMonomialPredictionModel
            sage: milp = MilpMonomialPredictionModel(cipher)
            sage: milp.find_upper_bound_degree_of_all_output_bits(which_var_degree="p") # doctest: +SKIP
            ...
        """

        degrees = []
        for i in range(self._cipher.output_bit_size):
            self.re_init()
            degree = self.find_upper_bound_degree_of_specific_output_bit(
                i, which_var_degree=which_var_degree, chosen_cipher_output=chosen_cipher_output
            )
            degrees.append(degree)
        return degrees


    def find_exact_degree_of_all_output_bits(self, which_var_degree=None, chosen_cipher_output=None):
        """
        Compute the exact algebraic degree for all cipher output bits.

        INPUT:

        - ``which_var_degree`` -- **string** (default: ``None``); prefix indicating which
          variable group the algebraic degree should be computed over:
            * ``"k"`` → key bits
            * ``"p"`` → plaintext bits
            * ``"i"`` → IV bits
          If ``None`` (default), the degree is computed with respect to the first input
          listed in ``self._cipher.inputs``.
        - ``chosen_cipher_output`` -- **string** (default: ``None``); specify a cipher
          component ID if the computation targets an intermediate output instead of the final cipher output.

        OUTPUT:

        - **list of integers**; exact algebraic degrees of all cipher output bits.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: cipher = SimonBlockCipher(number_of_rounds=4)
            sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import MilpMonomialPredictionModel
            sage: milp = MilpMonomialPredictionModel(cipher)
            sage: milp.find_exact_degree_of_all_output_bits(which_var_degree="p") # doctest: +SKIP
            ...
        """

        degrees = []
        for i in range(self._cipher.output_bit_size):
            self.re_init()
            degree = self.find_upper_bound_degree_of_specific_output_bit(
                i, which_var_degree=which_var_degree, chosen_cipher_output=chosen_cipher_output
            )
            degrees.append(degree)
        return degrees
