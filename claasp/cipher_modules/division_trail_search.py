
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
from sage.crypto.sbox import SBox
from collections import Counter
from sage.rings.polynomial.pbori.pbori import BooleanPolynomialRing
from claasp.cipher_modules.graph_generator import create_networkx_graph_from_input_ids, _get_predecessors_subgraph
from claasp.cipher_modules.component_analysis_tests import binary_matrix_of_linear_component
from gurobipy import Model, GRB, Env
import os

verbosity = False

class MilpDivisionTrailModel():
    """

    Given a number of rounds of a chosen cipher and a chosen output bit, this module produces a model that can either:
    - obtain the ANF of this chosen output bit,
    - find the degree of this ANF,
    - or check the presence or absence of a specified monomial.

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
        self._output_id = None
        self._output_bit_index_previous_comp = None
        self._block_needed = None
        self._input_id_link_needed = None

    def get_all_variables_as_list(self):
        for component_id in list(self._variables.keys())[:-1]:
            for bit_position in self._variables[component_id].keys():
                for value in self._variables[component_id][bit_position].keys():
                    if value != "current":
                        varname = self._variables[component_id][bit_position][value].VarName
                        if varname not in self._variables_as_list:  # rot and intermediate has the same name than original
                            self._variables_as_list.append(varname)

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
        for v in variables:
            if v.VarName not in self._used_variables:
                self._used_variables.append(v.VarName)
                if "copy" in v.VarName.split("_"):
                    tmp1 = v.VarName.split("_")[2:]
                    tmp2 = "_".join(tmp1)
                    self._used_variables.append(tmp2)

    def build_gurobi_model(self):
        env = Env(empty=True)
        env.setParam('ComputeServer', "10.191.12.120")
        env.start()
        # Create a new model
        model = Model("basic_model", env=env)
        # model = Model()
        model.Params.LogToConsole = 0
        # model.Params.Threads = 16
        self._model = model

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

    def add_xor_constraints(self, component):
        output_vars = self.get_output_vars(component)

        input_vars_concat = []
        constant_flag = []
        for index, input_name in enumerate(component.input_id_links):
            for pos in component.input_bit_positions[index]:
                current = self._variables[input_name][pos]["current"]
                if input_name[:8] == "constant":
                    const_comp = self._cipher.get_component_from_id(input_name)
                    constant_flag.append(
                        (int(const_comp.description[0], 16) >> (const_comp.output_bit_size - 1 - pos)) & 1)
                else:
                    input_vars_concat.append(self._variables[input_name][pos][current])
                    self._variables[input_name][pos]["current"] += 1

        block_size = component.output_bit_size
        nb_blocks = component.description[1]
        if constant_flag != []:
            nb_blocks -= 1
        for index, bit_pos in enumerate(list(self._occurences[component.id].keys())):
            constr = 0
            for j in range(nb_blocks):
                constr += input_vars_concat[index + block_size * j]
                self.set_as_used_variables([input_vars_concat[index + block_size * j]])
            if (constant_flag != []) and (constant_flag[index]):
                self._model.addConstr(output_vars[index] >= constr)
            else:
                self._model.addConstr(output_vars[index] == constr)
        self._model.update()

    def create_copies(self, nb_copies, var_to_copy):
        copies = self._model.addVars(list(range(nb_copies)), vtype=GRB.BINARY)
        for i in range(nb_copies):
            self._model.addConstr(var_to_copy >= copies[i])
        self._model.addConstr(sum(copies[i] for i in range(nb_copies)) >= var_to_copy)
        self._model.update()
        return list(copies.values())

    def get_output_vars(self, component):
        output_vars = []
        tmp = list(self._occurences[component.id].keys())
        tmp.sort()
        for i in tmp:
            output_vars.append(self._model.getVarByName(f"{component.id}[{i}]"))
        return output_vars

    def get_input_vars(self, component):
        input_vars_concat = []
        for index, input_name in enumerate(component.input_id_links):
            for pos in component.input_bit_positions[index]:
                current = self._variables[input_name][pos]["current"]
                input_vars_concat.append(self._variables[input_name][pos][current])
                self._variables[input_name][pos]["current"] += 1
        return input_vars_concat

    def add_modadd_constraints(self, component):
        # constraints are taken from https://www.iacr.org/archive/asiacrypt2017/106240224/106240224.pdf
        output_vars = self.get_output_vars(component)

        input_vars_concat = []
        for index, input_name in enumerate(component.input_id_links):
            for pos in component.input_bit_positions[index]:
                current = self._variables[input_name][pos]["current"]
                input_vars_concat.append(self._variables[input_name][pos][current])
                self._variables[input_name][pos]["current"] += 1
                self.set_as_used_variables([self._variables[input_name][pos][current]])

        len_concat = len(input_vars_concat)
        n = int(len_concat / 2)
        copies = {"a": {}, "b": {}}
        copies["a"][n - 1] = self.create_copies(2, input_vars_concat[n - 1])
        copies["b"][n - 1] = self.create_copies(2, input_vars_concat[len_concat - 1])
        self._model.addConstr(output_vars[n - 1] == copies["a"][n - 1][0] + copies["b"][n - 1][0])

        v = [self._model.addVar()]
        self._model.addConstr(v[0] == copies["a"][n - 1][1])
        self._model.addConstr(v[0] == copies["b"][n - 1][1])

        g0, r0 = self.create_copies(2, v[0])
        g = [g0]
        r = [r0]
        m = []
        q = []
        w = []

        copies["a"][n - 2] = self.create_copies(3, input_vars_concat[n - 2])
        copies["b"][n - 2] = self.create_copies(3, input_vars_concat[len_concat - 2])

        for i in range(2, n - 1):
            self._model.addConstr(output_vars[n - i] == copies["a"][n - i][0] + copies["b"][n - i][0] + g[i - 2])
            v.append(self._model.addVar())
            self._model.addConstr(v[i - 1] == copies["a"][n - i][1])
            self._model.addConstr(v[i - 1] == copies["b"][n - i][1])
            m.append(self._model.addVar())
            self._model.addConstr(m[i - 2] == copies["a"][n - i][2] + copies["b"][n - i][2])
            q.append(self._model.addVar())
            self._model.addConstr(q[i - 2] == m[i - 2])
            self._model.addConstr(q[i - 2] == r[i - 2])
            w.append(self._model.addVar())
            self._model.addConstr(w[i - 2] == v[i - 1] + q[i - 2])
            g_i_1, r_i_1 = self.create_copies(2, w[i - 2])
            g.append(g_i_1)
            r.append(r_i_1)
            copies["a"][n - i - 1] = self.create_copies(3, input_vars_concat[n - i - 1])
            copies["b"][n - i - 1] = self.create_copies(3, input_vars_concat[len_concat - i - 1])

        self._model.addConstr(output_vars[1] == copies["a"][1][0] + copies["b"][1][0] + g[n - 3])
        v.append(self._model.addVar())
        self._model.addConstr(v[n - 2] == copies["a"][1][1])
        self._model.addConstr(v[n - 2] == copies["b"][1][1])
        m.append(self._model.addVar())
        self._model.addConstr(m[n - 3] == copies["a"][1][2] + copies["b"][1][2])
        q.append(self._model.addVar())
        self._model.addConstr(q[n - 3] == m[n - 3])
        self._model.addConstr(q[n - 3] == r[n - 3])
        w.append(self._model.addVar())
        self._model.addConstr(w[n - 3] == v[n - 2] + q[n - 3])
        self._model.addConstr(output_vars[0] == input_vars_concat[0] + input_vars_concat[n] + w[n - 3])
        self._model.update()

    def add_and_constraints(self, component):
        # Constraints taken from Misuse-free paper
        output_vars = self.get_output_vars(component)
        input_vars_concat = self.get_input_vars(component)

        block_size = int(len(input_vars_concat) // component.description[1])
        for index, bit_pos in enumerate(list(self._occurences[component.id].keys())):
            self._model.addConstr(output_vars[index] == input_vars_concat[index])
            self._model.addConstr(output_vars[index] == input_vars_concat[index + block_size])
            self.set_as_used_variables([input_vars_concat[index], input_vars_concat[index + block_size]])
        self._model.update()

    def add_not_constraints(self, component):
        output_vars = self.get_output_vars(component)
        input_vars_concat = self.get_input_vars(component)

        for index, bit_pos in enumerate(list(self._occurences[component.id].keys())):
            self._model.addConstr(output_vars[index] >= input_vars_concat[index])
            self.set_as_used_variables([input_vars_concat[index]])
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
                if component.type == "sbox":
                    self.add_sbox_constraints(component)
                elif component.type in ["linear_layer", "mix_column"]:
                    self.add_linear_layer_constraints(component)
                elif component.type in ["cipher_output", "constant", "intermediate_output"]:
                    continue
                elif component.type == "word_operation":
                    if component.description[0] == "XOR":
                        self.add_xor_constraints(component)
                    elif component.description[0] == "ROTATE":
                        continue
                    elif component.description[0] == "AND":
                        self.add_and_constraints(component)
                    elif component.description[0] == "NOT":
                        self.add_not_constraints(component)
                    elif component.description[0] == "MODADD":
                        self.add_modadd_constraints(component)
                else:
                    print(f"---> {component.id} not yet implemented")

        return self._model

    def get_where_component_is_used(self, predecessors, input_id_link_needed, block_needed):
        occurences = {}
        ids = self._cipher.inputs + predecessors
        for name in ids:
            for component_id in predecessors:
                component = self._cipher.get_component_from_id(component_id)
                if (name in component.input_id_links) and (component.type not in ["cipher_output"]):
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
        for component_id in used_predecessors_sorted:
            all_vars[component_id] = {}
            # We need the inputs vars to be the first ones defined by gurobi in order to find their values with X.values method.
            # That's why we split the following loop: we first created the original vars, and then the copies vars when necessary.
            if component_id[:3] == "rot":
                component = self._cipher.get_component_from_id(component_id)
                rotate_offset = component.description[1]
                tmp = []
                for index, input_id_link in enumerate(component.input_id_links):
                    for j, pos in enumerate(component.input_bit_positions[index]):
                        current = all_vars[input_id_link][pos]["current"]
                        tmp.append(all_vars[input_id_link][pos][current])
                        all_vars[input_id_link][pos]["current"] += 1

                tmp2 = []
                for j in range(len(tmp)):
                    all_vars[component_id][j] = {}
                    all_vars[component_id][j][0] = tmp[(j - rotate_offset) % component.output_bit_size]
                    tmp2.append(all_vars[component_id][j][0])
                    all_vars[component_id][j]["current"] = 0

                for pos, gurobi_var in enumerate(tmp2):
                    if pos in list(occurences[component_id].keys()):
                        nb_copies_needed = occurences[component_id][pos]
                        if nb_copies_needed >= 2:
                            all_vars[component_id][pos]["current"] = 1
                            for i in range(nb_copies_needed):
                                all_vars[component_id][pos][i + 1] = self._model.addVar(vtype=GRB.BINARY,
                                                                                        name=f"copy_{i + 1}_" + gurobi_var.VarName)
                                self._model.addConstr(
                                    all_vars[component_id][pos][0] >= all_vars[component_id][pos][i + 1])
                            self._model.addConstr(
                                sum(all_vars[component_id][pos][i + 1] for i in range(nb_copies_needed)) >=
                                all_vars[component_id][pos][0])
            elif component_id[:5] == "inter":
                component = self._cipher.get_component_from_id(component_id)
                tmp = []
                for index, input_id_link in enumerate(component.input_id_links):
                    for j, pos in enumerate(component.input_bit_positions[index]):
                        current = all_vars[input_id_link][pos]["current"]
                        tmp.append(all_vars[input_id_link][pos][current])
                        all_vars[input_id_link][pos]["current"] += 1

                for j in range(len(tmp)):
                    all_vars[component_id][j] = {}
                    all_vars[component_id][j][0] = tmp[j]
                    all_vars[component_id][j]["current"] = 0

                for pos, gurobi_var in enumerate(tmp):
                    if pos in list(occurences[component_id].keys()):
                        nb_copies_needed = occurences[component_id][pos]
                        if nb_copies_needed >= 2:
                            all_vars[component_id][pos]["current"] = 1
                            for i in range(nb_copies_needed):
                                all_vars[component_id][pos][i + 1] = self._model.addVar(vtype=GRB.BINARY,
                                                                                        name=f"copy_{i + 1}_" + gurobi_var.VarName)
                                self._model.addConstr(
                                    all_vars[component_id][pos][0] >= all_vars[component_id][pos][i + 1])
                            self._model.addConstr(
                                sum(all_vars[component_id][pos][i + 1] for i in range(nb_copies_needed)) >=
                                all_vars[component_id][pos][0])
            else:
                for pos in list(occurences[component_id].keys()):
                    all_vars[component_id][pos] = {}
                    all_vars[component_id][pos][0] = self._model.addVar(vtype=GRB.BINARY,
                                                                        name=component_id + f"[{pos}]")
                    all_vars[component_id][pos]["current"] = 0
                for pos in list(occurences[component_id].keys()):
                    nb_copies_needed = occurences[component_id][pos]
                    if nb_copies_needed >= 2:
                        all_vars[component_id][pos]["current"] = 1
                        for i in range(nb_copies_needed):
                            all_vars[component_id][pos][i + 1] = self._model.addVar(vtype=GRB.BINARY,
                                                                                    name=f"copy_{i + 1}_" + component_id + f"[{pos}]")
                            self._model.addConstr(all_vars[component_id][pos][0] >= all_vars[component_id][pos][i + 1])
                        self._model.addConstr(
                            sum(all_vars[component_id][pos][i + 1] for i in range(nb_copies_needed)) >=
                            all_vars[component_id][pos][0])
            self._model.update()

        self._model.update()
        # print("all_vars")
        # print(all_vars)
        self._model.update()
        self._variables = all_vars

    def find_index_second_input(self):
        occurences = self._occurences
        count = 0
        for pos in list(occurences[self._cipher.inputs[0]].keys()):
            if occurences[self._cipher.inputs[0]][pos] > 1:
                count += occurences[self._cipher.inputs[0]][pos] + 1
            else:
                count += occurences[self._cipher.inputs[0]][pos]
        return count

    def get_output_bit_index_previous_component(self, output_bit_index_ciphertext, chosen_cipher_output=None):
        if chosen_cipher_output != None:
            pivot = 0
            for comp in self._cipher.get_all_components():
                for index, id_link in enumerate(comp.input_id_links):
                    if chosen_cipher_output == id_link:
                        output_id = comp.id
                        block_needed = comp.input_bit_positions[index]
                        input_id_link_needed = chosen_cipher_output
                        output_bit_index_previous_comp = output_bit_index_ciphertext
                        return output_id, output_bit_index_previous_comp, block_needed, input_id_link_needed, pivot
        else:
            output_id = self.get_cipher_output_component_id()
            component = self._cipher.get_component_from_id(output_id)
            pivot = 0
            output_bit_index_previous_comp = output_bit_index_ciphertext
            for index, block in enumerate(component.input_bit_positions):
                if pivot <= output_bit_index_ciphertext < pivot + len(block):
                    output_bit_index_previous_comp = block[output_bit_index_ciphertext - pivot]
                    block_needed = block
                    input_id_link_needed = component.input_id_links[index]
                    break
                pivot += len(block)

            if input_id_link_needed[:5] == "inter":
                pivot = 0
                component_inter = self._cipher.get_component_from_id(input_id_link_needed)
                for index, block in enumerate(component_inter.input_bit_positions):
                    if pivot <= block_needed[output_bit_index_previous_comp] < pivot + len(block):
                        output_bit_index_before_inter = block[block_needed[output_bit_index_previous_comp] - pivot]
                        input_id_link_needed = component_inter.input_id_links[index]
                        block_needed = block
                        break
                    pivot += len(block)
                output_bit_index_previous_comp = output_bit_index_before_inter
            return output_id, output_bit_index_previous_comp, block_needed, input_id_link_needed, pivot

    def build_generic_model_for_specific_output_bit(self, output_bit_index_ciphertext, fixed_degree=None,
                                                    chosen_cipher_output=None):
        start = time.time()
        output_id, output_bit_index_previous_comp, block_needed, input_id_link_needed, pivot = self.get_output_bit_index_previous_component(
            output_bit_index_ciphertext, chosen_cipher_output)

        self._output_id = output_id
        self._output_bit_index_previous_comp = output_bit_index_previous_comp
        self._block_needed = block_needed
        self._input_id_link_needed = input_id_link_needed

        G = create_networkx_graph_from_input_ids(self._cipher)
        predecessors = list(_get_predecessors_subgraph(G, [input_id_link_needed]))
        for input_id in self._cipher.inputs + ['']:
            if input_id in predecessors:
                predecessors.remove(input_id)

        self.add_constraints(predecessors, input_id_link_needed, block_needed)

        var_from_block_needed = []
        for i in block_needed:
            var_from_block_needed.append(self._variables[input_id_link_needed][i][0])

        output_vars = self._model.addVars(list(range(pivot, pivot + len(block_needed))), vtype=GRB.BINARY,
                                          name=output_id)
        self._variables[output_id] = output_vars
        output_vars = list(output_vars.values())
        self._model.update()

        for i in range(len(block_needed)):
            self._model.addConstr(output_vars[i] == var_from_block_needed[i])
            self.set_as_used_variables([output_vars[i], var_from_block_needed[i]])

        ks = self._model.addVar()
        self._model.addConstr(ks == sum(output_vars[i] for i in range(len(block_needed))))
        self._model.addConstr(ks == 1)
        self._model.addConstr(output_vars[output_bit_index_previous_comp] == 1)

        if fixed_degree != None:
            plaintext_vars = []
            for i in range(
                    self._cipher.inputs_bit_size[0]):  # Carreful, here we are assuming that input[0] is the plaintext
                plaintext_vars.append(self._model.getVarByName(f"plaintext[{i}]"))
            self._model.addConstr(
                sum(plaintext_vars[i] for i in range(self._cipher.inputs_bit_size[0])) == fixed_degree)

        self.set_unused_variables_to_zero()
        self._model.update()
        end = time.time()
        building_time = end - start
        if verbosity:
            print(f"########## building_time : {building_time}")
        self._model.update()

    def get_solutions(self):
        start = time.time()
        index_second_input = self.find_index_second_input()
        nb_inputs_used = 0
        for input_id in self._cipher.inputs:
            if input_id in list(self._occurences.keys()):
                nb_inputs_used += 1
        if nb_inputs_used == 2:
            max_input_bit_pos = index_second_input + len(list(self._occurences[self._cipher.inputs[1]].keys()))
            first_input_bit_positions = list(self._occurences[self._cipher.inputs[0]].keys())
            second_input_bit_positions = list(self._occurences[self._cipher.inputs[1]].keys())
        else:
            max_input_bit_pos = index_second_input
            first_input_bit_positions = list(self._occurences[self._cipher.inputs[0]].keys())

        solCount = self._model.SolCount
        monomials = []
        for sol in range(solCount):
            self._model.setParam(GRB.Param.SolutionNumber, sol)
            values = self._model.Xn

            tmp = ""
            for index, v in enumerate(values[:max_input_bit_pos]):
                if v == 1:
                    if nb_inputs_used > 1:
                        if index < len(list(self._occurences[self._cipher.inputs[0]].keys())):
                            tmp += self._cipher.inputs[0][0] + str(first_input_bit_positions[index])
                        elif index_second_input <= index < index_second_input + len(
                                list(self._occurences[self._cipher.inputs[1]].keys())):
                            tmp += self._cipher.inputs[1][0] + str(
                                second_input_bit_positions[abs(index_second_input - index)])
                    else:
                        if index < len(list(self._occurences[self._cipher.inputs[0]].keys())):
                            tmp += self._cipher.inputs[0][0] + str(first_input_bit_positions[index])
            if 1 not in values[:max_input_bit_pos]:
                tmp += str(1)
            else:
                if nb_inputs_used == 1:
                    input1_prefix = self._cipher.inputs[0][0]
                    l = tmp.split(input1_prefix)[1:]
                    sorted_l = sorted(l, key=lambda x: (x == '', int(x) if x else 0))
                    l = [''] + sorted_l
                    tmp = input1_prefix.join(l)

            if tmp in monomials:
                monomials.remove(tmp)
            else:
                monomials.append(tmp)

        end = time.time()
        printing_time = end - start
        if verbosity:
            print('Number of solutions (might cancel each other) found: ' + str(solCount))
            print(f"########## printing_time : {printing_time}")
            print(f'Number of monomials found: {len(monomials)}')
        return monomials

    def optimize_model(self):
        start = time.time()
        self._model.optimize()
        end = time.time()
        solving_time = end - start
        if verbosity:
            print(self._model)
            print(f"########## solving_time : {solving_time}")

    def find_anf_of_specific_output_bit(self, output_bit_index, fixed_degree=None, chosen_cipher_output=None):
        self.build_generic_model_for_specific_output_bit(output_bit_index, fixed_degree, chosen_cipher_output)
        self._model.setParam("PoolSolutions", 200000000)  # 200000000 to be large
        self._model.setParam(GRB.Param.PoolSearchMode, 2)
        self._model.write("division_trail_model.lp")

        self.optimize_model()
        return self.get_solutions()

    def check_presence_of_particular_monomial_in_specific_anf(self, monomial, output_bit_index, fixed_degree=None,
                                                              chosen_cipher_output=None):
        self.build_generic_model_for_specific_output_bit(output_bit_index, fixed_degree, chosen_cipher_output)
        self._model.setParam("PoolSolutions", 200000000)  # 200000000 to be large
        self._model.setParam(GRB.Param.PoolSearchMode, 2)

        for term in monomial:
            var_term = self._model.getVarByName(f"{term[0]}[{term[1]}]")
            self._model.addConstr(var_term == 1)
        self._model.update()
        self._model.write("division_trail_model.lp")

        self.optimize_model()
        return self.get_solutions()

    def check_presence_of_particular_monomial_in_all_anf(self, monomial, fixed_degree=None,
                                                         chosen_cipher_output=None):
        s = ""
        for term in monomial:
            s += term[0][0] + str(term[1])
        for i in range(self._cipher.output_bit_size):
            print(f"\nSearch of {s} in anf {i} :")
            self.check_presence_of_particular_monomial_in_specific_anf(monomial, i, fixed_degree,
                                                                       chosen_cipher_output)

    def find_degree_of_specific_output_bit(self, output_bit_index, chosen_cipher_output=None, cube_index=[]):
        fixed_degree = None
        self.build_generic_model_for_specific_output_bit(output_bit_index, fixed_degree, chosen_cipher_output)
        self._model.setParam(GRB.Param.PoolSearchMode, 1)
        self._model.setParam('Presolve', 2)
        self._model.setParam("MIPFocus", 2)
        self._model.setParam("MIPGap", 0)  # when set to 0, best solution = optimal solution
        self._model.setParam('Cuts', 2)

        index_plaintext = self._cipher.inputs.index("plaintext")
        plaintext_bit_size = self._cipher.inputs_bit_size[index_plaintext]
        p = []
        nb_plaintext_bits_used = len(list(self._occurences["plaintext"].keys()))
        for i in range(nb_plaintext_bits_used):
            p.append(self._model.getVarByName(f"plaintext[{i}]"))
        self._model.setObjective(sum(p[i] for i in range(nb_plaintext_bits_used)), GRB.MAXIMIZE)

        if cube_index:
            for i in range(plaintext_bit_size):
                if i not in cube_index:
                    self._model.addConstr(p[i] == 0)

        self._model.update()
        self._model.write("division_trail_model.lp")
        self.optimize_model()

        degree = self._model.getObjective().getValue()
        return degree

    def re_init(self):
        self._variables = None
        self._model = None
        self._occurences = None
        self._used_variables = []
        self._variables_as_list = []
        self._unused_variables = []

    def find_degree_of_all_output_bits(self, chosen_cipher_output=None):
        for i in range(self._cipher.output_bit_size):
            self.re_init()
            degree = self.find_degree_of_specific_output_bit(i, chosen_cipher_output)
            print(f"Degree of anf corresponding to output bit at position {i} = {degree}\n")
