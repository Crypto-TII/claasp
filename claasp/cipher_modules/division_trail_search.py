import time
# from gurobipy import *
from sage.crypto.sbox import SBox
from collections import Counter
from sage.rings.polynomial.pbori.pbori import BooleanPolynomialRing
from claasp.cipher_modules.graph_generator import create_networkx_graph_from_input_ids, _get_predecessors_subgraph

"""
IMPORTANT:
This module can only be used if the user possesses a Gurobi license.
In that case, please uncomment the gurobipy import.
"""

class MilpDivisionTrailModel():
    """
    EXAMPLES::

        sage: from claasp.ciphers.permutations.gaston_permutation import GastonPermutation
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: cipher = GastonPermutation(number_of_rounds=1)
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: component = cipher.get_component_from_id('sbox_0_30')
        sage: anfs = milp.get_anfs_from_sbox(component)
        sage: len(anfs)
        5

    """

    def __init__(self, cipher):
        self._cipher = cipher
        self._variables = None
        self._model = None
        self._occurences = None
        self._used_variables = []
        self._variables_as_list = []
        self._unused_variables = []

    def get_all_variables_as_list(self):
        for component_id in list(self._variables.keys())[:-1]:
            for bit_position in self._variables[component_id].keys():
                for value in self._variables[component_id][bit_position].keys():
                    if value != "current":
                        self._variables_as_list.append(self._variables[component_id][bit_position][value].VarName)

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
        model = Model()
        model.Params.LogToConsole = 0
        model.Params.Threads = 32  # best found experimentaly on ascon_sbox_2rounds
        model.setParam("PoolSolutions", 200000000)  # 200000000
        model.setParam(GRB.Param.PoolSearchMode, 2)
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
        output_vars = []
        # for i in list(self._occurences[component.id].keys()):
        tmp = list(self._occurences[component.id].keys())
        tmp.sort()
        for i in tmp:
            output_vars.append(self._model.getVarByName(f"{component.id}[{i}]"))
        # print(output_vars)

        input_vars_concat = []
        for index, input_name in enumerate(component.input_id_links):
            for pos in component.input_bit_positions[index]:
                current = self._variables[input_name][pos]["current"]
                input_vars_concat.append(self._variables[input_name][pos][current])
                self._variables[input_name][pos]["current"] += 1
        # print(input_vars_concat)
        # print(self._occurences[component.id])

        B = BooleanPolynomialRing(component.input_bit_size, 'x')
        x = B.variable_names()
        anfs = self.get_anfs_from_sbox(component)
        anfs = [B(anfs[i]) for i in range(component.input_bit_size)]
        # print(anfs)

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
            # self.set_as_used_variables([output_vars[index]])

        self._model.update()

    def add_xor_constraints(self, component):
        output_vars = []
        # print(self._occurences[component.id])
        tmp = list(self._occurences[component.id].keys())  # cannot use range(len()) because of xoodoo
        tmp.sort()
        for i in tmp:
            output_vars.append(self._model.getVarByName(f"{component.id}[{i}]"))
        # print(output_vars)

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
        # print(input_vars_concat)

        block_size = component.output_bit_size
        nb_blocks = component.description[1]
        if constant_flag != []:
            nb_blocks -= 1
        # print(list(self._occurences[component.id].keys()))
        # print(len(list(self._occurences[component.id].keys())))
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

    def add_modadd_constraints(self, component):
        # constraints are taken from https://www.iacr.org/archive/asiacrypt2017/106240224/106240224.pdf
        output_vars = []
        # for i in range(component.output_bit_size):
        tmp = list(self._occurences[component.id].keys())
        tmp.sort()
        for i in tmp:
            output_vars.append(self._model.getVarByName(f"{component.id}[{i}]"))

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

    def add_rotate_constraints(self, component):
        output_vars = []
        # for i in list(self._occurences[component.id].keys()):
        tmp = list(self._occurences[component.id].keys())
        tmp.sort()
        for i in tmp:
            output_vars.append(self._model.getVarByName(f"{component.id}[{i}]"))
        # print(output_vars)

        input_vars_concat = []
        for index, input_name in enumerate(component.input_id_links):
            for pos in component.input_bit_positions[index]:
                current = self._variables[input_name][pos]["current"]
                input_vars_concat.append(self._variables[input_name][pos][current])
                self._variables[input_name][pos]["current"] += 1
        # print(input_vars_concat)
        # print(self._occurences[component.id])
        # print(list(self._occurences[component.id].keys()))
        # print(len(list(self._occurences[component.id].keys())))

        rotate_offset = component.description[1]
        for index, bit_pos in enumerate(list(self._occurences[component.id].keys())):
            self._model.addConstr(
                output_vars[index] == input_vars_concat[(index - rotate_offset) % component.output_bit_size])
            self.set_as_used_variables([input_vars_concat[(index - rotate_offset) % component.output_bit_size]])
        self._model.update()

    def add_and_constraints(self, component):
        # Constraints taken from Misuse-free paper
        output_vars = []
        # for i in list(self._occurences[component.id].keys()):
        tmp = list(self._occurences[component.id].keys())
        tmp.sort()
        for i in tmp:
            output_vars.append(self._model.getVarByName(f"{component.id}[{i}]"))

        input_vars_concat = []
        for index, input_name in enumerate(component.input_id_links):
            for pos in component.input_bit_positions[index]:
                current = self._variables[input_name][pos]["current"]
                input_vars_concat.append(self._variables[input_name][pos][current])
                self._variables[input_name][pos]["current"] += 1

        block_size = int(len(input_vars_concat) // component.description[1])
        for index, bit_pos in enumerate(list(self._occurences[component.id].keys())):
            self._model.addConstr(output_vars[index] == input_vars_concat[index])
            self._model.addConstr(output_vars[index] == input_vars_concat[index + block_size])
            self.set_as_used_variables([input_vars_concat[index], input_vars_concat[index + block_size]])
        self._model.update()

    def add_not_constraints(self, component):
        output_vars = []
        # for i in list(self._occurences[component.id].keys()):
        tmp = list(self._occurences[component.id].keys())
        tmp.sort()
        for i in tmp:
            output_vars.append(self._model.getVarByName(f"{component.id}[{i}]"))

        input_vars_concat = []
        for index, input_name in enumerate(component.input_id_links):
            for pos in component.input_bit_positions[index]:
                current = self._variables[input_name][pos]["current"]
                input_vars_concat.append(self._variables[input_name][pos][current])
                self._variables[input_name][pos]["current"] += 1

        for index, bit_pos in enumerate(list(self._occurences[component.id].keys())):
            self._model.addConstr(output_vars[index] >= input_vars_concat[index])
            self.set_as_used_variables([input_vars_concat[index]])
        self._model.update()

    def add_constant_constraints(self, component):
        output_vars = []
        for i in range(component.output_bit_size):
            output_vars.append(self._model.getVarByName(f"{component.id}[{i}]"))

        const = int(component.description[0], 16)
        for i in range(component.output_bit_size):
            self._model.addConstr(output_vars[i] == (const >> (component.output_bit_size - 1 - i)) & 1)
        self._model.update()

    def add_cipher_output_constraints(self, component):
        input_vars = {}
        for index, input_name in enumerate(component.input_id_links):
            if input_name not in input_vars.keys():
                input_vars[input_name] = []
            for i in component.input_bit_positions[index]:
                input_vars[input_name].append(self._model.getVarByName(input_name + f"[{i}]"))
        output_vars = self._model.addVars(list(range(component.output_bit_size)), vtype=GRB.BINARY, name=component.id)

        input_vars_concat = []
        for key in input_vars.keys():
            input_vars_concat += input_vars[key]

        for i in range(component.output_bit_size):
            self._model.addConstr(output_vars[i] == input_vars_concat[i])
        self._model.update()

    def add_intermediate_output_constraints(self, component):
        output_vars = []
        # for i in list(self._occurences[component.id].keys()):
        tmp = list(self._occurences[component.id].keys())
        tmp.sort()
        for i in tmp:
            output_vars.append(self._model.getVarByName(f"{component.id}[{i}]"))
        # print(output_vars)

        input_vars_concat = []
        for index, input_name in enumerate(component.input_id_links):
            for pos in component.input_bit_positions[index]:
                current = self._variables[input_name][pos]["current"]
                input_vars_concat.append(self._variables[input_name][pos][current])
                self._variables[input_name][pos]["current"] += 1
        # print(input_vars_concat)

        # print(list(self._occurences[component.id].keys()))
        for index, bit_pos in enumerate(list(self._occurences[component.id].keys())):
            self._model.addConstr(output_vars[index] == input_vars_concat[bit_pos])
            self.set_as_used_variables([input_vars_concat[bit_pos]])
        self._model.update()

    def get_cipher_output_component_id(self):
        for component in self._cipher.get_all_components():
            if component.type == "cipher_output":
                return component.id

    def pretty_print(self, monomials):
        occurences = self._occurences
        pos_second_input = self.find_index_second_input()
        print(f"pos_second_input = {pos_second_input}")
        l = []
        nb_inputs_used = 0
        for input_id in self._cipher.inputs:
            if input_id in list(self._occurences.keys()):
                nb_inputs_used += 1
        if nb_inputs_used > 1:
            first_input_bit_positions = list(self._occurences[self._cipher.inputs[0]].keys())
            second_input_bit_positions = list(self._occurences[self._cipher.inputs[1]].keys())
            for monomial in monomials:
                tmp = ""
                if len(monomial) != 1:
                    for var in monomial[:-1]:  # [:1] to remove the occurences
                        if var < len(list(self._occurences[self._cipher.inputs[0]].keys())):
                            tmp += self._cipher.inputs[0][0] + str(first_input_bit_positions[var])
                        elif pos_second_input <= var < pos_second_input + len(
                                list(self._occurences[self._cipher.inputs[1]].keys())):
                            tmp += self._cipher.inputs[1][0] + str(
                                second_input_bit_positions[abs(pos_second_input - var)])
                        # if var is not in this range, it belongs to the copies, so no need to print
                else:
                    tmp += str(1)
                # uncomment if you also want the nb of occurences
                # l.append((tmp, monomial[-1]))
                l.append(tmp)
        else:
            first_input_bit_positions = list(self._occurences[self._cipher.inputs[0]].keys())
            for monomial in monomials:
                tmp = ""
                if len(monomial) != 1:
                    for var in monomial[:-1]:  # [:1] to remove the occurences
                        if var < len(list(self._occurences[self._cipher.inputs[0]].keys())):
                            tmp += self._cipher.inputs[0][0] + str(first_input_bit_positions[var])
                        # if var is not in this range, it belongs to the copies, so no need to print
                else:
                    tmp += str(1)
                # uncomment if you also want the nb of occurences
                # l.append((tmp, monomial[-1]))
                l.append(tmp)
        print(l)
        print(f'Number of monomials found: {len(l)}')

    def add_constraints(self, predecessors, input_id_link_needed, block_needed):
        self.build_gurobi_model()
        self.create_gurobi_vars_from_all_components(predecessors, input_id_link_needed, block_needed)

        for component_id in list(self._occurences.keys()):  # predecessors:
            if component_id not in self._cipher.inputs:
                component = self._cipher.get_component_from_id(component_id)
                print(f"---------> {component.id}")
                if component.type == SBOX:
                    self.add_sbox_constraints(component)
                elif component.type == "cipher_output":
                    # self.add_cipher_output_constraints(component)
                    continue
                elif component.type == "constant":
                    # self.add_constant_constraints(component)
                    continue
                elif component.type == "intermediate_output":
                    self.add_intermediate_output_constraints(component)
                elif component.type == "word_operation":
                    if component.description[0] == "XOR":
                        self.add_xor_constraints(component)
                    elif component.description[0] == "ROTATE":
                        self.add_rotate_constraints(component)
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
                if (name in component.input_id_links) and (
                        component.type not in ["cipher_output"]):  # "intermediate_output"
                    indexes = [i for i, j in enumerate(component.input_id_links) if j == name]
                    if name not in occurences.keys():
                        occurences[name] = []
                    ## if we want to check the occurences of each bit
                    # occurences[name] += component.input_bit_positions[index]
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
        # print("occurences_final")
        # print(occurences_final)

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

    def create_gurobi_vars_from_all_components(self, predecessors, input_id_link_needed, block_needed):
        occurences = self.get_where_component_is_used(predecessors, input_id_link_needed, block_needed)
        all_vars = {}
        for component_id in occurences.keys():
            all_vars[component_id] = {}
            # We need the inputs vars to be the first ones defined by gurobi in order to find their values with X.values method.
            # That's why we split the following loop: we first created the original vars, and then the copies vars when necessary.
            for pos in list(occurences[component_id].keys()):
                all_vars[component_id][pos] = {}
                all_vars[component_id][pos][0] = self._model.addVar(vtype=GRB.BINARY, name=component_id + f"[{pos}]")
                all_vars[component_id][pos]["current"] = 0
            for pos in list(occurences[component_id].keys()):
                nb_copies_needed = occurences[component_id][pos]
                if nb_copies_needed >= 2:
                    all_vars[component_id][pos]["current"] = 1
                    for i in range(nb_copies_needed):
                        all_vars[component_id][pos][i + 1] = self._model.addVar(vtype=GRB.BINARY,
                                                                                name=f"copy_{i + 1}_" + component_id + f"[{pos}]")
                        self._model.addConstr(all_vars[component_id][pos][0] >= all_vars[component_id][pos][i + 1])
                    self._model.addConstr(sum(all_vars[component_id][pos][i + 1] for i in range(nb_copies_needed)) >=
                                          all_vars[component_id][pos][0])

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

    def build_generic_model_for_specific_output_bit(self, output_bit_index, fixed_degree=None):
        start = time.time()

        output_id = self.get_cipher_output_component_id()
        # output_id = "xor_1_69"
        component = self._cipher.get_component_from_id(output_id)
        pivot = 0
        new_output_bit_index = output_bit_index
        for index, block in enumerate(component.input_bit_positions):
            if pivot <= output_bit_index < pivot + len(block):
                block_needed = block
                input_id_link_needed = component.input_id_links[index]
                break
            pivot += len(block)
            new_output_bit_index -= len(block)
        # print("new_output_bit_index")
        # print(new_output_bit_index)

        # input_id_link_needed = "rot_1_68"
        # block_needed = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63] #[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]

        G = create_networkx_graph_from_input_ids(self._cipher)
        predecessors = list(_get_predecessors_subgraph(G, [input_id_link_needed]))
        # print("predecessors")
        # print(predecessors)
        for input_id in self._cipher.inputs + ['']:
            if input_id in predecessors:
                predecessors.remove(input_id)

        print("input_id_link_needed")
        print(input_id_link_needed)
        print("predecessors")
        print(predecessors)
        self.add_constraints(predecessors, input_id_link_needed, block_needed)

        var_from_block_needed = []
        for i in block_needed:
            var_from_block_needed.append(self._model.getVarByName(f"{input_id_link_needed}[{i}]"))
        # print("var_from_block_needed")
        # print(var_from_block_needed)

        output_vars = self._model.addVars(list(range(len(block_needed))), vtype=GRB.BINARY, name=output_id)
        self._variables[output_id] = output_vars
        self._model.update()
        # print("output_vars")
        # print(output_vars)

        for i in range(len(block_needed)):
            self._model.addConstr(output_vars[i] == var_from_block_needed[i])
            self.set_as_used_variables([output_vars[i], var_from_block_needed[i]])

        ks = self._model.addVar()
        self._model.addConstr(ks == sum(output_vars[i] for i in range(len(block_needed))))
        self._model.addConstr(ks == 1)
        self._model.addConstr(output_vars[new_output_bit_index] == 1)

        if fixed_degree != None:
            plaintext_vars = []
            for i in range(
                    self._cipher.inputs_bit_size[0]):  # Carreful, here we are assuming that input[0] is the plaintext
                plaintext_vars.append(self._model.getVarByName(f"plaintext[{i}]"))
            self._model.addConstr(
                sum(plaintext_vars[i] for i in range(self._cipher.inputs_bit_size[0])) == fixed_degree)

        self.set_unused_variables_to_zero()
        self._model.update()
        self._model.write("division_trail_model.lp")
        end = time.time()
        building_time = end - start
        print(f"building_time : {building_time}")
        self._model.update()

    def get_solutions(self):
        index_second_input = self.find_index_second_input()
        nb_inputs_used = 0
        for input_id in self._cipher.inputs:
            if input_id in list(self._occurences.keys()):
                nb_inputs_used += 1
        if nb_inputs_used == 2:
            max_input_bit_pos = index_second_input + len(list(self._occurences[self._cipher.inputs[1]].keys()))
        else:
            max_input_bit_pos = index_second_input
        print(f"max_input_bit_pos = {max_input_bit_pos}")

        solCount = self._model.SolCount
        print('Number of solutions (might cancel each other) found: ' + str(solCount))
        monomials = []
        for sol in range(solCount):
            self._model.setParam(GRB.Param.SolutionNumber, sol)
            values = self._model.Xn

            tmp = []
            for index, v in enumerate(values[:max_input_bit_pos]):
                if v == 1:
                    if nb_inputs_used > 1:
                        if index < len(list(self._occurences[self._cipher.inputs[0]].keys())):
                            tmp.append(index)
                        elif index_second_input <= index < index_second_input + len(
                                list(self._occurences[self._cipher.inputs[1]].keys())):
                            tmp.append(index)
                    else:
                        if index < len(list(self._occurences[self._cipher.inputs[0]].keys())):
                            tmp.append(index)
            monomials.append(tmp)

        # print(monomials)
        monomials_with_occurences = [x + [monomials.count(x)] for x in monomials]
        # print(monomials_with_occurences)
        monomials_duplicates_removed = list(set(tuple(i) for i in monomials_with_occurences))
        # print(monomials_duplicates_removed)
        monomials_even_occurences_removed = [x for x in monomials_duplicates_removed if x[-1] % 2 == 1]
        # print(monomials_even_occurences_removed)
        self.pretty_print(monomials_even_occurences_removed)

    def find_anf_of_specific_output_bit(self, output_bit_index, fixed_degree=None):
        self.build_generic_model_for_specific_output_bit(output_bit_index, fixed_degree)

        print(self._model)
        start = time.time()
        self._model.optimize()
        end = time.time()
        solving_time = end - start
        print(f"solving_time : {solving_time}")

        self.get_solutions()
        return self._model

    def check_presence_of_particular_monomial_in_specific_anf(self, monomial, output_bit_index, fixed_degree=None):
        self.build_generic_model_for_specific_output_bit(output_bit_index, fixed_degree)
        for term in monomial:
            var_term = self._model.getVarByName(f"{term[0]}[{term[1]}]")
            self._model.addConstr(var_term == 1)
        self._model.update()
        self._model.write("division_trail_model.lp")

        print(self._model)
        start = time.time()
        self._model.optimize()
        end = time.time()
        solving_time = end - start
        print(f"solving_time : {solving_time}")

        self.get_solutions()
        return self._model

    def check_presence_of_particular_monomial_in_all_anf(self, monomial, fixed_degree=None):
        s = ""
        for term in monomial:
            s += term[0][0] + str(term[1])
        for i in range(self._cipher.output_bit_size):
            print(f"\nSearch of {s} in anf {i} :")
            self.check_presence_of_particular_monomial_in_specific_anf(monomial, i, fixed_degree)

    def find_degree_of_specific_anf(self, output_bit_index):
        fixed_degree = None
        self.build_generic_model_for_specific_output_bit(output_bit_index, fixed_degree)

        index_plaintext = self._cipher.inputs.index("plaintext")
        p = []
        nb_plaintext_bits_used = len(list(self._occurences["plaintext"].keys()))
        for i in range(nb_plaintext_bits_used):
            p.append(self._model.getVarByName(f"plaintext[{i}]"))
        self._model.setObjective(sum(p[i] for i in range(nb_plaintext_bits_used)), GRB.MAXIMIZE)

        print(self._model)
        start = time.time()
        self._model.optimize()
        end = time.time()
        solving_time = end - start
        print(f"solving_time : {solving_time}")

        # get degree
        degree = self._model.getObjective().getValue()
        return degree

    def re_init(self):
        self._variables = None
        self._model = None
        self._occurences = None
        self._used_variables = []
        self._variables_as_list = []
        self._unused_variables = []

    def find_degree_of_all_anfs(self):
        for i in range(self._cipher.output_bit_size):
            self.re_init()
            degree = self.find_degree_of_specific_anf(i)
            print(f"Degree of anf corresponding to output bit at position {i} = {degree}\n")