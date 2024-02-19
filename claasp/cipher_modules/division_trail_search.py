import time
from gurobipy import *
from sage.crypto.sbox import SBox
from sage.crypto.boolean_function import BooleanFunction
from collections import Counter
from sage.rings.polynomial.pbori.pbori import BooleanPolynomialRing
from claasp.name_mappings import (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT,
                                  WORD_OPERATION, LINEAR_LAYER, SBOX, MIX_COLUMN)

class MilpDivisionTrailModel():
    """
    EXAMPLES::

        sage: from claasp.ciphers.permutations.ascon_permutation import AsconPermutation
        sage: cipher = AsconPermutation(number_of_rounds=1)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_for_specific_output_bit(0)

        sage: from claasp.ciphers.permutations.ascon_sbox_sigma_no_matrix_permutation import AsconSboxSigmaNoMatrixPermutation
        sage: cipher = AsconSboxSigmaNoMatrixPermutation(number_of_rounds=1)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_for_specific_output_bit(0)

        sage: from claasp.ciphers.permutations.gaston_permutation import GastonPermutation
        sage: cipher = GastonPermutation(number_of_rounds=1)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_for_specific_output_bit(0)

        sage: from claasp.ciphers.permutations.gaston_sbox_permutation import GastonSboxPermutation
        sage: cipher = GastonSboxPermutation(number_of_rounds=1)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_for_specific_output_bit(0)

        sage: from claasp.ciphers.toys.toyspn1 import ToySPN1
        sage: cipher = ToySPN1(number_of_rounds=1)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_for_specific_output_bit(1)

        sage: from claasp.ciphers.toys.toyand import ToyAND
        sage: cipher = ToyAND()
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_for_specific_output_bit(0)

        sage: from claasp.ciphers.toys.toyand_v2 import ToyAND
        sage: cipher = ToyAND()
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_for_specific_output_bit(0)

        sage: from claasp.ciphers.toys.toyconstant import ToyCONSTANT
        sage: cipher = ToyCONSTANT()
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_for_specific_output_bit(0)

        sage: from claasp.ciphers.toys.toynot import ToyNOT
        sage: cipher = ToyNOT()
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_for_specific_output_bit(0)

        sage: from claasp.ciphers.toys.toysbox import ToySBOX
        sage: cipher = ToySBOX()
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_for_specific_output_bit(0)

        sage: from claasp.ciphers.toys.toysimon import ToySIMON
        sage: cipher = ToySIMON()
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_for_specific_output_bit(0)

        sage: from claasp.ciphers.toys.toysimon_v2 import ToySIMON
        sage: cipher = ToySIMON()
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_for_specific_output_bit(0)

        sage: from claasp.ciphers.toys.toyspn1 import ToySPN1
        sage: cipher = ToySPN1(number_of_rounds=1)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.check_presence_of_particular_monomial_in_specific_anf([("plaintext", 0)], 1)

        sage: from claasp.ciphers.toys.toyspn1 import ToySPN1
        sage: cipher = ToySPN1(number_of_rounds=1)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.check_presence_of_particular_monomial_in_all_anf([("plaintext", 0)])

        sage: from claasp.ciphers.toys.toyspn2 import ToySPN2
        sage: cipher = ToySPN2(number_of_rounds=1)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_for_specific_output_bit(1)

        sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
        sage: cipher = SimonBlockCipher(number_of_rounds=1)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_for_specific_output_bit(0)

    """

    def __init__(self, cipher):
        self._cipher = cipher
        self._variables = None
        self._model = None
        self._occurences = None

    def build_gurobi_model(self):
        model = Model()
        model.Params.LogToConsole = 0
        model.setParam("PoolSolutions", 1000) # 200000000
        model.setParam(GRB.Param.PoolSearchMode, 2)
        self._model = model

    def get_anfs_from_sbox(self, component):
        anfs = []
        B = BooleanPolynomialRing(5,'x')
        C = BooleanPolynomialRing(5,'x')
        var_names = [f"x{i}" for i in range(component.output_bit_size)]
        d = {}
        for i in range(component.output_bit_size):
            d[B(var_names[i])] = C(var_names[component.output_bit_size-i-1])

        sbox = SBox(component.description)
        for i in range(component.input_bit_size):
            anf = sbox.component_function(1<<i).algebraic_normal_form()
            anf = anf.subs(d) # x0 was msb, now it is the lsb
            anfs.append(anf)
        return anfs

    def get_monomial_occurences(self, component):
        B = BooleanPolynomialRing(component.input_bit_size,'x')
        anfs = self.get_anfs_from_sbox(component)

        anfs = [B(anfs[i]) for i in range(component.input_bit_size)]
        monomials = []
        for anf in anfs:
            monomials += anf.monomials()

        monomials_degree_based = {}
        sbox = SBox(component.description)
        for deg in range(sbox.max_degree()+1):
            monomials_degree_based[deg] = dict(Counter([monomial for monomial in monomials if monomial.degree() == deg]))
            if deg >= 2:
                for monomial in monomials_degree_based[deg].keys():
                    deg1_monomials = monomial.variables()
                    for deg1_monomial in deg1_monomials:
                        monomials_degree_based[1][deg1_monomial] += monomials_degree_based[deg][monomial]

        return monomials_degree_based

    def create_gurobi_vars_sbox(self, component, input_vars_concat):
        monomial_occurences = self.get_monomial_occurences(component)
        B = BooleanPolynomialRing(component.input_bit_size,'x')
        x = B.variable_names()

        copy_xi = {}
        for index, xi in enumerate(x):
            nb_occurence_xi = monomial_occurences[1][B(xi)]
            if nb_occurence_xi != 0:
                copy_xi[B(xi)] = self._model.addVars(list(range(nb_occurence_xi)), vtype=GRB.BINARY, name=input_vars_concat[index].VarName + "_" +xi)
                self._model.update()
                for i in range(nb_occurence_xi):
                    self._model.addConstr(input_vars_concat[index] >= copy_xi[B(xi)][i])
                self._model.addConstr(sum(copy_xi[B(xi)][i] for i in range(nb_occurence_xi)) >= input_vars_concat[index])

        copy_monomials_deg = {}
        for deg in list(monomial_occurences.keys()):
            if deg >= 2: # here you are looking at only deg 2, what if deg 3 or more?
                nb_monomials = sum(monomial_occurences[2].values())
                copy_monomials_deg[deg] = self._model.addVars(list(range(nb_monomials)), vtype=GRB.BINARY) #name="copy_deg2"
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
        for i in range(component.output_bit_size):
            output_vars.append(self._model.getVarByName(f"{component.id}[{i}]"))
        # print(output_vars)
        # print("###########")

        input_vars_concat = []
        for index, input_name in enumerate(component.input_id_links):
            current = self._variables[input_name]["current"]
            for pos in component.input_bit_positions[index]:
                input_vars_concat.append(self._variables[input_name][current][pos])
            self._variables[input_name]["current"] += 1

        B = BooleanPolynomialRing(component.input_bit_size,'x')
        x = B.variable_names()
        anfs = self.get_anfs_from_sbox(component)
        anfs = [B(anfs[i]) for i in range(component.input_bit_size)]
        anfs.reverse()
        # print(anfs)

        copy_monomials_deg = self.create_gurobi_vars_sbox(component, input_vars_concat)

        for index, anf in enumerate(anfs):
            constr = 0
            equality = True
            monomials = anf.monomials()
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
                        self._model.addConstr(copy_monomials_deg[deg][current] == copy_monomials_deg[1][deg1_monomial][current_deg1])
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

    def add_xor_constraints(self, component):
        output_vars = []
        for i in range(component.output_bit_size):
            output_vars.append(self._model.getVarByName(f"{component.id}[{i}]"))

        input_vars_concat = []
        constant_flag = []
        for index, input_name in enumerate(component.input_id_links):
            current = self._variables[input_name]["current"]
            for pos in component.input_bit_positions[index]:
                if input_name[:8] == "constant":
                    const_comp = self._cipher.get_component_from_id(input_name)
                    # constant_flag.append((int(const_comp.description[0], 16) & (1 << const_comp.output_bit_size-pos)) >> const_comp.output_bit_size-pos)
                    constant_flag.append((int(const_comp.description[0], 16) >> (const_comp.output_bit_size - 1 - pos)) & 1)
                else:
                    input_vars_concat.append(self._variables[input_name][current][pos])
            self._variables[input_name]["current"] += 1

        block_size = component.output_bit_size
        nb_blocks = component.description[1]
        if constant_flag != []:
            nb_blocks -= 1
        for i in range(block_size):
            constr = 0
            for j in range(nb_blocks):
                constr += input_vars_concat[i + block_size * j]
            if (constant_flag != []) and (constant_flag[i]):
                self._model.addConstr(output_vars[i] >= constr)
            else:
                self._model.addConstr(output_vars[i] == constr)
        self._model.update()

    def add_rotate_constraints(self, component):
        output_vars = []
        for i in range(component.output_bit_size):
            output_vars.append(self._model.getVarByName(f"{component.id}[{i}]"))

        input_vars_concat = []
        for index, input_name in enumerate(component.input_id_links):
            current = self._variables[input_name]["current"]
            for pos in component.input_bit_positions[index]:
                input_vars_concat.append(self._variables[input_name][current][pos])
            self._variables[input_name]["current"] += 1

        rotate_offset = component.description[1]
        for i in range(component.output_bit_size):
            self._model.addConstr(output_vars[i] == input_vars_concat[(i-rotate_offset) % component.output_bit_size])
        self._model.update()

    def add_and_constraints(self, component):
        # Constraints taken from Misuse-free paper
        output_vars = []
        for i in range(component.output_bit_size):
            output_vars.append(self._model.getVarByName(f"{component.id}[{i}]"))

        input_vars_concat = []
        for index, input_name in enumerate(component.input_id_links):
            current = self._variables[input_name]["current"]
            for pos in component.input_bit_positions[index]:
                input_vars_concat.append(self._variables[input_name][current][pos])
            self._variables[input_name]["current"] += 1

        block_size = int(len(input_vars_concat)//component.description[1])
        for i in range(component.output_bit_size):
            self._model.addConstr(output_vars[i] == input_vars_concat[i])
            self._model.addConstr(output_vars[i] == input_vars_concat[i + block_size])
        self._model.update()

    def add_not_constraints(self, component):
        output_vars = []
        for i in range(component.output_bit_size):
            output_vars.append(self._model.getVarByName(f"{component.id}[{i}]"))

        input_vars_concat = []
        for index, input_name in enumerate(component.input_id_links):
            current = self._variables[input_name]["current"]
            for pos in component.input_bit_positions[index]:
                input_vars_concat.append(self._variables[input_name][current][pos])
            self._variables[input_name]["current"] += 1
        input_vars_concat

        for i in range(component.output_bit_size):
            self._model.addConstr(output_vars[i] >= input_vars_concat[i])
        self._model.update()

    def add_constant_constraints(self, component):
        output_vars = []
        for i in range(component.output_bit_size):
            output_vars.append(self._model.getVarByName(f"{component.id}[{i}]"))

        const = int(component.description[0], 16)
        for i in range(component.output_bit_size):
            # self._model.addConstr(output_vars[i] == (const & (1 << component.output_bit_size-i)) >> component.output_bit_size-i)
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


    def get_cipher_output_component_id(self):
        for component in self._cipher.get_all_components():
            if component.type == "cipher_output":
                return component.id

    def pretty_print(self, monomials):
        occurences = self._occurences
        pos_second_input = self.find_index_second_input()
        print(f"pos_second_input = {pos_second_input}")
        l = []
        if len(self._cipher.inputs_bit_size) > 1:
            for monomial in monomials:
                tmp = ""
                if len(monomial) != 1:
                    for var in monomial[:-1]: #[:1] to remove the occurences
                        if var < self._cipher.inputs_bit_size[0]:
                            tmp += self._cipher.inputs[0][0] + str(var)
                        elif pos_second_input <= var < pos_second_input + self._cipher.inputs_bit_size[1]:
                            tmp += self._cipher.inputs[1][0] + str(abs(pos_second_input - var))
                        # if var is not in this range, it belongs to the copies, so no need to print
                else:
                    tmp += str(1)
                # uncomment if you also want the nb of occurences
                # l.append((tmp, monomial[-1]))
                l.append(tmp)
        else:
            for monomial in monomials:
                tmp = ""
                if len(monomial) != 1:
                    for var in monomial[:-1]: #[:1] to remove the occurences
                        if var < self._cipher.inputs_bit_size[0]:
                            tmp += self._cipher.inputs[0][0] + str(var)
                        # if var is not in this range, it belongs to the copies, so no need to print
                else:
                    tmp += str(1)
                # uncomment if you also want the nb of occurences
                # l.append((tmp, monomial[-1]))
                l.append(tmp)
        print(f'Number of monomials found: {len(l)}')
        print(l)

    def add_constraints(self):
        self.build_gurobi_model()
        self.create_gurobi_vars_from_all_components()
        word_operations_types = ['AND', 'MODADD', 'MODSUB', 'NOT', 'OR', 'ROTATE', 'SHIFT', 'XOR']

        for component in self._cipher.get_all_components(): #[:5]
            # print(f"---------> {component.id}")
            if component.type == SBOX:
                self.add_sbox_constraints(component)
            elif component.type == "cipher_output":
                self.add_cipher_output_constraints(component)
            elif component.type == "constant":
                self.add_constant_constraints(component)
            elif component.type == "intermediate_output":
                continue
            elif component.type == "word_operation":
                if component.description[0] == "XOR":
                    self.add_xor_constraints(component)
                elif component.description[0] == "ROTATE":
                    self.add_rotate_constraints(component)
                elif component.description[0] == "AND":
                    self.add_and_constraints(component)
                elif component.description[0] == "NOT":
                    self.add_not_constraints(component)
            else:
                print(f"---> {component.id} not yet implemented")

        return self._model

    def get_where_component_is_used(self):
        occurences = {}
        ids = self._cipher.inputs + self._cipher.get_all_components_ids() # [:2]
        for name in ids:
            for component in self._cipher.get_all_components(): # [:2]
                if (name in component.input_id_links) and (component.type != "intermediate_output"):
                    indexes = [i for i, j in enumerate(component.input_id_links) if j == name]
                    if name not in occurences.keys():
                        occurences[name] = []
                    ## if we want to check the occurences of each bit
                    # occurences[name] += component.input_bit_positions[index]
                    for index in indexes:
                        occurences[name].append(component.input_bit_positions[index])

        occurences_final = {}
        for component_id in occurences.keys():
            occurences_final[component_id] = self.find_copy_indexes(occurences[component_id])

        self._occurences = occurences_final
        return occurences_final


    def find_copy_indexes(self, input_bit_positions):
        already_visited = []
        l = []
        for input_bit_position in input_bit_positions:
            if input_bit_position not in already_visited:
                already_visited.append(input_bit_position)
                indexes = [i for i, j in enumerate(input_bit_positions) if j == input_bit_position]
                l.append([input_bit_position, indexes])
        return l

    def create_gurobi_vars_from_all_components(self):
        occurences = self.get_where_component_is_used()
        print(occurences)
        all_vars = {}
        for component_id in occurences.keys():
            all_vars[component_id] = {}
            all_vars[component_id]["current"] = 0
            if component_id not in self._cipher.inputs:
                component = self._cipher.get_component_from_id(component_id)
                all_vars[component_id][0] = self._model.addVars(list(range(component.output_bit_size)), vtype=GRB.BINARY, name=component.id)
                for input_bit_positions_indexes in occurences[component_id]:
                    input_bit_positions = input_bit_positions_indexes[0]
                    indexes = input_bit_positions_indexes[1]
                    nb_occurence_for_this_input_bit_positions = len(indexes)
                    if (len(indexes) > 1) or (len(occurences[component_id]) > 1):
                        all_vars[component_id]["current"] = 1
                        for pos in indexes:
                            all_vars[component_id][pos+1] = self._model.addVars(input_bit_positions, vtype=GRB.BINARY, name="copy_"+component_id+f"_{pos}")
                        for i in input_bit_positions:
                            for pos in indexes:
                                self._model.addConstr(all_vars[component_id][0][i] >= all_vars[component_id][pos+1][i])
                            self._model.addConstr(sum(all_vars[component_id][pos+1][i] for pos in indexes) >= all_vars[component_id][0][i])
            else:
                index = self._cipher.inputs.index(component_id)
                input_size = self._cipher.inputs_bit_size[index]
                all_vars[component_id][0] = self._model.addVars(list(range(input_size)), vtype=GRB.BINARY, name=component_id)
                for input_bit_positions_indexes in occurences[component_id]:
                    input_bit_positions = input_bit_positions_indexes[0]
                    indexes = input_bit_positions_indexes[1]
                    nb_occurence_for_this_input_bit_positions = len(indexes)
                    if (len(indexes) > 1) or (len(occurences[component_id]) > 1):
                        all_vars[component_id]["current"] = 1
                        for pos in indexes:
                            all_vars[component_id][pos+1] = self._model.addVars(input_bit_positions, vtype=GRB.BINARY, name="copy_"+component_id+f"_{pos}")
                        for i in input_bit_positions:
                            for pos in indexes:
                                self._model.addConstr(all_vars[component_id][0][i] >= all_vars[component_id][pos+1][i])
                            self._model.addConstr(sum(all_vars[component_id][pos+1][i] for pos in indexes) >= all_vars[component_id][0][i])

        # self._model.addVars(list(range(64)), vtype=GRB.BINARY, name="xor_0_27")
        # self._model.addVars(list(range(64)), vtype=GRB.BINARY, name="xor_0_30")
        # self._model.addVars(list(range(64)), vtype=GRB.BINARY, name="xor_0_33")
        # self._model.addVars(list(range(64)), vtype=GRB.BINARY, name="xor_0_36")
        # self._model.addVars(list(range(5)), vtype=GRB.BINARY, name="sbox_0_2")
        self._model.update()
        self._variables = all_vars

    def find_index_second_input(self):
        occurences = self._occurences
        index = self._cipher.inputs_bit_size[0]
        # need_to_copy = False
        for input_bit_positions_indexes in occurences[self._cipher.inputs[0]]:
            if len(input_bit_positions_indexes[1]) > 1:
                # need_to_copy = True
                index += len(input_bit_positions_indexes[0])*len(input_bit_positions_indexes[1])
        # if need_to_copy:
            # index += self._cipher.inputs_bit_size[0]
        return index

    def find_anf_for_specific_output_bit(self, output_bit_index):
        start = time.time()

        self.add_constraints()
        output_id = self.get_cipher_output_component_id()
        output_vars = []
        for i in range(self._cipher.output_bit_size): # self._cipher.output_bit_size
            output_vars.append(self._model.getVarByName(f"{output_id}[{i}]")) # {output_id}

        ks = self._model.addVar()
        self._model.addConstr(ks == sum(output_vars[i] for i in range(self._cipher.output_bit_size))) # self._cipher.output_bit_size
        self._model.addConstr(ks == 1)
        self._model.addConstr(output_vars[output_bit_index] == 1)

        # Before linear layer
        # for i in range(64): # self._cipher.output_bit_size
        #     c = self._model.getVarByName(f"xor_0_20[{i}]")
        #     self._model.addConstr(c == 0)

        # for i in range(64): # self._cipher.output_bit_size
        #     c = self._model.getVarByName(f"xor_0_21[{i}]")
        #     self._model.addConstr(c == 0)

        # for i in range(64): # self._cipher.output_bit_size
        #     c = self._model.getVarByName(f"xor_0_22[{i}]")
        #     self._model.addConstr(c == 0)
        ################

        # for i in range(1,64): # self._cipher.output_bit_size
        #     c = self._model.getVarByName(f"plaintext[{i}]")
        #     self._model.addConstr(c == 0)

        # for i in range(65,128): # self._cipher.output_bit_size
        #     c = self._model.getVarByName(f"plaintext[{i}]")
        #     self._model.addConstr(c == 0)

        # for i in range(129, 192): # self._cipher.output_bit_size
        #     c = self._model.getVarByName(f"plaintext[{i}]")
        #     self._model.addConstr(c == 0)

        # for i in range(193, 256): # self._cipher.output_bit_size
        #     c = self._model.getVarByName(f"plaintext[{i}]")
        #     self._model.addConstr(c == 0)

        # for i in range(257, 320): # self._cipher.output_bit_size
        #     c = self._model.getVarByName(f"plaintext[{i}]")
        #     self._model.addConstr(c == 0)

        self._model.update()
        self._model.write("division_trail_model_toy_cipher.lp")
        end = time.time()
        building_time = end - start
        print(f"building_time : {building_time}")

        occurences = self._occurences
        index_second_input = self.find_index_second_input()
        if len(self._cipher.inputs_bit_size) > 1:
            max_input_bit_pos = index_second_input + self._cipher.inputs_bit_size[1]
        else:
            max_input_bit_pos = index_second_input
        print(f"max_input_bit_pos = {max_input_bit_pos}")

        start = time.time()
        # self._model.setObjective(0)
        self._model.optimize()
        end = time.time()
        solving_time = end - start
        print(f"solving_time : {solving_time}")
        solCount = self._model.SolCount
        print('Number of solutions (might cancel each other) found: ' + str(solCount))
        monomials = []
        for sol in range(solCount):
            self._model.setParam(GRB.Param.SolutionNumber, sol)
            values = self._model.Xn
            # print(values[:64])
            # print(values[64:128])
            # print(values[128:192])
            # print(values[192:256])
            # print(values[256:320])
            # print("################")

            # Simon 1 round
            # print("plaintext")
            # print(values[:32])
            # print("copy plaintext")
            # print(values[32:48])
            # print(values[48:64])
            # print(values[64:80])
            # print(values[80:96])
            # print(values[96:112])
            # print("key")
            # print(values[112:176])
            # print("rots")
            # print(values[224:240])
            # print(values[240:256])
            # print(values[256:272])
            # print("and")
            # print(values[272:288])
            # print("xors")
            # print(values[288:304])
            # print(values[304:320])
            # print("################")
            # print(len(values))

            # tmp = []
            # for index, v in enumerate(values[:max_input_bit_pos]):
            #     if v == 1:
            #         tmp.append(index)
            # monomials.append(tmp)

            tmp = []
            for index, v in enumerate(values[:max_input_bit_pos]):
                if v == 1:
                    if len(self._cipher.inputs_bit_size) > 1:
                        if index < self._cipher.inputs_bit_size[0]:
                            tmp.append(index)
                        elif index_second_input <= index < index_second_input + self._cipher.inputs_bit_size[1]:
                            tmp.append(index)
                    else:
                        if index < self._cipher.inputs_bit_size[0]:
                            tmp.append(index)
            monomials.append(tmp)

        # print(monomials)
        monomials_with_occurences = [x+[monomials.count(x)] for x in monomials]
        # print(monomials_with_occurences)
        monomials_duplicates_removed = list(set(tuple(i) for i in monomials_with_occurences))
        # print(monomials_duplicates_removed)
        monomials_even_occurences_removed = [x for x in monomials_duplicates_removed if x[-1] % 2 == 1]
        # print(monomials_even_occurences_removed)
        self.pretty_print(monomials_even_occurences_removed)
        return self._model

    def check_presence_of_particular_monomial_in_specific_anf(self, monomial, output_bit_index):
        start = time.time()
        self.add_constraints()
        output_id = self.get_cipher_output_component_id()
        output_vars = []
        for i in range(self._cipher.output_bit_size):
            output_vars.append(self._model.getVarByName(f"{output_id}[{i}]"))
        ks = self._model.addVar()
        self._model.addConstr(ks == sum(output_vars[i] for i in range(self._cipher.output_bit_size)))
        self._model.addConstr(ks == 1)
        self._model.addConstr(output_vars[output_bit_index] == 1)

        for term in monomial:
            var_term = self._model.getVarByName(f"{term[0]}[{term[1]}]")
            self._model.addConstr(var_term == 1)

        self._model.write("division_trail_model_toy_cipher.lp")

        self._model.update()
        end = time.time()
        building_time = end - start
        print(f"building_time : {building_time}")

        start = time.time()
        self._model.optimize()
        end = time.time()
        solving_time = end - start
        print(f"solving_time : {solving_time}")

        solCount = self._model.SolCount
        print('Number of solutions/monomials found: ' + str(solCount))
        monomials = []
        for sol in range(solCount):
            self._model.setParam(GRB.Param.SolutionNumber, sol)
            values = self._model.Xn
            tmp = []
            for index, v in enumerate(values[:12]):
                if v == 1:
                    tmp.append(index)
            monomials.append(tmp)

        monomials_with_occurences = [x+[monomials.count(x)] for x in monomials]
        monomials_duplicates_removed = list(set(tuple(i) for i in monomials_with_occurences))
        monomials_even_occurences_removed = [x for x in monomials_duplicates_removed if x[-1] % 2 == 1]
        self.pretty_print(monomials_even_occurences_removed)
        return self._model

    def check_presence_of_particular_monomial_in_all_anf(self, monomial):
        s = ""
        for term in monomial:
            s += term[0][0]+str(term[1])
        for i in range(self._cipher.output_bit_size):
            print(f"\nSearch of {s} in anf {i} :")
            self.check_presence_of_particular_monomial_in_specific_anf(monomial, i)


# Ascon circuit version, checked by hand for y0
['p64p256', 'p45', 'p64p128', 'p36', 'p45p109', 'p0p64', 'p192', 'p128', 'p64', 'p100p164', 'p0', 'p100p292', 'p109p301', 'p109p173', 'p237', 'p173', 'p228', 'p164', 'p36p100', 'p109', 'p100']
# Ascon circuit version, checked by hand for y256
['p64p256', 'p215', 'p313', 'p64', 'p249', 'p279', 'p87p279', 'p256', 'p121p313', 'p87', 'p0p64', 'p121', 'p23p87', 'p192', 'p57p121']





