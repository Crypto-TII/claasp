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
        sage: cipher = AsconPermutation(number_of_rounds=2)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_for_specific_output_bit(0)

        sage: from claasp.ciphers.permutations.ascon_sbox_sigma_no_matrix_permutation import AsconSboxSigmaNoMatrixPermutation
        sage: cipher = AsconSboxSigmaNoMatrixPermutation(number_of_rounds=2)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_for_specific_output_bit(0)

        sage: from claasp.ciphers.permutations.gaston_permutation import GastonPermutation
        sage: cipher = GastonPermutation(number_of_rounds=2)
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
        sage: cipher = SimonBlockCipher(number_of_rounds=2)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_for_specific_output_bit(0)

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
        sage: cipher = SpeckBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=1)
        sage: modadd_component = cipher.get_component_from_id('modadd_0_1')
        sage: boolean_polynomial_ring = CipherComponentsAnalysis(cipher)._generate_boolean_polynomial_ring_from_cipher()
        sage: boolean_polynomials = CipherComponentsAnalysis(cipher)._MODADD_as_boolean_function(modadd_component, boolean_polynomial_ring)

    """

    def __init__(self, cipher):
        self._cipher = cipher
        self._variables = None
        self._model = None
        self._occurences = None

    def build_gurobi_model(self):
        model = Model()
        model.Params.LogToConsole = 0
        model.Params.Threads = 32 # best found experimentaly on ascon_sbox_2rounds
        model.setParam("PoolSolutions", 200000000) # 200000000
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
        # print(occurences)
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
        # monomials = []
        # for sol in range(solCount):
        #     self._model.setParam(GRB.Param.SolutionNumber, sol)
        #     values = self._model.Xn
        #     # print(values[:64])
        #     # print(values[64:128])
        #     # print(values[128:192])
        #     # print(values[192:256])
        #     # print(values[256:320])
        #     # print("################")

        #     # Simon 1 round
        #     # print("plaintext")
        #     # print(values[:32])
        #     # print("copy plaintext")
        #     # print(values[32:48])
        #     # print(values[48:64])
        #     # print(values[64:80])
        #     # print(values[80:96])
        #     # print(values[96:112])
        #     # print("key")
        #     # print(values[112:176])
        #     # print("rots")
        #     # print(values[224:240])
        #     # print(values[240:256])
        #     # print(values[256:272])
        #     # print("and")
        #     # print(values[272:288])
        #     # print("xors")
        #     # print(values[288:304])
        #     # print(values[304:320])
        #     # print("################")
        #     # print(len(values))

        #     # tmp = []
        #     # for index, v in enumerate(values[:max_input_bit_pos]):
        #     #     if v == 1:
        #     #         tmp.append(index)
        #     # monomials.append(tmp)

        #     tmp = []
        #     for index, v in enumerate(values[:max_input_bit_pos]):
        #         if v == 1:
        #             if len(self._cipher.inputs_bit_size) > 1:
        #                 if index < self._cipher.inputs_bit_size[0]:
        #                     tmp.append(index)
        #                 elif index_second_input <= index < index_second_input + self._cipher.inputs_bit_size[1]:
        #                     tmp.append(index)
        #             else:
        #                 if index < self._cipher.inputs_bit_size[0]:
        #                     tmp.append(index)
        #     monomials.append(tmp)

        # # print(monomials)
        # monomials_with_occurences = [x+[monomials.count(x)] for x in monomials]
        # # print(monomials_with_occurences)
        # monomials_duplicates_removed = list(set(tuple(i) for i in monomials_with_occurences))
        # # print(monomials_duplicates_removed)
        # monomials_even_occurences_removed = [x for x in monomials_duplicates_removed if x[-1] % 2 == 1]
        # # print(monomials_even_occurences_removed)
        # self.pretty_print(monomials_even_occurences_removed)
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


    # # Ascon circuit version, checked by hand for y0
    # ['p64p256', 'p45', 'p64p128', 'p36', 'p45p109', 'p0p64', 'p192', 'p128', 'p64', 'p100p164', 'p0', 'p100p292', 'p109p301', 'p109p173', 'p237', 'p173', 'p228', 'p164', 'p36p100', 'p109', 'p100']
    # # Ascon circuit version, checked by hand for y256
    # ['p64p256', 'p215', 'p313', 'p64', 'p249', 'p279', 'p87p279', 'p256', 'p121p313', 'p87', 'p0p64', 'p121', 'p23p87', 'p192', 'p57p121']

    def find_degree_of_specific_anf(self, output_bit_index):
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

        index_plaintext = self._cipher.inputs.index("plaintext")
        plaintext_bit_size = self._cipher.inputs_bit_size[index_plaintext]
        p = []
        for i in range(plaintext_bit_size):
            p.append(self._model.getVarByName(f"plaintext[{i}]"))
        self._model.setObjective(sum(p[i] for i in range(plaintext_bit_size)), GRB.MAXIMIZE)

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

        # get degree
        degree = self._model.getObjective().getValue()
        return degree

    def find_degree_of_all_anfs(self):
        for i in range(5): # self._cipher.output_bit_size
            degree = self.find_degree_of_specific_anf(i)
            print(f"Degree of anf {i} = {degree}\n")


def test():
    circuit = ['p165p205', 'p69', 'p55p275', 'p40p115', 'p274p313', 'p15p33', 'p33p166', 'p58p205', 'p55p248', 'p33p234', 'p128p230', 'p107p313', 'p205', 'p100p230', 'p292p315', 'p276p315', 'p140p153', 'p128p153', 'p115p171', 'p107p141', 'p16p223', 'p314', 'p107p209', 'p33p292', 'p275p315', 'p15p55', 'p76p146', 'p82p171', 'p171p315', 'p166p314', 'p75p115', 'p40p205', 'p146p276', 'p205p274', 'p210p276', 'p141p166', 'p230p313', 'p55p171', 'p235p315', 'p15p230', 'p116p223', 'p209p292', 'p284', 'p33', 'p115p125', 'p165p314', 'p15p153', 'p116p146', 'p234p314', 'p15p181', 'p107p114', 'p58p314', 'p140', 'p15p115', 'p125p313', 'p115p234', 'p114p276', 'p153p315', 'p76p100', 'p54p75', 'p16p128', 'p16p33', 'p128p165', 'p146p153', 'p141p292', 'p100p165', 'p125p141', 'p171p181', 'p75p205', 'p210p230', 'p153p209', 'p54p171', 'p58p82', 'p140p235', 'p55p125', 'p54p76', 'p100p116', 'p141p234', 'p166p210', 'p209p235', 'p140p292', 'p55p76', 'p230p315', 'p114p153', 'p83', 'p58p140', 'p15p58', 'p115p166', 'p82p165', 'p165p181', 'p146p230', 'p153p181', 'p33p248', 'p33p153', 'p181', 'p125p315', 'p33p276', 'p230p267', 'p125p209', 'p82p116', 'p58p181', 'p181p274', 'p107p223', 'p54p116', 'p238', 'p16p314', 'p15p107', 'p76p209', 'p55p292', 'p82p234', 'p128p274', 'p115p292', 'p55p166', 'p100p274', 'p40p140', 'p116p313', 'p16p210', 'p209p276', 'p16p82', 'p55p234', 'p173', 'p248p314', 'p116p141', 'p16p55', 'p40p315', 'p55p235', 'p40p209', 'p223p234', 'p76p315', 'p192', 'p128p171', 'p141p276', 'p115p275', 'p76p141', 'p107p128', 'p54p166', 'p48', 'p115p248', 'p15p274', 'p116p267', 'p153p223', 'p75p140', 'p209p230', 'p54p234', 'p140p276', 'p267p275', 'p33p107', 'p107p314', 'p146p274', 'p58p146', 'p141p248', 'p210p274', 'p171p313', 'p75p315', 'p141p153', 'p33p58', 'p146', 'p235p313', 'p282', 'p15p140', 'p276p313', 'p76p114', 'p223p275', 'p116p210', 'p140p230', 'p114p274', 'p292p314', 'p115p153', 'p16p115', 'p166p205', 'p223p276', 'p275p313', 'p125p223', 'p40p146', 'p15p315', 'p125p128', 'p82p275', 'p15p209', 'p75p181', 'p54p275', 'p23', 'p33p274', 'p82p248', 'p275p314', 'p234p315', 'p107p210', 'p54p248', 'p100p171', 'p107p267', 'p205p234', 'p171p209', 'p55p153', 'p274p314', 'p223p248', 'p58p100', 'p16p205', 'p40p223', 'p33p235', 'p153p313', 'p75p146', 'p181p292', 'p100', 'p76p223', 'p82p125', 'p140p165', 'p58p313', 'p15p75', 'p179', 'p165p209', 'p58p141', 'p100p125', 'p181p234', 'p315', 'p107p115', 'p54p153', 'p166p181', 'p128p234', 'p166p315', 'p100p234', 'p40p100', 'p116p128', 'p205p275', 'p55p58', 'p181p275', 'p153p267', 'p116p205', 'p230p314', 'p125p267', 'p114p230', 'p40p313', 'p205p248', 'p141p235', 'p165p315', 'p76p313', 'p141p274', 'p15p165', 'p40p141', 'p76p128', 'p54p125', 'p58p315', 'p141', 'p58p209', 'p55p107', 'p15p116', 'p115p235', 'p16p140', 'p209', 'p140p274', 'p128p166', 'p33p75', 'p114', 'p146p165', 'p100p166', 'p40p54', 'p15p234', 'p15p223', 'p209p274', 'p75p100', 'p153p210', 'p125p210', 'p15p146', 'p115p276', 'p40p267', 'p15p40', 'p128p275', 'p75p313', 'p16p315', 'p76p267', 'p267p292', 'p82p292', 'p33p230', 'p171p223', 'p116p140', 'p75p141', 'p181p276', 'p114p165', 'p54p107', 'p84', 'p116p314', 'p82p166', 'p114p116', 'p55p274', 'p58p114', 'p223p235', 'p107p205', 'p33p165', 'p116p181', 'p223p292', 'p16p181', 'p33p116', 'p75p267', 'p165p223', 'p76p210', 'p82p235', 'p181p248', 'p54p235', 'p223', 'p100p275', 'p146p234', 'p75p209', 'p54p292', 'p141p230', 'p210p234', 'p128p248', 'p174', 'p33p40', 'p100p248', 'p40p114', 'p140p171', 'p82p276', 'p242', 'p2', 'p15p100', 'p115p230', 'p210p275', 'p55p276', 'p223p274', 'p15p313', 'p114p234', 'p205p235', 'p107p140', 'p165p313', 'p153p205', 'p58p223', 'p125p205', 'p15p141', 'p205p292', 'p15p275', 'p76p115', 'p234p313', 'p235p267', 'p128', 'p267p276', 'p114p275', 'p15p248', 'p107p181', 'p107p315', 'p75p114', 'p146p275', 'p100p153', 'p15p54', 'p16p146', 'p15p210', 'p171p314', 'p166p313', 'p235p314', 'p146p248', 'p15p267', 'p283', 'p223p230', 'p15p16', 'p210p248', 'p276p314', 'p40p128', 'p171p267', 'p55p75', 'p15p114', 'p82', 'p76p205', 'p58p128', 'p82p230', 'p274p315', 'p313', 'p115p165', 'p128p292', 'p15p171', 'p82p153', 'p15p76', 'p114p248', 'p153p314', 'p54p276', 'p24', 'p16p100', 'p55p230', 'p115p116', 'p125p314', 'p33p275', 'p114p171', 'p140p166', 'p209p234', 'p16p313', 'p141p165', 'p165p267', 'p146p171', 'p40p82', 'p171p210', 'p75p223', 'p181p235', 'p234p267', 'p54', 'p166p209', 'p210', 'p58p267', 'p55p165', 'p209p275', 'p267', 'p128p235', 'p248p313', 'p161', 'p55p116', 'p55', 'p15p125', 'p205p276', 'p100p107', 'p54p230', 'p16p54', 'p100p292', 'p166p267', 'p40p314', 'p125p140', 'p76p314', 'p16p267', 'p140p234', 'p165p210', 'p141p275', 'p115p274', 'p16p141', 'p15p205', 'p33p171', 'p54p165', 'p58p210', 'p125p181', 'p16p209', 'p75p128', 'p140p275', 'p76p82', 'p100p235', 'p82p107', 'p107p146', 'p114p125', 'p248p315', 'p54p58', 'p166p223', 'p128p276', 'p75p314', 'p100p276', 'p15p166', 'p116p315', 'p76p140', 'p33p125', 'p40p210', 'p15p128', 'p146p292', 'p210p292', 'p243', 'p141p171', 'p248p267', 'p33p76', 'p146p166', 'p75p82', 'p267p274', 'p76p181', 'p40p55', 'p205p230', 'p15p235', 'p58p115', 'p171p205', 'p181p230', 'p292p313', 'p300', 'p16p114', 'p140p248', 'p15p314', 'p15p292', 'p82p274', 'p114p235', 'p209p248', 'p54p274', 'p0', 'p146p235', 'p114p292', 'p15p276', 'p114p166', 'p125p146', 'p15p82', 'p40p181', 'p116p209', 'p75p210', 'p210p235']
    sbox = ['p165p205', 'p69', 'p55p275', 'p40p115', 'p274p313', 'p15p33', 'p33p166', 'p58p205', 'p55p248', 'p33p234', 'p128p230', 'p107p313', 'p205', 'p100p230', 'p292p315', 'p276p315', 'p140p153', 'p128p153', 'p115p171', 'p107p141', 'p16p223', 'p314', 'p107p209', 'p33p292', 'p275p315', 'p15p55', 'p76p146', 'p82p171', 'p171p315', 'p166p314', 'p75p115', 'p40p205', 'p146p276', 'p205p274', 'p210p276', 'p141p166', 'p230p313', 'p55p171', 'p235p315', 'p15p230', 'p116p223', 'p209p292', 'p284', 'p33', 'p115p125', 'p165p314', 'p15p153', 'p116p146', 'p234p314', 'p15p181', 'p107p114', 'p58p314', 'p140', 'p15p115', 'p125p313', 'p115p234', 'p114p276', 'p153p315', 'p76p100', 'p54p75', 'p16p128', 'p16p33', 'p128p165', 'p146p153', 'p141p292', 'p100p165', 'p125p141', 'p171p181', 'p75p205', 'p210p230', 'p153p209', 'p54p171', 'p58p82', 'p140p235', 'p55p125', 'p54p76', 'p100p116', 'p141p234', 'p166p210', 'p209p235', 'p140p292', 'p55p76', 'p230p315', 'p114p153', 'p83', 'p58p140', 'p15p58', 'p115p166', 'p82p165', 'p165p181', 'p146p230', 'p153p181', 'p33p248', 'p33p153', 'p181', 'p125p315', 'p33p276', 'p230p267', 'p125p209', 'p82p116', 'p58p181', 'p181p274', 'p107p223', 'p54p116', 'p238', 'p16p314', 'p15p107', 'p76p209', 'p55p292', 'p82p234', 'p128p274', 'p115p292', 'p55p166', 'p100p274', 'p40p140', 'p116p313', 'p16p210', 'p209p276', 'p16p82', 'p55p234', 'p173', 'p248p314', 'p116p141', 'p16p55', 'p40p315', 'p55p235', 'p40p209', 'p223p234', 'p76p315', 'p192', 'p128p171', 'p141p276', 'p115p275', 'p76p141', 'p107p128', 'p54p166', 'p48', 'p115p248', 'p15p274', 'p116p267', 'p153p223', 'p75p140', 'p209p230', 'p54p234', 'p140p276', 'p267p275', 'p33p107', 'p107p314', 'p146p274', 'p58p146', 'p141p248', 'p210p274', 'p141p153', 'p75p315', 'p171p313', 'p33p58', 'p146', 'p235p313', 'p282', 'p15p140', 'p276p313', 'p76p114', 'p223p275', 'p116p210', 'p140p230', 'p114p274', 'p292p314', 'p115p153', 'p16p115', 'p166p205', 'p223p276', 'p275p313', 'p125p223', 'p40p146', 'p15p315', 'p125p128', 'p82p275', 'p15p209', 'p75p181', 'p54p275', 'p23', 'p33p274', 'p82p248', 'p275p314', 'p234p315', 'p107p210', 'p54p248', 'p100p171', 'p107p267', 'p205p234', 'p171p209', 'p55p153', 'p274p314', 'p223p248', 'p58p100', 'p16p205', 'p40p223', 'p33p235', 'p153p313', 'p75p146', 'p181p292', 'p100', 'p76p223', 'p82p125', 'p140p165', 'p58p313', 'p15p75', 'p179', 'p165p209', 'p58p141', 'p100p125', 'p181p234', 'p315', 'p107p115', 'p54p153', 'p166p181', 'p128p234', 'p166p315', 'p100p234', 'p40p100', 'p116p128', 'p205p275', 'p55p58', 'p181p275', 'p153p267', 'p116p205', 'p230p314', 'p125p267', 'p114p230', 'p40p313', 'p205p248', 'p141p235', 'p165p315', 'p76p313', 'p141p274', 'p15p165', 'p40p141', 'p76p128', 'p54p125', 'p58p315', 'p141', 'p58p209', 'p55p107', 'p15p116', 'p115p235', 'p16p140', 'p209', 'p140p274', 'p128p166', 'p33p75', 'p114', 'p146p165', 'p100p166', 'p40p54', 'p15p234', 'p15p223', 'p209p274', 'p75p100', 'p153p210', 'p125p210', 'p15p146', 'p115p276', 'p40p267', 'p15p40', 'p128p275', 'p16p315', 'p75p313', 'p76p267', 'p267p292', 'p82p292', 'p33p230', 'p171p223', 'p116p140', 'p75p141', 'p181p276', 'p114p165', 'p54p107', 'p84', 'p116p314', 'p82p166', 'p114p116', 'p55p274', 'p58p114', 'p223p235', 'p107p205', 'p33p165', 'p116p181', 'p223p292', 'p16p181', 'p33p116', 'p75p267', 'p165p223', 'p76p210', 'p82p235', 'p181p248', 'p54p235', 'p223', 'p100p275', 'p146p234', 'p75p209', 'p54p292', 'p141p230', 'p210p234', 'p128p248', 'p174', 'p33p40', 'p100p248', 'p40p114', 'p140p171', 'p82p276', 'p242', 'p2', 'p15p100', 'p115p230', 'p210p275', 'p55p276', 'p223p274', 'p15p313', 'p114p234', 'p205p235', 'p107p140', 'p165p313', 'p153p205', 'p58p223', 'p125p205', 'p15p141', 'p205p292', 'p15p275', 'p76p115', 'p234p313', 'p235p267', 'p128', 'p267p276', 'p114p275', 'p15p248', 'p107p181', 'p107p315', 'p75p114', 'p146p275', 'p100p153', 'p15p54', 'p16p146', 'p15p210', 'p171p314', 'p166p313', 'p235p314', 'p146p248', 'p15p267', 'p283', 'p223p230', 'p15p16', 'p210p248', 'p276p314', 'p40p128', 'p171p267', 'p55p75', 'p15p114', 'p82', 'p76p205', 'p58p128', 'p82p230', 'p274p315', 'p313', 'p115p165', 'p128p292', 'p15p171', 'p82p153', 'p15p76', 'p114p248', 'p153p314', 'p54p276', 'p24', 'p16p100', 'p55p230', 'p115p116', 'p125p314', 'p33p275', 'p114p171', 'p140p166', 'p209p234', 'p16p313', 'p141p165', 'p165p267', 'p146p171', 'p40p82', 'p171p210', 'p75p223', 'p181p235', 'p234p267', 'p54', 'p166p209', 'p210', 'p58p267', 'p55p165', 'p209p275', 'p267', 'p128p235', 'p248p313', 'p161', 'p55p116', 'p55', 'p15p125', 'p205p276', 'p100p107', 'p54p230', 'p16p54', 'p100p292', 'p166p267', 'p40p314', 'p125p140', 'p76p314', 'p16p267', 'p140p234', 'p165p210', 'p141p275', 'p115p274', 'p16p141', 'p15p205', 'p33p171', 'p54p165', 'p58p210', 'p125p181', 'p16p209', 'p75p128', 'p140p275', 'p76p82', 'p100p235', 'p82p107', 'p107p146', 'p114p125', 'p248p315', 'p54p58', 'p166p223', 'p128p276', 'p75p314', 'p100p276', 'p15p166', 'p116p315', 'p76p140', 'p33p125', 'p40p210', 'p15p128', 'p146p292', 'p210p292', 'p243', 'p141p171', 'p248p267', 'p33p76', 'p146p166', 'p75p82', 'p267p274', 'p76p181', 'p40p55', 'p205p230', 'p15p235', 'p58p115', 'p171p205', 'p181p230', 'p300', 'p292p313', 'p16p114', 'p140p248', 'p15p314', 'p15p292', 'p82p274', 'p114p235', 'p209p248', 'p54p274', 'p0', 'p146p235', 'p114p292', 'p15p276', 'p114p166', 'p125p146', 'p15p82', 'p40p181', 'p116p209', 'p75p210', 'p210p235']

    for monomial in circuit:
        if monomial not in sbox:
            print("######## different")
            return 0
    print("######## equal")

