import time
from gurobipy import *
from sage.crypto.sbox import SBox
from sage.crypto.boolean_function import BooleanFunction
from collections import Counter
from sage.rings.polynomial.pbori.pbori import BooleanPolynomialRing
from claasp.name_mappings import (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT,
                                  WORD_OPERATION, LINEAR_LAYER, SBOX, MIX_COLUMN)
import networkx as nx
from claasp.cipher_modules.graph_generator import create_networkx_graph_from_input_ids, _get_predecessors_subgraph


class MilpDivisionTrailModel():
    """
    EXAMPLES::

        sage: from claasp.ciphers.permutations.ascon_permutation import AsconPermutation
        sage: cipher = AsconPermutation(number_of_rounds=1)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_of_specific_output_bit(0)

        sage: from claasp.ciphers.permutations.ascon_sbox_sigma_no_matrix_permutation import AsconSboxSigmaNoMatrixPermutation
        sage: cipher = AsconSboxSigmaNoMatrixPermutation(number_of_rounds=1)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_of_specific_output_bit(0)

        sage: from claasp.ciphers.permutations.gaston_permutation import GastonPermutation
        sage: cipher = GastonPermutation(number_of_rounds=1)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_of_specific_output_bit(0)

        sage: from claasp.ciphers.permutations.gaston_sbox_permutation import GastonSboxPermutation
        sage: cipher = GastonSboxPermutation(number_of_rounds=1)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_of_specific_output_bit(0)

        sage: from claasp.ciphers.permutations.xoodoo_sbox_permutation import XoodooSboxPermutation
        sage: cipher = XoodooSboxPermutation(number_of_rounds=1)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_of_specific_output_bit(0)

        sage: from claasp.ciphers.permutations.xoodoo_permutation import XoodooPermutation
        sage: cipher = XoodooPermutation(number_of_rounds=1)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_of_specific_output_bit(0)

        sage: from claasp.ciphers.permutations.keccak_permutation import KeccakPermutation
        sage: cipher = KeccakPermutation(number_of_rounds=1, word_size=64)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_of_specific_output_bit(0)

        sage: from claasp.ciphers.permutations.keccak_sbox_permutation import KeccakSboxPermutation
        sage: cipher = KeccakSboxPermutation(number_of_rounds=1, word_size=64)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_of_specific_output_bit(0)

        sage: from claasp.ciphers.toys.toyspn1 import ToySPN1
        sage: cipher = ToySPN1(number_of_rounds=1)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_for_specific_output_bit(1)

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

        sage: from claasp.ciphers.toys.toyand_v3 import ToyAND
        sage: cipher = ToyAND()
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_for_specific_output_bit(0)

        sage: from claasp.ciphers.toys.toymodadd import ToyMODADD
        sage: cipher = ToyMODADD()
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
        sage: milp.find_anf_of_specific_output_bit(0)

        sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
        sage: cipher = SimonBlockCipher(number_of_rounds=1)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.check_presence_of_particular_monomial_in_specific_anf([("plaintext", 0)], 1)

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: cipher = SpeckBlockCipher(number_of_rounds=1)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_of_specific_output_bit(15)

        sage: from claasp.ciphers.block_ciphers.lblock_block_cipher import LBlockBlockCipher
        sage: cipher = LBlockBlockCipher(number_of_rounds=1)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_of_specific_output_bit(0)

        sage: from claasp.ciphers.block_ciphers.aradi_block_cipher import AradiBlockCipher
        sage: cipher = AradiBlockCipher(number_of_rounds=1)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_of_specific_output_bit(0)

        sage: from claasp.ciphers.block_ciphers.aradi_block_cipher_sbox import AradiBlockCipherSBox
        sage: cipher = AradiBlockCipherSBox(number_of_rounds=1)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_of_specific_output_bit(0)

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

        input_vars_concat = []
        for index, input_name in enumerate(component.input_id_links):
            for pos in component.input_bit_positions[index]:
                current = self._variables[input_name][pos]["current"]
                input_vars_concat.append(self._variables[input_name][pos][current])
                self._variables[input_name][pos]["current"] += 1

        for index, bit_pos in enumerate(list(self._occurences[component.id].keys())):
            self._model.addConstr(output_vars[index] == input_vars_concat[index])
            self.set_as_used_variables([input_vars_concat[index]])
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
        print(f'Number of monomials found: {len(l)}')
        print(l)

    def add_constraints(self, predecessors, input_id_link_needed, block_needed):
        self.build_gurobi_model()
        self.create_gurobi_vars_from_all_components(predecessors, input_id_link_needed, block_needed)
        word_operations_types = ['AND', 'MODADD', 'MODSUB', 'NOT', 'OR', 'ROTATE', 'SHIFT', 'XOR']

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
                if (name in component.input_id_links) and (component.type not in ["cipher_output"]):
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
        # output_id = "modadd_1_7"
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

        # input_id_link_needed = "rot_1_6"
        # block_needed = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]

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

    # # Ascon circuit version, checked by hand for y0
    # ['p64p256', 'p109p301', 'p128', 'p109p45', 'p64p0', 'p192', 'p0', 'p109', 'p100', 'p100p164', 'p45', 'p173', 'p237', 'p164', 'p228', 'p109p173', 'p100p292', 'p64', 'p100p36', 'p64p128', 'p36']

    # Simon y0 round 2 checked by hand:
    # ['p3p24', 'p2p9p24', 'p0p9p17', 'k50', 'p0p3p9', 'k32', 'p18', 'p2p9p10', 'p24k49', 'p0', 'p10k49', 'k49k56', 'p17k56', 'p0p2p9', 'p4', 'p10p17', 'p2p9k56', 'p17p24', 'p0p9k49', 'p3k56']

    # Speck y_round2[15]:
    # y_round1[8] = ['p2p3p5p8p27p29p30p31', 'p3p5p7p8p25p27p29p31', 'p2p5p8p26p27p29p30p31', 'p2p3p6p27p28p29', 'p2p3p5p6p8p27p30p31', 'p5p6p7p25p26p27p30', 'p2p5p6p26p27p29', 'p2p4p26p27', 'p2p4p8p26p28p29p30p31', 'k56', 'p3p5p6p7p25p27p30', 'p2p3p4p5p7p29p30', 'p2p5p6p8p26p27p30p31', 'p3p4p5p6p7p8p25p31', 'p4p6p7p25p26p28p30', 'p24', 'p8p25p26p27p28p29p30p31', 'p2p3p4p6p8p28p30p31', 'p3p4p5p7p8p25p29p31', 'p5p6p25p26p27p29', 'p6p7p8p25p26p27p28p31', 'p2p5p26p27p28', 'p4p6p25p26p28p29', 'p2p4p7p26p28p29p30', 'p3p5p6p8p25p27p30p31', 'p2p3p5p6p27p29', 'p4p7p25p26p28p29p30', 'p3p5p25p27p28', 'p6p7p25p26p27p28p30', 'p2p6p8p26p27p28p30p31', 'p2p3p5p27p28', 'p2p4p6p26p28p29', 'p4p8p25p26p28p29p30p31', 'p3p4p25p27', 'p3p4p5p8p25p29p30p31', 'p2p3p6p8p27p28p30p31', 'p2p5p7p26p27p29p30', 'p2p3p4p5p28', 'p3p4p6p25p28p29', 'p2p3p4p6p7p28p30', 'p2p6p26p27p28p29', 'p2p3p7p8p27p28p29p31', 'p3p4p7p8p25p28p29p31', 'p2p4p5p6p8p26p30p31', 'p2p3p4p6p7p8p28p31', 'p2p4p5p6p7p8p26p31', 'p3p4p5p6p7p25p30', 'p2p3p4p5p7p8p29p31', 'p2p3p4p5p6p7p30', 'p2p3p4p5p8p29p30p31', 'p6p8p25p26p27p28p30p31', 'p3p6p7p8p25p27p28p31', 'p2p3p6p7p8p27p28p31', 'p4p6p7p8p25p26p28p31', 'p2p3p4p7p8p28p29p31', 'p3p7p25p27p28p29p30', 'p2p3p5p6p7p27p30', 'p2p4p5p6p7p26p30', 'p5p6p8p25p26p27p30p31', 'p3p5p6p7p8p25p27p31', 'p3p25p26', 'p2p4p6p7p26p28p30', 'p4p5p25p26p28', 'p2p6p7p26p27p28p30', 'p2p3p6p7p27p28p30', 'p3p7p8p25p27p28p29p31', 'p2p6p7p8p26p27p28p31', 'p2p4p6p8p26p28p30p31', 'p3p4p6p8p25p28p30p31', 'p4p5p6p7p8p25p26p31', 'p3p6p8p25p27p28p30p31', 'p2p3p5p7p27p29p30', 'p4p5p7p8p25p26p29p31', 'p2p5p6p7p26p27p30', 'p2p4p6p7p8p26p28p31', 'p2p3p5p7p8p27p29p31', 'p2p4p7p8p26p28p29p31', 'p4p5p6p25p26p29', 'p2p4p5p8p26p29p30p31', 'p3p6p25p27p28p29', 'p2p3p7p27p28p29p30', 'p5p6p7p8p25p26p27p31', 'p2p3p4p7p28p29p30', 'p2p3p8p27p28p29p30p31', 'p2p4p5p7p26p29p30', 'p2p4p5p6p26p29', 'p3p4p8p25p28p29p30p31', 'p3p4p5p6p8p25p30p31', 'p3p8p25p27p28p29p30p31', 'p2p5p7p8p26p27p29p31', 'p2p8p26p27p28p29p30p31', 'p3p5p8p25p27p29p30p31', 'p4p25p26p27', 'p2p7p8p26p27p28p29p31', 'p5p7p25p26p27p29p30', 'p3p4p5p25p28', 'p2p3p4p5p6p29', 'p5p25p26p27p28', 'p2p3p4p8p28p29p30p31', 'p4p5p6p7p25p26p30', 'p3p5p6p25p27p29', 'p5p8p25p26p27p29p30p31', 'p2p3p4p27', 'p7p25p26p27p28p29p30', 'p3p4p6p7p8p25p28p31', 'p2p4p5p26p28', 'p4p6p8p25p26p28p30p31', 'p3p4p5p7p25p29p30', 'p2p3p4p5p6p7p8p31', 'p2p5p6p7p8p26p27p31', 'p4p5p8p25p26p29p30p31', 'p3p4p7p25p28p29p30', 'p3p4p5p6p25p29', 'p2p3p5p6p7p8p27p31', 'p4p5p7p25p26p29p30', 'p2p7p26p27p28p29p30', 'p2p3p4p5p6p8p30p31', 'p4p7p8p25p26p28p29p31', 'p2p3p4p6p28p29', 'p7p8p25p26p27p28p29p31', 'p3p4p6p7p25p28p30', 'p3p5p7p25p27p29p30', 'p6p25p26p27p28p29', 'p2p4p5p7p8p26p29p31', 'p2p3p26', 'p4p5p6p8p25p26p30p31', 'p1', 'p3p6p7p25p27p28p30', 'p5p7p8p25p26p27p29p31', 'p2p25']
    # y_round2[15] = k40 + k49 + y_round1[31] + y_round1[8]
    # Note that rot_1_6[6] = y_round1[15] = p8 + p31 + k63

    def find_degree_of_specific_anf(self, output_bit_index):
        fixed_degree = None
        self.build_generic_model_for_specific_output_bit(output_bit_index, fixed_degree)

        index_plaintext = self._cipher.inputs.index("plaintext")
        plaintext_bit_size = self._cipher.inputs_bit_size[index_plaintext]
        p = []
        nb_plaintext_bits_used = len(list(self._occurences["plaintext"].keys()))
        for i in range(nb_plaintext_bits_used):
            p.append(self._model.getVarByName(f"plaintext[{i}]"))
        print(p)
        self._model.setObjective(sum(p[i] for i in range(nb_plaintext_bits_used)), GRB.MAXIMIZE)

        self._model.update()
        self._model.write("division_trail_model.lp")

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


def test():
    """
    from claasp.cipher_modules.division_trail_search import *
    test()
    """
    circuit = ['p165p205', 'p69', 'p55p275', 'p40p115', 'p274p313', 'p15p33', 'p33p166', 'p58p205', 'p55p248',
               'p33p234', 'p128p230', 'p107p313', 'p205', 'p100p230', 'p292p315', 'p276p315', 'p140p153', 'p128p153',
               'p115p171', 'p107p141', 'p16p223', 'p314', 'p107p209', 'p33p292', 'p275p315', 'p15p55', 'p76p146',
               'p82p171', 'p171p315', 'p166p314', 'p75p115', 'p40p205', 'p146p276', 'p205p274', 'p210p276', 'p141p166',
               'p230p313', 'p55p171', 'p235p315', 'p15p230', 'p116p223', 'p209p292', 'p284', 'p33', 'p115p125',
               'p165p314', 'p15p153', 'p116p146', 'p234p314', 'p15p181', 'p107p114', 'p58p314', 'p140', 'p15p115',
               'p125p313', 'p115p234', 'p114p276', 'p153p315', 'p76p100', 'p54p75', 'p16p128', 'p16p33', 'p128p165',
               'p146p153', 'p141p292', 'p100p165', 'p125p141', 'p171p181', 'p75p205', 'p210p230', 'p153p209', 'p54p171',
               'p58p82', 'p140p235', 'p55p125', 'p54p76', 'p100p116', 'p141p234', 'p166p210', 'p209p235', 'p140p292',
               'p55p76', 'p230p315', 'p114p153', 'p83', 'p58p140', 'p15p58', 'p115p166', 'p82p165', 'p165p181',
               'p146p230', 'p153p181', 'p33p248', 'p33p153', 'p181', 'p125p315', 'p33p276', 'p230p267', 'p125p209',
               'p82p116', 'p58p181', 'p181p274', 'p107p223', 'p54p116', 'p238', 'p16p314', 'p15p107', 'p76p209',
               'p55p292', 'p82p234', 'p128p274', 'p115p292', 'p55p166', 'p100p274', 'p40p140', 'p116p313', 'p16p210',
               'p209p276', 'p16p82', 'p55p234', 'p173', 'p248p314', 'p116p141', 'p16p55', 'p40p315', 'p55p235',
               'p40p209', 'p223p234', 'p76p315', 'p192', 'p128p171', 'p141p276', 'p115p275', 'p76p141', 'p107p128',
               'p54p166', 'p48', 'p115p248', 'p15p274', 'p116p267', 'p153p223', 'p75p140', 'p209p230', 'p54p234',
               'p140p276', 'p267p275', 'p33p107', 'p107p314', 'p146p274', 'p58p146', 'p141p248', 'p210p274', 'p171p313',
               'p75p315', 'p141p153', 'p33p58', 'p146', 'p235p313', 'p282', 'p15p140', 'p276p313', 'p76p114',
               'p223p275', 'p116p210', 'p140p230', 'p114p274', 'p292p314', 'p115p153', 'p16p115', 'p166p205',
               'p223p276', 'p275p313', 'p125p223', 'p40p146', 'p15p315', 'p125p128', 'p82p275', 'p15p209', 'p75p181',
               'p54p275', 'p23', 'p33p274', 'p82p248', 'p275p314', 'p234p315', 'p107p210', 'p54p248', 'p100p171',
               'p107p267', 'p205p234', 'p171p209', 'p55p153', 'p274p314', 'p223p248', 'p58p100', 'p16p205', 'p40p223',
               'p33p235', 'p153p313', 'p75p146', 'p181p292', 'p100', 'p76p223', 'p82p125', 'p140p165', 'p58p313',
               'p15p75', 'p179', 'p165p209', 'p58p141', 'p100p125', 'p181p234', 'p315', 'p107p115', 'p54p153',
               'p166p181', 'p128p234', 'p166p315', 'p100p234', 'p40p100', 'p116p128', 'p205p275', 'p55p58', 'p181p275',
               'p153p267', 'p116p205', 'p230p314', 'p125p267', 'p114p230', 'p40p313', 'p205p248', 'p141p235',
               'p165p315', 'p76p313', 'p141p274', 'p15p165', 'p40p141', 'p76p128', 'p54p125', 'p58p315', 'p141',
               'p58p209', 'p55p107', 'p15p116', 'p115p235', 'p16p140', 'p209', 'p140p274', 'p128p166', 'p33p75', 'p114',
               'p146p165', 'p100p166', 'p40p54', 'p15p234', 'p15p223', 'p209p274', 'p75p100', 'p153p210', 'p125p210',
               'p15p146', 'p115p276', 'p40p267', 'p15p40', 'p128p275', 'p75p313', 'p16p315', 'p76p267', 'p267p292',
               'p82p292', 'p33p230', 'p171p223', 'p116p140', 'p75p141', 'p181p276', 'p114p165', 'p54p107', 'p84',
               'p116p314', 'p82p166', 'p114p116', 'p55p274', 'p58p114', 'p223p235', 'p107p205', 'p33p165', 'p116p181',
               'p223p292', 'p16p181', 'p33p116', 'p75p267', 'p165p223', 'p76p210', 'p82p235', 'p181p248', 'p54p235',
               'p223', 'p100p275', 'p146p234', 'p75p209', 'p54p292', 'p141p230', 'p210p234', 'p128p248', 'p174',
               'p33p40', 'p100p248', 'p40p114', 'p140p171', 'p82p276', 'p242', 'p2', 'p15p100', 'p115p230', 'p210p275',
               'p55p276', 'p223p274', 'p15p313', 'p114p234', 'p205p235', 'p107p140', 'p165p313', 'p153p205', 'p58p223',
               'p125p205', 'p15p141', 'p205p292', 'p15p275', 'p76p115', 'p234p313', 'p235p267', 'p128', 'p267p276',
               'p114p275', 'p15p248', 'p107p181', 'p107p315', 'p75p114', 'p146p275', 'p100p153', 'p15p54', 'p16p146',
               'p15p210', 'p171p314', 'p166p313', 'p235p314', 'p146p248', 'p15p267', 'p283', 'p223p230', 'p15p16',
               'p210p248', 'p276p314', 'p40p128', 'p171p267', 'p55p75', 'p15p114', 'p82', 'p76p205', 'p58p128',
               'p82p230', 'p274p315', 'p313', 'p115p165', 'p128p292', 'p15p171', 'p82p153', 'p15p76', 'p114p248',
               'p153p314', 'p54p276', 'p24', 'p16p100', 'p55p230', 'p115p116', 'p125p314', 'p33p275', 'p114p171',
               'p140p166', 'p209p234', 'p16p313', 'p141p165', 'p165p267', 'p146p171', 'p40p82', 'p171p210', 'p75p223',
               'p181p235', 'p234p267', 'p54', 'p166p209', 'p210', 'p58p267', 'p55p165', 'p209p275', 'p267', 'p128p235',
               'p248p313', 'p161', 'p55p116', 'p55', 'p15p125', 'p205p276', 'p100p107', 'p54p230', 'p16p54', 'p100p292',
               'p166p267', 'p40p314', 'p125p140', 'p76p314', 'p16p267', 'p140p234', 'p165p210', 'p141p275', 'p115p274',
               'p16p141', 'p15p205', 'p33p171', 'p54p165', 'p58p210', 'p125p181', 'p16p209', 'p75p128', 'p140p275',
               'p76p82', 'p100p235', 'p82p107', 'p107p146', 'p114p125', 'p248p315', 'p54p58', 'p166p223', 'p128p276',
               'p75p314', 'p100p276', 'p15p166', 'p116p315', 'p76p140', 'p33p125', 'p40p210', 'p15p128', 'p146p292',
               'p210p292', 'p243', 'p141p171', 'p248p267', 'p33p76', 'p146p166', 'p75p82', 'p267p274', 'p76p181',
               'p40p55', 'p205p230', 'p15p235', 'p58p115', 'p171p205', 'p181p230', 'p292p313', 'p300', 'p16p114',
               'p140p248', 'p15p314', 'p15p292', 'p82p274', 'p114p235', 'p209p248', 'p54p274', 'p0', 'p146p235',
               'p114p292', 'p15p276', 'p114p166', 'p125p146', 'p15p82', 'p40p181', 'p116p209', 'p75p210', 'p210p235']
    sbox = ['p165p205', 'p69', 'p55p275', 'p40p115', 'p274p313', 'p15p33', 'p33p166', 'p58p205', 'p55p248', 'p33p234',
            'p128p230', 'p107p313', 'p205', 'p100p230', 'p292p315', 'p276p315', 'p140p153', 'p128p153', 'p115p171',
            'p107p141', 'p16p223', 'p314', 'p107p209', 'p33p292', 'p275p315', 'p15p55', 'p76p146', 'p82p171',
            'p171p315', 'p166p314', 'p75p115', 'p40p205', 'p146p276', 'p205p274', 'p210p276', 'p141p166', 'p230p313',
            'p55p171', 'p235p315', 'p15p230', 'p116p223', 'p209p292', 'p284', 'p33', 'p115p125', 'p165p314', 'p15p153',
            'p116p146', 'p234p314', 'p15p181', 'p107p114', 'p58p314', 'p140', 'p15p115', 'p125p313', 'p115p234',
            'p114p276', 'p153p315', 'p76p100', 'p54p75', 'p16p128', 'p16p33', 'p128p165', 'p146p153', 'p141p292',
            'p100p165', 'p125p141', 'p171p181', 'p75p205', 'p210p230', 'p153p209', 'p54p171', 'p58p82', 'p140p235',
            'p55p125', 'p54p76', 'p100p116', 'p141p234', 'p166p210', 'p209p235', 'p140p292', 'p55p76', 'p230p315',
            'p114p153', 'p83', 'p58p140', 'p15p58', 'p115p166', 'p82p165', 'p165p181', 'p146p230', 'p153p181',
            'p33p248', 'p33p153', 'p181', 'p125p315', 'p33p276', 'p230p267', 'p125p209', 'p82p116', 'p58p181',
            'p181p274', 'p107p223', 'p54p116', 'p238', 'p16p314', 'p15p107', 'p76p209', 'p55p292', 'p82p234',
            'p128p274', 'p115p292', 'p55p166', 'p100p274', 'p40p140', 'p116p313', 'p16p210', 'p209p276', 'p16p82',
            'p55p234', 'p173', 'p248p314', 'p116p141', 'p16p55', 'p40p315', 'p55p235', 'p40p209', 'p223p234', 'p76p315',
            'p192', 'p128p171', 'p141p276', 'p115p275', 'p76p141', 'p107p128', 'p54p166', 'p48', 'p115p248', 'p15p274',
            'p116p267', 'p153p223', 'p75p140', 'p209p230', 'p54p234', 'p140p276', 'p267p275', 'p33p107', 'p107p314',
            'p146p274', 'p58p146', 'p141p248', 'p210p274', 'p141p153', 'p75p315', 'p171p313', 'p33p58', 'p146',
            'p235p313', 'p282', 'p15p140', 'p276p313', 'p76p114', 'p223p275', 'p116p210', 'p140p230', 'p114p274',
            'p292p314', 'p115p153', 'p16p115', 'p166p205', 'p223p276', 'p275p313', 'p125p223', 'p40p146', 'p15p315',
            'p125p128', 'p82p275', 'p15p209', 'p75p181', 'p54p275', 'p23', 'p33p274', 'p82p248', 'p275p314', 'p234p315',
            'p107p210', 'p54p248', 'p100p171', 'p107p267', 'p205p234', 'p171p209', 'p55p153', 'p274p314', 'p223p248',
            'p58p100', 'p16p205', 'p40p223', 'p33p235', 'p153p313', 'p75p146', 'p181p292', 'p100', 'p76p223', 'p82p125',
            'p140p165', 'p58p313', 'p15p75', 'p179', 'p165p209', 'p58p141', 'p100p125', 'p181p234', 'p315', 'p107p115',
            'p54p153', 'p166p181', 'p128p234', 'p166p315', 'p100p234', 'p40p100', 'p116p128', 'p205p275', 'p55p58',
            'p181p275', 'p153p267', 'p116p205', 'p230p314', 'p125p267', 'p114p230', 'p40p313', 'p205p248', 'p141p235',
            'p165p315', 'p76p313', 'p141p274', 'p15p165', 'p40p141', 'p76p128', 'p54p125', 'p58p315', 'p141', 'p58p209',
            'p55p107', 'p15p116', 'p115p235', 'p16p140', 'p209', 'p140p274', 'p128p166', 'p33p75', 'p114', 'p146p165',
            'p100p166', 'p40p54', 'p15p234', 'p15p223', 'p209p274', 'p75p100', 'p153p210', 'p125p210', 'p15p146',
            'p115p276', 'p40p267', 'p15p40', 'p128p275', 'p16p315', 'p75p313', 'p76p267', 'p267p292', 'p82p292',
            'p33p230', 'p171p223', 'p116p140', 'p75p141', 'p181p276', 'p114p165', 'p54p107', 'p84', 'p116p314',
            'p82p166', 'p114p116', 'p55p274', 'p58p114', 'p223p235', 'p107p205', 'p33p165', 'p116p181', 'p223p292',
            'p16p181', 'p33p116', 'p75p267', 'p165p223', 'p76p210', 'p82p235', 'p181p248', 'p54p235', 'p223',
            'p100p275', 'p146p234', 'p75p209', 'p54p292', 'p141p230', 'p210p234', 'p128p248', 'p174', 'p33p40',
            'p100p248', 'p40p114', 'p140p171', 'p82p276', 'p242', 'p2', 'p15p100', 'p115p230', 'p210p275', 'p55p276',
            'p223p274', 'p15p313', 'p114p234', 'p205p235', 'p107p140', 'p165p313', 'p153p205', 'p58p223', 'p125p205',
            'p15p141', 'p205p292', 'p15p275', 'p76p115', 'p234p313', 'p235p267', 'p128', 'p267p276', 'p114p275',
            'p15p248', 'p107p181', 'p107p315', 'p75p114', 'p146p275', 'p100p153', 'p15p54', 'p16p146', 'p15p210',
            'p171p314', 'p166p313', 'p235p314', 'p146p248', 'p15p267', 'p283', 'p223p230', 'p15p16', 'p210p248',
            'p276p314', 'p40p128', 'p171p267', 'p55p75', 'p15p114', 'p82', 'p76p205', 'p58p128', 'p82p230', 'p274p315',
            'p313', 'p115p165', 'p128p292', 'p15p171', 'p82p153', 'p15p76', 'p114p248', 'p153p314', 'p54p276', 'p24',
            'p16p100', 'p55p230', 'p115p116', 'p125p314', 'p33p275', 'p114p171', 'p140p166', 'p209p234', 'p16p313',
            'p141p165', 'p165p267', 'p146p171', 'p40p82', 'p171p210', 'p75p223', 'p181p235', 'p234p267', 'p54',
            'p166p209', 'p210', 'p58p267', 'p55p165', 'p209p275', 'p267', 'p128p235', 'p248p313', 'p161', 'p55p116',
            'p55', 'p15p125', 'p205p276', 'p100p107', 'p54p230', 'p16p54', 'p100p292', 'p166p267', 'p40p314',
            'p125p140', 'p76p314', 'p16p267', 'p140p234', 'p165p210', 'p141p275', 'p115p274', 'p16p141', 'p15p205',
            'p33p171', 'p54p165', 'p58p210', 'p125p181', 'p16p209', 'p75p128', 'p140p275', 'p76p82', 'p100p235',
            'p82p107', 'p107p146', 'p114p125', 'p248p315', 'p54p58', 'p166p223', 'p128p276', 'p75p314', 'p100p276',
            'p15p166', 'p116p315', 'p76p140', 'p33p125', 'p40p210', 'p15p128', 'p146p292', 'p210p292', 'p243',
            'p141p171', 'p248p267', 'p33p76', 'p146p166', 'p75p82', 'p267p274', 'p76p181', 'p40p55', 'p205p230',
            'p15p235', 'p58p115', 'p171p205', 'p181p230', 'p300', 'p292p313', 'p16p114', 'p140p248', 'p15p314',
            'p15p292', 'p82p274', 'p114p235', 'p209p248', 'p54p274', 'p0', 'p146p235', 'p114p292', 'p15p276',
            'p114p166', 'p125p146', 'p15p82', 'p40p181', 'p116p209', 'p75p210', 'p210p235']
    new = ['p165p205', 'p69', 'p55p275', 'p40p115', 'p274p313', 'p15p33', 'p33p166', 'p58p205', 'p55p248', 'p33p234',
           'p128p230', 'p107p313', 'p205', 'p100p230', 'p292p315', 'p276p315', 'p140p153', 'p128p153', 'p115p171',
           'p107p141', 'p16p223', 'p314', 'p107p209', 'p33p292', 'p275p315', 'p15p55', 'p76p146', 'p82p171', 'p171p315',
           'p166p314', 'p75p115', 'p40p205', 'p146p276', 'p205p274', 'p210p276', 'p141p166', 'p230p313', 'p55p171',
           'p235p315', 'p15p230', 'p116p223', 'p209p292', 'p284', 'p33', 'p115p125', 'p165p314', 'p15p153', 'p116p146',
           'p234p314', 'p15p181', 'p107p114', 'p58p314', 'p140', 'p15p115', 'p125p313', 'p115p234', 'p114p276',
           'p153p315', 'p76p100', 'p54p75', 'p16p128', 'p16p33', 'p128p165', 'p146p153', 'p141p292', 'p100p165',
           'p125p141', 'p171p181', 'p75p205', 'p210p230', 'p153p209', 'p54p171', 'p58p82', 'p140p235', 'p55p125',
           'p54p76', 'p100p116', 'p141p234', 'p166p210', 'p209p235', 'p140p292', 'p55p76', 'p230p315', 'p114p153',
           'p83', 'p58p140', 'p15p58', 'p115p166', 'p82p165', 'p165p181', 'p146p230', 'p153p181', 'p33p248', 'p33p153',
           'p181', 'p125p315', 'p33p276', 'p230p267', 'p125p209', 'p82p116', 'p58p181', 'p181p274', 'p107p223',
           'p54p116', 'p238', 'p16p314', 'p15p107', 'p76p209', 'p55p292', 'p82p234', 'p128p274', 'p115p292', 'p55p166',
           'p100p274', 'p40p140', 'p116p313', 'p16p210', 'p209p276', 'p16p82', 'p55p234', 'p173', 'p248p314',
           'p116p141', 'p16p55', 'p40p315', 'p55p235', 'p40p209', 'p223p234', 'p76p315', 'p192', 'p128p171', 'p141p276',
           'p115p275', 'p76p141', 'p107p128', 'p54p166', 'p48', 'p115p248', 'p15p274', 'p116p267', 'p153p223',
           'p75p140', 'p209p230', 'p54p234', 'p140p276', 'p267p275', 'p33p107', 'p107p314', 'p146p274', 'p58p146',
           'p141p248', 'p210p274', 'p141p153', 'p75p315', 'p171p313', 'p33p58', 'p146', 'p235p313', 'p282', 'p15p140',
           'p276p313', 'p76p114', 'p223p275', 'p116p210', 'p140p230', 'p114p274', 'p292p314', 'p115p153', 'p16p115',
           'p166p205', 'p223p276', 'p275p313', 'p125p223', 'p40p146', 'p15p315', 'p125p128', 'p82p275', 'p15p209',
           'p75p181', 'p54p275', 'p23', 'p33p274', 'p82p248', 'p275p314', 'p234p315', 'p107p210', 'p54p248', 'p100p171',
           'p107p267', 'p205p234', 'p171p209', 'p55p153', 'p274p314', 'p223p248', 'p58p100', 'p16p205', 'p40p223',
           'p33p235', 'p153p313', 'p75p146', 'p181p292', 'p100', 'p76p223', 'p82p125', 'p140p165', 'p58p313', 'p15p75',
           'p179', 'p165p209', 'p58p141', 'p100p125', 'p181p234', 'p315', 'p107p115', 'p54p153', 'p166p181', 'p128p234',
           'p166p315', 'p100p234', 'p40p100', 'p116p128', 'p205p275', 'p55p58', 'p181p275', 'p153p267', 'p116p205',
           'p230p314', 'p125p267', 'p114p230', 'p40p313', 'p205p248', 'p141p235', 'p165p315', 'p76p313', 'p141p274',
           'p15p165', 'p40p141', 'p76p128', 'p54p125', 'p58p315', 'p141', 'p58p209', 'p55p107', 'p15p116', 'p115p235',
           'p16p140', 'p209', 'p140p274', 'p128p166', 'p33p75', 'p114', 'p146p165', 'p100p166', 'p40p54', 'p15p234',
           'p15p223', 'p209p274', 'p75p100', 'p153p210', 'p125p210', 'p15p146', 'p115p276', 'p40p267', 'p15p40',
           'p128p275', 'p16p315', 'p75p313', 'p76p267', 'p267p292', 'p82p292', 'p33p230', 'p171p223', 'p116p140',
           'p75p141', 'p181p276', 'p114p165', 'p54p107', 'p84', 'p116p314', 'p82p166', 'p114p116', 'p55p274', 'p58p114',
           'p223p235', 'p107p205', 'p33p165', 'p116p181', 'p223p292', 'p16p181', 'p33p116', 'p75p267', 'p165p223',
           'p76p210', 'p82p235', 'p181p248', 'p54p235', 'p223', 'p100p275', 'p146p234', 'p75p209', 'p54p292',
           'p141p230', 'p210p234', 'p128p248', 'p174', 'p33p40', 'p100p248', 'p40p114', 'p140p171', 'p82p276', 'p242',
           'p2', 'p15p100', 'p115p230', 'p210p275', 'p55p276', 'p223p274', 'p15p313', 'p114p234', 'p205p235',
           'p107p140', 'p165p313', 'p153p205', 'p58p223', 'p125p205', 'p15p141', 'p205p292', 'p15p275', 'p76p115',
           'p234p313', 'p235p267', 'p128', 'p267p276', 'p114p275', 'p15p248', 'p107p181', 'p107p315', 'p75p114',
           'p146p275', 'p100p153', 'p15p54', 'p16p146', 'p15p210', 'p171p314', 'p166p313', 'p235p314', 'p146p248',
           'p15p267', 'p283', 'p223p230', 'p15p16', 'p210p248', 'p276p314', 'p40p128', 'p171p267', 'p55p75', 'p15p114',
           'p82', 'p76p205', 'p58p128', 'p82p230', 'p274p315', 'p313', 'p115p165', 'p128p292', 'p15p171', 'p82p153',
           'p15p76', 'p114p248', 'p153p314', 'p54p276', 'p24', 'p16p100', 'p55p230', 'p115p116', 'p125p314', 'p33p275',
           'p114p171', 'p140p166', 'p209p234', 'p16p313', 'p141p165', 'p165p267', 'p146p171', 'p40p82', 'p171p210',
           'p75p223', 'p181p235', 'p234p267', 'p54', 'p166p209', 'p210', 'p58p267', 'p55p165', 'p209p275', 'p267',
           'p128p235', 'p248p313', 'p161', 'p55p116', 'p55', 'p15p125', 'p205p276', 'p100p107', 'p54p230', 'p16p54',
           'p100p292', 'p166p267', 'p40p314', 'p125p140', 'p76p314', 'p16p267', 'p140p234', 'p165p210', 'p141p275',
           'p115p274', 'p16p141', 'p15p205', 'p33p171', 'p54p165', 'p58p210', 'p125p181', 'p16p209', 'p75p128',
           'p140p275', 'p76p82', 'p100p235', 'p82p107', 'p107p146', 'p114p125', 'p248p315', 'p54p58', 'p166p223',
           'p128p276', 'p75p314', 'p100p276', 'p15p166', 'p116p315', 'p76p140', 'p33p125', 'p40p210', 'p15p128',
           'p146p292', 'p210p292', 'p243', 'p141p171', 'p248p267', 'p33p76', 'p146p166', 'p75p82', 'p267p274',
           'p76p181', 'p40p55', 'p205p230', 'p15p235', 'p58p115', 'p171p205', 'p181p230', 'p300', 'p292p313', 'p16p114',
           'p140p248', 'p15p314', 'p15p292', 'p82p274', 'p114p235', 'p209p248', 'p54p274', 'p0', 'p146p235', 'p114p292',
           'p15p276', 'p114p166', 'p125p146', 'p15p82', 'p40p181', 'p116p209', 'p75p210', 'p210p235']

    new_ascon = ['p228', 'p173', 'p164', 'p109', 'p109p301', 'p0', 'p173p109', 'p164p100', 'p100p292', 'p45p109',
                 'p100', 'p128', 'p192', 'p64p256', 'p45', 'p128p64', 'p36p100', 'p237', 'p0p64', 'p64', 'p36']
    checked_by_hand_ascon = ['p64p256', 'p109p301', 'p128', 'p109p45', 'p64p0', 'p192', 'p0', 'p109', 'p100',
                             'p100p164', 'p45', 'p173', 'p237', 'p164', 'p228', 'p109p173', 'p100p292', 'p64',
                             'p100p36', 'p64p128', 'p36']

    for monomial in new_ascon:
        if monomial not in checked_by_hand_ascon:
            print(f"######## different : {monomial}")
            return 0
    print("######## equal")


# Ascon 1 round circuit matchs sbox:
y0 = ['p128', 'p109p301', 'p64p256', 'p0', 'p192', 'p109', 'p100', 'p109p45', 'p100p164', 'p173', 'p45', 'p164', 'p237',
      'p100p36', 'p109p173', 'p36', 'p228', 'p64', 'p100p292', 'p64p128', 'p64p0']  # 21
y64 = ['p192', 'p3', 'p153p217', 'p67p195', 'p128', 'p67p131', 'p256', 'p0', 'p128p192', 'p67', 'p89', 'p89p217',
       'p89p153', 'p195', 'p217', 'p131p195', 'p131', 'p259', 'p64', 'p64p192', 'p153', 'p64p128', 'p281', 'p25']  # 24
y128 = ['p64', 'p122', 'p256', 'p314p250', 'p256p192', 'p319p255', 'p128', 'p314', 'p191', 'p186', 'p127',
        'p319']  # 12
y192 = ['p128', 'p310', 'p239p47', 'p246p54', 'p0', 'p64', 'p303', 'p246', 'p239', 'p303p47', 'p182', 'p256', 'p256p0',
        'p54', 'p118', 'p175', 'p47', 'p192', 'p310p54', 'p192p0', 'p111']  # 21
y256 = ['p256', 'p313', 'p313p121', 'p279', 'p192', 'p279p87', 'p121', 'p87', 'p57p121', 'p0p64', 'p23p87', 'p215',
        'p256p64', 'p249', 'p64']  # 15

# Ascon_anfs = [
# x0*x1 + x0 + x1*x2 + x1*x4 + x1 + x2 + x3,
# x0 + x1*x2 + x1*x3 + x1 + x2*x3 + x2 + x3 + x4,
# x1 + x2 + x3*x4 + x4 + 1,
# x0*x3 + x0*x4 + x0 + x1 + x2 + x3 + x4,
# x0*x1 + x1*x4 + x1 + x3 + x4]

# Ascon 2 rounds circuit:
y0 = 2595
y64 = 2141
y128 = 966
y192 = 1963
y256 = 1897
# Ascon 2 rounds sbox:
y0 = 2593
y64 = 2143
y128 = 966
y192 = 1963
y256 = 1897

# Gaston 1 rounds circuit:
y0 = 479
y64 = 481
y128 = 481
y192 = 471
y256 = 479
# Gaston 1 round sbox:
y0 = 479
y64 = 481
y128 = 481
y192 = 471
y256 = 479

