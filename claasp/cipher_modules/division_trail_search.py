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

        sage: from claasp.ciphers.permutations.ascon_sbox_sigma_permutation import AsconSboxSigmaPermutation
        sage: cipher = AsconSboxSigmaPermutation(number_of_rounds=2)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.add_constraints()

        sage: from claasp.ciphers.toys.toyspn1 import ToySPN1
        sage: cipher = ToySPN1(number_of_rounds=1)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(cipher)
        sage: milp.build_gurobi_model()
        sage: milp.find_anf_for_specific_output_bit(1)

    """

    def __init__(self, cipher):
        self._cipher = cipher
        self._variables_list = []
        self._model_constraints = []
        self._model = None

    def build_gurobi_model(self):
        model = Model()
        model.Params.LogToConsole = 0
        model.setParam("PoolSolutions", 200000000)
        model.setParam(GRB.Param.PoolSearchMode, 2)
        self._model = model

    def get_anfs_from_sbox(self, component):
        anfs = []
        sbox = SBox(component.description)
        for i in range(component.input_bit_size):
            anfs.append(sbox.component_function(1<<i).algebraic_normal_form())
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
                copy_xi[B(xi)] = self._model.addVars(list(range(nb_occurence_xi)), vtype=GRB.BINARY, name="copy_"+xi)
                self._model.update()
                for i in range(nb_occurence_xi):
                    self._model.addConstr(input_vars_concat[index] >= copy_xi[B(xi)][i])
                self._model.addConstr(sum(copy_xi[B(xi)][i] for i in range(nb_occurence_xi)) >= input_vars_concat[index])

        copy_monomials_deg = {}
        for deg in list(monomial_occurences.keys()):
            if deg >= 2: # here you are looking at only deg 2, what if deg 3 or more?
                nb_monomials = sum(monomial_occurences[2].values())
                copy_monomials_deg[deg] = self._model.addVars(list(range(nb_monomials)), vtype=GRB.BINARY, name="copy_deg2")
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
        input_vars = {}
        for index, input_name in enumerate(component.input_id_links):
            input_vars[input_name] = []
            for i in component.input_bit_positions[index]:
                input_vars[input_name].append(self._model.getVarByName(input_name + f"[{i}]"))
        output_vars = self._model.addVars(list(range(component.output_bit_size)), vtype=GRB.BINARY, name=component.id)

        input_vars_concat = []
        for key in input_vars.keys():
            input_vars_concat += input_vars[key]
        self._model.update()

        B = BooleanPolynomialRing(component.input_bit_size,'x')
        x = B.variable_names()
        anfs = self.get_anfs_from_sbox(component)
        anfs = [B(anfs[i]) for i in range(component.input_bit_size)]
        anfs.reverse()

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

    def set_cipher_input_output_vars(self):
        for index, input_name in enumerate(self._cipher.inputs):
            self._model.addVars(list(range(self._cipher.inputs_bit_size[index])), vtype=GRB.BINARY, name=input_name)
        # self._model.addVars(list(range(self._cipher.output_bit_size)), vtype=GRB.BINARY, name="ciphertext")
        self._model.update()


    def add_xor_constraints(self, component):
        input_vars = {}
        for index, input_name in enumerate(component.input_id_links):
            input_vars[input_name] = []
            for i in component.input_bit_positions[index]:
                input_vars[input_name].append(self._model.getVarByName(input_name + f"[{i}]"))
        output_vars = self._model.addVars(list(range(component.output_bit_size)), vtype=GRB.BINARY, name=component.id)
        self._model.update()

        input_vars_concat = []
        for key in input_vars.keys():
            input_vars_concat += input_vars[key]

        block_size = int(len(input_vars_concat)//2)
        for i in range(block_size):
            self._model.addConstr(output_vars[i] == input_vars_concat[i] + input_vars_concat[i + block_size])
        self._model.update()

    def add_rotate_constraints(self, component):
        input_vars = {}
        for index, input_name in enumerate(component.input_id_links):
            input_vars[input_name] = []
            for i in component.input_bit_positions[index]:
                input_vars[input_name].append(self._model.getVarByName(input_name + f"[{i}]"))
        output_vars = self._model.addVars(list(range(component.output_bit_size)), vtype=GRB.BINARY, name=component.id)

        input_vars_concat = []
        for key in input_vars.keys():
            input_vars_concat += input_vars[key]

        rotate_offset = component.description[1]
        for i in range(component.output_bit_size):
            self._model.addConstr(output_vars[i] == input_vars_concat[i-rotate_offset % component.output_bit_size])
        self._model.update()

    def add_cipher_output_constraints(self, component):
        input_vars = {}
        for index, input_name in enumerate(component.input_id_links):
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
        l = []
        for monomial in monomials:
            tmp = ""
            if len(monomial) != 1:
                for var in monomial[:-1]:
                    if var < 6:
                        tmp += "p" + str(var)
                    else:
                        tmp += "k" + str(var%6)
            else:
                tmp += str(1)
            # uncomment if you also want the nb of occurences
            # l.append((tmp, monomial[-1]))
            l.append(tmp)
        print(l)

    def add_constraints(self):
        self.build_gurobi_model()
        self.set_cipher_input_output_vars()
        word_operations_types = ['AND', 'MODADD', 'MODSUB', 'NOT', 'OR', 'ROTATE', 'SHIFT', 'XOR']

        for component in self._cipher.get_all_components():
            if component.type == SBOX:
                self.add_sbox_constraints(component)
            elif component.type == "cipher_output":
                self.add_cipher_output_constraints(component)
            elif component.type == "intermediate_output":
                continue
            elif component.type == "word_operation":
                if component.description[0] == "XOR":
                    self.add_xor_constraints(component)
                if component.description[0] == "ROTATE":
                    self.add_rotate_constraints(component)
            else:
                print("not yet implemented")

        return self._model


    def find_anf_for_specific_output_bit(self, output_bit_index):
        self.add_constraints()
        output_id = self.get_cipher_output_component_id()
        output_vars = []
        for i in range(self._cipher.output_bit_size):
            output_vars.append(self._model.getVarByName(f"{output_id}[{i}]"))
        ks = self._model.addVar()
        self._model.addConstr(ks == sum(output_vars[i] for i in range(self._cipher.output_bit_size)))
        self._model.addConstr(ks == 1)
        self._model.addConstr(output_vars[output_bit_index] == 1)
        self._model.update()
        # self._model.write("division_trail_model_toy_cipher.lp")
        self._model.optimize()

        solCount = self._model.SolCount
        print('Number of solutions found: ' + str(solCount))
        monomials = []
        for sol in range(solCount):
            self._model.setParam(GRB.Param.SolutionNumber, sol)
            values = self._model.Xn
            # print(values[:6])
            # print(values[6:12])
            # print(len(values))
            tmp = []
            for index, v in enumerate(values[:12]):
                if v == 1:
                    tmp.append(index)
            monomials.append(tmp)

        monomials_with_occurences = [x+[monomials.count(x)] for x in monomials]
        monomials_duplicates_removed = list(set(tuple(i) for i in monomials_with_occurences))
        monomials_even_occurences_removed = [x for x in monomials_duplicates_removed if x[-1] % 2 == 1]
        self.pretty_print(monomials_even_occurences_removed)
