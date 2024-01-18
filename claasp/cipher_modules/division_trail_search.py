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
        sage: milp.add_constraints()

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
            anfs.append(sbox.component_function(1 << i).algebraic_normal_form())
        return anfs

    def get_monomial_occurences(self, component):
        B = BooleanPolynomialRing(component.input_bit_size, 'x')
        anfs = self.get_anfs_from_sbox(component)

        anfs = [B(anfs[i]) for i in range(component.input_bit_size)]
        monomials = []
        for anf in anfs:
            monomials += anf.monomials()
        print(monomials)

        monomials_degree_based = {}
        sbox = SBox(component.description)
        for deg in range(sbox.max_degree() + 1):
            monomials_degree_based[deg] = dict(
                Counter([monomial for monomial in monomials if monomial.degree() == deg]))
            if deg >= 2:
                for monomial in monomials_degree_based[deg].keys():
                    deg1_monomials = monomial.variables()
                    for deg1_monomial in deg1_monomials:
                        monomials_degree_based[1][deg1_monomial] += monomials_degree_based[deg][monomial]

        return monomials_degree_based

    def create_gurobi_vars_sbox(self, component):
        input_vars = self._model.addVars(list(range(5)), vtype=GRB.BINARY)
        output_vars = self._model.addVars(list(range(5)), vtype=GRB.BINARY)

        monomial_occurences = self.get_monomial_occurences(component)
        print(monomial_occurences)
        B = BooleanPolynomialRing(component.input_bit_size, 'x')
        x = B.variable_names()

        copy_xi = {}
        for xi in x:
            nb_occurence_xi = monomial_occurences[1][B(xi)]
            if nb_occurence_xi != 0:
                copy_xi[B(xi)] = self._model.addVars(list(range(nb_occurence_xi)), vtype=GRB.BINARY)
                for i in range(nb_occurence_xi):
                    self._model.addConstr(input_vars[0] >= copy_xi[B(xi)][i])
                self._model.addConstr(sum(copy_xi[B(xi)][i] for i in range(nb_occurence_xi)) >= input_vars[0])

        copy_monomials_deg = {}
        for deg in list(monomial_occurences.keys()):
            if deg >= 2:
                nb_monomials = sum(monomial_occurences[2].values())
                copy_monomials_deg[deg] = self._model.addVars(list(range(nb_monomials)), vtype=GRB.BINARY)

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
        input_vars = self._model.addVars(list(range(5)), vtype=GRB.BINARY)
        output_vars = self._model.addVars(list(range(5)), vtype=GRB.BINARY)

        B = BooleanPolynomialRing(component.input_bit_size, 'x')
        x = B.variable_names()
        anfs = self.get_anfs_from_sbox(component)
        anfs = [B(anfs[i]) for i in range(component.input_bit_size)]
        print(anfs)

        copy_monomials_deg = self.create_gurobi_vars_sbox(component)
        print(copy_monomials_deg)

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
                        self._model.addConstr(
                            copy_monomials_deg[deg][current] == copy_monomials_deg[1][deg1_monomial][current_deg1])
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

    def create_cipher_input_output_vars(self):
        inputs = {}
        for index, input in enumerate(self._cipher.inputs):
            inputs[input] = self._model.addVars(list(range(self._cipher.inputs_bit_size[index])), vtype=GRB.BINARY)
        ciphertext = self._model.addVars(list(range(self._cipher.output_bit_size)), vtype=GRB.BINARY)
        return inputs, ciphertext

    # def create_component_input_output_vars(self):

    # def add_xor_constraints(self, component):
    #     print("doisjd")

    def add_constraints(self):
        self.build_gurobi_model()
        inputs, output = self.create_cipher_input_output_vars()
        word_operations_types = ['AND', 'MODADD', 'MODSUB', 'NOT', 'OR', 'ROTATE', 'SHIFT', 'XOR']

        for component in self._cipher.get_all_components():
            if component.type == SBOX:
                self.add_sbox_constraints(component)
            elif component.type in word_operations_types:
                if component.description[0] = "ROTATE":
                    self.add_xor_constraints(component)
            else:
                print("not sbox")

        return self._model

# ascon_sbox = [4, 11, 31, 20, 26, 21, 9, 2, 27, 5, 8, 18, 29, 3, 6, 28, 30, 19, 7, 14, 0, 13, 17, 24, 16, 12, 1, 25, 22, 10, 15, 23]