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
        sage: milp.find_anf_for_specific_output_bit(1)

    """

    def __init__(self, cipher):
        self._cipher = cipher
        self._variables = None
        self._model = None

    def build_gurobi_model(self):
        model = Model()
        model.Params.LogToConsole = 0
        model.setParam("PoolSolutions", 200000000) # 200000000
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
        # input_vars = {}
        # for index, input_name in enumerate(component.input_id_links):
        #     input_vars[input_name] = []
        #     for i in component.input_bit_positions[index]:
        #         input_vars[input_name].append(self._model.getVarByName(input_name + f"[{i}]"))
        # output_vars = self._model.addVars(list(range(component.output_bit_size)), vtype=GRB.BINARY, name=component.id)
        output_vars = []
        for i in range(component.output_bit_size):
            output_vars.append(self._model.getVarByName(f"{component.id}[{i}]"))

        # input_vars_concat = []
        # for key in input_vars.keys():
        #     input_vars_concat += input_vars[key]
        # self._model.update()

        input_vars_concat = []
        for index, input_name in enumerate(component.input_id_links):
            current = self._variables[input_name]["current"]
            for pos in component.input_bit_positions[index]:
                input_vars_concat.append(self._variables[input_name][current][pos])
            # self._variables[input_name]["current"] += 1

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

        l = self.how_many_times_key_appear()
        copy_key = []
        for index, component in enumerate(l):
            copy_key.append(self._model.addVars(list(range(6)), vtype=GRB.BINARY, name="copy_key_" + component.id))

        self._model.update()

    def add_xor_constraints(self, component):
        # input_vars = {}
        # for index, input_name in enumerate(component.input_id_links):
        #     input_vars[input_name] = []
        #     for i in component.input_bit_positions[index]:
        #         input_vars[input_name].append(self._model.getVarByName(input_name + f"[{i}]"))
        # output_vars = self._model.addVars(list(range(component.output_bit_size)), vtype=GRB.BINARY, name=component.id)
        output_vars = []
        for i in range(component.output_bit_size):
            output_vars.append(self._model.getVarByName(f"{component.id}[{i}]"))
        # self._model.update()

        # input_vars_concat = []
        # for key in input_vars.keys():
        #     input_vars_concat += input_vars[key]

        input_vars_concat = []
        for index, input_name in enumerate(component.input_id_links):
            current = self._variables[input_name]["current"]
            for pos in component.input_bit_positions[index]:
                input_vars_concat.append(self._variables[input_name][current][pos])
            self._variables[input_name]["current"] += 1

        block_size = int(len(input_vars_concat)//component.description[1])
        for i in range(block_size):
            self._model.addConstr(output_vars[i] == input_vars_concat[i] + input_vars_concat[i + block_size]) # works only if 2 blocks
        self._model.update()

    def add_rotate_constraints(self, component):
        # input_vars = {}
        # for index, input_name in enumerate(component.input_id_links):
        #     input_vars[input_name] = []
        #     for i in component.input_bit_positions[index]:
        #         input_vars[input_name].append(self._model.getVarByName(input_name + f"[{i}]"))
        # output_vars = self._model.addVars(list(range(component.output_bit_size)), vtype=GRB.BINARY, name=component.id)
        output_vars = []
        for i in range(component.output_bit_size):
            output_vars.append(self._model.getVarByName(f"{component.id}[{i}]"))

        # input_vars_concat = []
        # for key in input_vars.keys():
        #     input_vars_concat += input_vars[key]

        input_vars_concat = []
        for index, input_name in enumerate(component.input_id_links):
            current = self._variables[input_name]["current"]
            for pos in component.input_bit_positions[index]:
                input_vars_concat.append(self._variables[input_name][current][pos])
            self._variables[input_name]["current"] += 1

        rotate_offset = component.description[1]
        for i in range(component.output_bit_size):
            self._model.addConstr(output_vars[i] == input_vars_concat[i-rotate_offset % component.output_bit_size])
        self._model.update()

    def add_and_constraints(self, component):
        # input_vars = {}
        # for index, input_name in enumerate(component.input_id_links):
        #     input_vars[input_name] = []
        #     for i in component.input_bit_positions[index]:
        #         input_vars[input_name].append(self._model.getVarByName(input_name + f"[{i}]"))
        output_vars = self._model.addVars(list(range(component.output_bit_size)), vtype=GRB.BINARY, name=component.id)

        # input_vars_concat = []
        # for key in input_vars.keys():
        #     input_vars_concat += input_vars[key]

        input_vars_concat = []
        for index, input_name in enumerate(component.input_id_links):
            current = self._variables[input_name]["current"]
            for pos in component.input_bit_positions[index]:
                input_vars_concat.append(self._variables[input_name][current][pos])
            self._variables[input_name]["current"] += 1

        block_size = int(len(input_vars_concat)//component.description[1])
        for i in range(component.output_bit_size):
            self._model.addConstr(output_vars[i] >= input_vars_concat[i])
            self._model.addConstr(output_vars[i] >= input_vars_concat[i + block_size])
            self._model.addConstr(output_vars[i] <= input_vars_concat[i] + input_vars_concat[i + block_size])
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
                for var in monomial[:-1]: #[:1] to remove the occurences
                    if var < self._cipher.inputs_bit_size[0]:
                        tmp += self._cipher.inputs[0][0] + str(var)
                    else:
                        tmp += self._cipher.inputs[1][0] + str(var%self._cipher.inputs_bit_size[0])
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

        for component in self._cipher.get_all_components():
            # print(component.id)
            if component.type == SBOX:
                self.add_sbox_constraints(component)
            elif component.type == "cipher_output":
                self.add_cipher_output_constraints(component)
            elif component.type == "intermediate_output":
                continue
            elif component.type == "word_operation":
                if component.description[0] == "XOR":
                    self.add_xor_constraints(component)
                elif component.description[0] == "ROTATE":
                    self.add_rotate_constraints(component)
                elif component.description[0] == "AND":
                    self.add_and_constraints(component)
            else:
                print("not yet implemented")

        return self._model

    def get_where_component_is_used(self):
        occurences = {}
        ids = self._cipher.inputs + self._cipher.get_all_components_ids()
        for name in ids:
            for component in self._cipher.get_all_components():
                if (name in component.input_id_links) and (component.type != "intermediate_output"):
                    index = component.input_id_links.index(name)
                    if name not in occurences.keys():
                        occurences[name] = []
                    occurences[name] += component.input_bit_positions[index]

        occurences_final = {}
        for name in occurences.keys():
            counter = Counter(occurences[name])
            maximum_occ = max(counter.values())
            occurences_final[name] = maximum_occ

        return occurences_final

    def create_gurobi_vars_from_all_components(self):
        occurences = self.get_where_component_is_used()
        all_vars = {}
        for component_id in occurences.keys():
            nb_occurence = occurences[component_id]
            all_vars[component_id] = {}
            all_vars[component_id]["current"] = 0
            if component_id not in self._cipher.inputs:
                component = self._cipher.get_component_from_id(component_id)
                all_vars[component_id][0] = self._model.addVars(list(range(component.output_bit_size)), vtype=GRB.BINARY, name=component.id)
                if nb_occurence >= 2:
                    all_vars[component_id]["current"] = 1
                    for i in range(nb_occurence):
                        all_vars[component_id][i+1] = self._model.addVars(list(range(component.output_bit_size)), vtype=GRB.BINARY, name="copy_"+component_id+f"_{i}")
                    for i in range(component.output_bit_size):
                        for j in range(nb_occurence):
                            self._model.addConstr(all_vars[component_id][0][i] >= all_vars[component_id][j+1][i])
                        self._model.addConstr(sum(all_vars[component_id][j+1][i] for j in range(nb_occurence)) >= all_vars[component_id][0][i])
            else:
                index = self._cipher.inputs.index(component_id)
                input_size = self._cipher.inputs_bit_size[index]
                all_vars[component_id][0] = self._model.addVars(list(range(input_size)), vtype=GRB.BINARY, name=component_id)
                if nb_occurence >= 2:
                    all_vars[component_id]["current"] = 1
                    for i in range(nb_occurence):
                        all_vars[component_id][i+1] = self._model.addVars(list(range(input_size)), vtype=GRB.BINARY, name="copy_"+component_id+f"_{i}")
                    for i in range(input_size):
                        for j in range(nb_occurence):
                            self._model.addConstr(all_vars[component_id][0][i] >= all_vars[component_id][j+1][i])
                        self._model.addConstr(sum(all_vars[component_id][j+1][i] for j in range(nb_occurence)) >= all_vars[component_id][0][i])
        self._model.update()
        self._variables = all_vars


    def find_anf_for_specific_output_bit(self, output_bit_index):
        start = time.time()
        self.add_constraints()
        output_id = self.get_cipher_output_component_id()
        output_vars = []
        for i in range(self._cipher.output_bit_size):
            output_vars.append(self._model.getVarByName(f"{output_id}[{i}]")) # {output_id}
        ks = self._model.addVar()
        self._model.addConstr(ks == sum(output_vars[i] for i in range(self._cipher.output_bit_size)))
        self._model.addConstr(ks == 1)
        self._model.addConstr(output_vars[output_bit_index] == 1)

        # key = []
        # for i in range(6):
        #     key.append(self._model.getVarByName(f"key[{i}]"))
        # for i in range(6):
        #     self._model.addConstr(key[i] == 0)

        self._model.update()
        self._model.write("division_trail_model_toy_cipher.lp")
        end = time.time()
        building_time = end - start
        print(f"building_time : {building_time}")

        start = time.time()
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

