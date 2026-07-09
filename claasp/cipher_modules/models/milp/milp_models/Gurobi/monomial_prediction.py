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

import os
import secrets
import sys
import time
from collections import Counter
from copy import deepcopy

from gurobipy import GRB, Env, Model
from sage.all import GF, Polyhedron
from sage.crypto.sbox import SBox
from sage.rings.polynomial.pbori.pbori import BooleanPolynomialRing

from claasp.cipher_modules.component_analysis_tests import binary_matrix_of_linear_component
from claasp.cipher_modules.graph_generator import _get_predecessors_subgraph, create_networkx_graph_from_input_ids
from claasp.cipher_modules.models.milp.utils.generate_sbox_inequalities_for_trail_search import cutting_off_milp
from claasp.name_mappings import INTERMEDIATE_OUTPUT

verbosity = False

MODEL_INFEASIBLE_MSG = "[INFO] Model is infeasible"


class MilpMonomialPredictionModel:
    """

    Given a number of rounds of a chosen cipher and a chosen output bit, this module produces a model that can either:
    - find the ANF of this chosen output bit,
    - find an upper bound of this ANF,
    - find a tight upper bound on the algebraic degree via parity (slower),
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
        self._sbox_valid_cache = {}
        self._sbox_ineq_cache = {}
        self._gurobi_params = {}

    def build_gurobi_model(self):
        if os.getenv("GUROBI_COMPUTE_SERVER") is not None:
            env = Env(empty=True)
            env.setParam("ComputeServer", os.getenv("GUROBI_COMPUTE_SERVER"))
            env.start()
            model = Model(env=env)
        else:
            model = Model()
        model.Params.LogToConsole = 0
        self._model = model
        for param, value in self._gurobi_params.items():
            self._model.setParam(param, value)

    def get_all_variables_as_list(self):
        for component_id in list(self._variables.keys())[:-1]:
            for bit_position in self._variables[component_id].keys():
                self._variables_as_list.append(self._variables[component_id][bit_position]["original"].VarName)
                copies = self._variables[component_id][bit_position]["copies"]
                for copy in copies:
                    self._variables_as_list.append(copy.VarName)

    def get_unused_variables(self):
        self.get_all_variables_as_list()
        # Collect all global input names to protect them from pruning (as they might be constrained later in D&C copies)
        input_bits = set()
        for inp_name in self._cipher.inputs:
            sz = self._cipher.inputs_bit_size[self._cipher.inputs.index(inp_name)]
            for i in range(sz):
                input_bits.add(f"{inp_name}[{i}]")

        for variable in self._variables_as_list:
            if variable not in self._used_variables and variable not in input_bits:
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
                        tmp1 = v.VarName.split("_")[(i + 2) :]
                        tmp2 = "_".join(tmp1)
                        self._used_variables.append(tmp2)
                self._unused_variables = [x for x in self._unused_variables if x != v.VarName]
            except Exception:
                continue

    def create_all_copies(self):
        for name in list(self._variables.keys())[:-1]:
            for bit_position in self._variables[name].keys():
                copies = self._variables[name][bit_position]["copies"]
                original_var = self._variables[name][bit_position]["original"]

                if copies:
                    for i in range(len(copies)):
                        self._model.addConstr(original_var >= copies[i])
                    self._model.addConstr(sum(copies[i] for i in range(len(copies))) >= original_var)
                self._model.update()

    def get_anfs_from_sbox(self, component):
        anfs = []
        B = BooleanPolynomialRing(component.output_bit_size, "x")
        C = BooleanPolynomialRing(component.output_bit_size, "x")
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
        B = BooleanPolynomialRing(component.input_bit_size, "x")
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
                Counter([monomial for monomial in monomials if monomial.degree() == deg])
            )
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
        B = BooleanPolynomialRing(component.input_bit_size, "x")

        copy_xi = {}
        for index, xi in enumerate(monomial_occurences[1].keys()):
            nb_occurence_xi = monomial_occurences[1][B(xi)]
            if nb_occurence_xi != 0:
                copy_xi[B(xi)] = self._model.addVars(
                    list(range(nb_occurence_xi)),
                    vtype=GRB.BINARY,
                    name="copy_" + input_vars_concat[index].VarName + "_as_" + str(xi),
                )
                self._model.update()
                self.set_as_used_variables(list(copy_xi[B(xi)].values()))
                self.set_as_used_variables([input_vars_concat[index]])
                for i in range(nb_occurence_xi):
                    self._model.addConstr(input_vars_concat[index] >= copy_xi[B(xi)][i])
                self._model.addConstr(
                    sum(copy_xi[B(xi)][i] for i in range(nb_occurence_xi)) >= input_vars_concat[index]
                )

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

    def get_valid_monomial_exponents_table(self, component):
        """
        Exact 3SDP-woU monomial-transition table of the S-box, read from its output ANFs.

        Returns ``v_mask -> set(u_mask)``: for each output-monomial exponent v (selecting
        the output bits with v_q=1), the input-monomial exponents u whose monomial x^u
        survives with odd multiplicity over GF(2) in the product ``prod_{q: v_q=1}
        y_q(x)`` of the selected output-bit ANFs.
        """
        desc = tuple(component.description)
        if desc in self._sbox_valid_cache:
            return self._sbox_valid_cache[desc]
        n = component.input_bit_size
        m = component.output_bit_size
        B = BooleanPolynomialRing(n, "x")
        anfs = [B(a) for a in self.get_anfs_from_sbox(component)]
        names = list(B.variable_names())
        table = {}
        for v_mask in range(1 << m):
            prod = B(1)
            for q in range(m):
                if (v_mask >> q) & 1:
                    prod = prod * anfs[q]
            us = set()
            for mon in prod.monomials():
                u = 0
                for var in mon.variables():
                    u |= 1 << names.index(str(var))
                us.add(u)
            table[v_mask] = us
        self._sbox_valid_cache[desc] = (table, n, m)
        return self._sbox_valid_cache[desc]

    def get_sbox_inequalities(self, component):
        """
        Compact, exact MILP encoding of ``get_valid_monomial_exponents_table``.

        A point ``z = (u_0..u_{n-1}, v_0..v_{m-1})`` is VALID if (u, v) is a valid trail and
        INVALID otherwise. Returns inequalities ``(b, a_0, ..., a_{n+m-1})`` meaning
        ``b + sum_k a_k z_k >= 0`` that hold on every valid point and are violated by every
        invalid one: the convex-hull facets of the valid points, minimised via CLAASP's
        ``cutting_off_milp``, plus a no-good cut for any invalid point inside the hull (so it
        is exact for any S-box).
        """
        desc = tuple(component.description)
        if desc in self._sbox_ineq_cache:
            return self._sbox_ineq_cache[desc]
        table, n, m = self.get_valid_monomial_exponents_table(component)
        dim = n + m
        valid = set()
        for v_mask, us in table.items():
            for u in us:
                valid.add(tuple([(u >> j) & 1 for j in range(n)] + [(v_mask >> q) & 1 for q in range(m)]))
        invalid = {tuple((i >> k) & 1 for k in range(dim)) for i in range(1 << dim)} - valid

        poly = Polyhedron(vertices=[list(p) for p in valid])
        reduced = cutting_off_milp({1: poly})[1]
        chosen = [tuple(int(c) for c in ie.vector()) for ie in reduced]  # (b, a_0..)

        def excludes(ie, p):
            return ie[0] + sum(ie[k + 1] * p[k] for k in range(dim)) < 0

        for p in invalid:  # invalid points inside the hull are uncut by facets -> explicit no-good cut
            if not any(excludes(ie, p) for ie in chosen):
                b = sum(p) - 1
                chosen.append(tuple([b] + [(-1 if p[k] == 1 else 1) for k in range(dim)]))

        self._sbox_ineq_cache[desc] = (chosen, n, m)
        return self._sbox_ineq_cache[desc]

    def _map_sbox_output_vars(self, component, output_vars, m):
        needed = sorted(self._occurences[component.id].keys())  # matches output_vars order
        out_all = [None] * m
        for idx, pos in enumerate(needed):
            out_all[pos] = output_vars[idx]
        for q in range(m):
            if out_all[q] is None:  # output bit unused downstream -> pin to 0
                var = self._model.addVar(vtype=GRB.BINARY, name=f"{component.id}_unused_out_{q}")
                self._model.addConstr(var == 0)
                out_all[q] = var
        return out_all

    def add_sbox_constraints(self, component):
        """
        Constrain the S-box's input variables (the exponents u) and output-bit variables
        (the exponents v) to the exact monomial-trail relation.

        Large S-boxes (e.g. 8-bit AES): the (u, v) point set lives in {0,1}^(n+m), and
        building its convex hull becomes infeasible once n+m > 12, so fall back to the
        ANF-circuit model. That fallback is exact for single-output-bit queries
        (|v| = 1).
        """
        if (1 << (component.input_bit_size + component.output_bit_size)) > 4096:
            return self.add_sbox_constraints_anf_circuit(component)

        output_vars = self.get_output_vars(component)
        input_vars = self.get_input_vars(component)
        self._model.update()

        ineqs, n, m = self.get_sbox_inequalities(component)
        out_all = self._map_sbox_output_vars(component, output_vars, m)
        self._model.update()

        for ie in ineqs:
            expr = ie[0]
            for j in range(n):
                if ie[1 + j] != 0:
                    expr = expr + ie[1 + j] * input_vars[j]
            for q in range(m):
                if ie[1 + n + q] != 0:
                    expr = expr + ie[1 + n + q] * out_all[q]
            self._model.addConstr(expr >= 0)

        self.set_as_used_variables(list(input_vars) + list(output_vars))
        self._model.update()

    def add_sbox_constraints_anf_circuit(self, component):
        """
        ANF-circuit S-box model (fallback for large S-boxes). Builds each needed
        output bit as the XOR of its ANF monomials, with products via AND gadgets
        on copied inputs.
        """
        output_vars = self.get_output_vars(component)
        input_vars_concat = self.get_input_vars(component)
        self._model.update()

        B = BooleanPolynomialRing(component.input_bit_size, "x")
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
                            copy_monomials_deg[deg][current] == copy_monomials_deg[1][deg1_monomial][current_deg1]
                        )
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
            new_vars = self._model.addVars(list(range(number_of_1s)), vtype=GRB.BINARY, name="copy_" + var.VarName)
            self._model.update()
            for i in range(number_of_1s):
                self._model.addConstr(var >= new_vars[i])
            self._model.addConstr(sum(new_vars[i] for i in range(number_of_1s)) >= var)
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
                output_vars[index] == input_vars_concat[(bit_pos - rotate_offset) % component.output_bit_size]
            )
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
                    const_comp = self._cipher.component_from_id(input_name)
                    value = (int(const_comp.description[0], 16) >> (const_comp.output_bit_size - 1 - pos)) & 1
                    const_bits_per_bit[output_index].append(value)
                else:
                    copy_index = len(self._variables[input_name][pos]["copies"])
                    copy_var = self._model.addVar(vtype=GRB.BINARY, name=f"copy_{copy_index}_{input_name}[{pos}]")
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

        # Components that iterate over bit indices (or where its required to track all output bits, even unused ones) must use the padded logic.
        safe_components = ["MODADD", "MODMUL", "XOR", "AND"]
        desc_str = str(component.description[0])
        needs_padding = any(c in desc_str for c in safe_components)

        if not needs_padding:
            output_vars = self._get_unpadded_output_vars(component)
        else:
            output_vars = self._get_padded_output_vars(component)

        self._model.update()
        return output_vars

    def _get_unpadded_output_vars(self, component):
        output_vars = []
        tmp = sorted(self._occurences[component.id].keys())

        # Use _variables dict if available (created by create_gurobi_vars_from_all_components)
        if component.id in self._variables:
            vars_dict = self._variables[component.id]
            for i in tmp:
                if i in vars_dict:
                    output_vars.append(vars_dict[i]["original"])
                else:
                    # Fallback to name search if for some reason not in dict (should not happen)
                    output_vars.append(self._model.getVarByName(f"{component.id}[{i}]"))
        else:
            # Fallback for legacy calls or unitialized dict
            for i in tmp:
                output_vars.append(self._model.getVarByName(f"{component.id}[{i}]"))
        return output_vars

    def _get_padded_output_vars(self, component):
        output_vars = []
        # Unused bits must be created and strictly constrained to 0 to prevent weight leaks.
        output_size = component.output_bit_size
        for i in range(output_size):
            var = self._model.getVarByName(f"{component.id}[{i}]")
            if var is None:
                var = self._model.addVar(vtype=GRB.BINARY, name=f"{component.id}[{i}]_unused")
                self._model.addConstr(var == 0)
            output_vars.append(var)
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
        b_bits = input_vars_concat[n : 2 * n]
        z_bits = output_vars

        # Rerverse endianess
        a_bits = list(reversed(a_bits))
        b_bits = list(reversed(b_bits))
        z_bits = list(reversed(z_bits))

        # Create carry-out variables for bits 0..n-1
        carry_vars = [None] * n
        for i in range(n - 1):
            carry_vars[i] = self._model.addVar(vtype=GRB.BINARY, name=f"modadd_carry_{component.id}_{i}")
        # top carry fixed to 0
        carry_vars[n - 1] = self._model.addVar(
            vtype=GRB.BINARY, lb=0, ub=0, name=f"modadd_carry_{component.id}_{n - 1}_zero"
        )
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

            s_i = self._model.addVar(vtype=GRB.INTEGER, lb=0, ub=3, name=f"modadd_sum_{component.id}_{i}")
            if c_in is not None:
                self._model.addConstr(s_i == ai + bi + c_in)
            else:
                self._model.addConstr(s_i == ai + bi)

            t_i = carry_vars[i]
            self._model.addConstr(zi + 2 * t_i == s_i)

            self.set_as_used_variables([ai, bi, zi, t_i, s_i])

        self._model.update()

    def add_modmul_constraints(self, component):
        """
        Modular multiplication constraints based on 3SDP-woU model.
        """
        output_vars = self.get_output_vars(component)
        input_vars_concat = self.get_input_vars(component)
        self._model.update()

        total = len(input_vars_concat)
        if total % 2 != 0:
            raise ValueError("add_modmul_constraints: input length not even")
        n = total // 2
        x_bits = list(reversed(input_vars_concat[:n]))  # index 0 is LSB
        y_bits = list(reversed(input_vars_concat[n : 2 * n]))
        z_bits_out = list(reversed(output_vars))

        tag = f"modmul_{component.id}"

        # p_matrix[i][j]: truncation i + j < n
        p_matrix = []
        for i in range(n):
            row = []
            for j in range(n):
                p_var = self._model.addVar(vtype=GRB.BINARY, name=f"{tag}_p_{i}_{j}") if i + j < n else None
                row.append(p_var)
            p_matrix.append(row)
        self._model.update()

        # Enforce 3SDP-woU COPY structure for partial products:
        for i in range(n):
            relevant_ps = [p_matrix[i][j] for j in range(n) if p_matrix[i][j] is not None]
            if relevant_ps:
                for p_var in relevant_ps:
                    self._model.addConstr(x_bits[i] >= p_var)
                self._model.addConstr(sum(relevant_ps) >= x_bits[i])
            self.set_as_used_variables([x_bits[i]])

        for j in range(n):
            relevant_ps = [p_matrix[i][j] for i in range(n) if p_matrix[i][j] is not None]
            if relevant_ps:
                for p_var in relevant_ps:
                    self._model.addConstr(y_bits[j] >= p_var)
                self._model.addConstr(sum(relevant_ps) >= y_bits[j])
            self.set_as_used_variables([y_bits[j]])

        for i in range(n):
            for j in range(n):
                if p_matrix[i][j] is not None:
                    self.set_as_used_variables([p_matrix[i][j]])

        # z accumulator init to zero
        z_acc = [self._model.addVar(vtype=GRB.BINARY, lb=0, ub=0, name=f"{tag}_zinit_{i}") for i in range(n)]
        self._model.update()

        # Cascade additions: z = z + (X * y[j] << j)
        for j in range(n):
            # shifted row = [0...0, p_0j, p_1j, ..., p_{n-1-j,j}]
            shifted = []
            for k in range(n):
                if k < j:
                    shifted.append(self._model.addVar(vtype=GRB.BINARY, lb=0, ub=0, name=f"{tag}_sh0_{k}_{j}"))
                else:
                    shifted.append(p_matrix[k - j][j])

            next_z = (
                z_bits_out
                if j == n - 1
                else [self._model.addVar(vtype=GRB.BINARY, name=f"{tag}_zacc_{j + 1}_{i}") for i in range(n)]
            )
            self._model.update()

            # Carry-ripple adder: next_z = z_acc + shifted
            carry_vars = [self._model.addVar(vtype=GRB.BINARY, name=f"{tag}_c_{j}_{i}") for i in range(n - 1)]
            carry_vars.append(self._model.addVar(vtype=GRB.BINARY, lb=0, ub=0, name=f"{tag}_czero_{j}"))
            self._model.update()

            for i in range(n):
                c_in = carry_vars[i - 1] if i > 0 else 0
                s_i = self._model.addVar(vtype=GRB.INTEGER, lb=0, ub=3, name=f"{tag}_s_{j}_{i}")
                self._model.addConstr(s_i == z_acc[i] + shifted[i] + c_in)
                self._model.addConstr(next_z[i] + 2 * carry_vars[i] == s_i)
                self.set_as_used_variables([z_acc[i], shifted[i], next_z[i], carry_vars[i], s_i])
            z_acc = next_z

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

    def add_fsr_constraints(self, component):
        output_bit_size = component.output_bit_size

        output_vars = {}
        tmp = list(self._occurences[component.id].keys())
        tmp.sort()
        for i in tmp:
            output_vars[i] = self._model.getVarByName(f"{component.id}[{i}]")

        input_vars_concat = self.get_input_vars(component)
        self._model.update()

        interm_input_vars = self._model.addVars(list(range(output_bit_size)), vtype=GRB.BINARY, name="interm_input")
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

        interm_output_vars = self._model.addVars(
            list(range(output_bit_size)), vtype=GRB.BINARY, name=f"interm_{component.id}_output"
        )
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
            y = Or(x1, x2, ..., xn)
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
                copy_var = self._model.addVar(vtype=GRB.BINARY, name=f"copy_{copy_index}_{input_name}[{pos}]")
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
            self.set_as_used_variables([input_vars_concat[bit_pos], output_vars[index]])
        self._model.update()

    def get_cipher_output_component_id(self):
        for component in self._cipher.get_all_components():
            if component.type == "cipher_output":
                return component.id

    def add_constraints(self, predecessors, input_id_link_needed, block_needed, skip_components=None):
        self.build_gurobi_model()
        self.create_gurobi_vars_from_all_components(
            predecessors, input_id_link_needed, block_needed, skip_components=skip_components
        )

        used_predecessors_sorted = self.order_predecessors(list(self._occurences.keys()))
        self._used_predecessors_sorted = used_predecessors_sorted
        for component_id in used_predecessors_sorted:
            if component_id in self._cipher.inputs:
                continue
            # Skip components in the exclusion set (e.g., dead-end round_output tap at middle_round)
            if skip_components and component_id in skip_components:
                continue
            component = self._cipher.component_from_id(component_id)
            print(f"---> {component.id}") if verbosity else None
            self._dispatch_constraints(component)

        return self._model

    def _dispatch_constraints(self, component):
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
            self._add_word_operation_constraints(component)
        else:
            raise NotImplementedError(f"Component {component.type} is not yet implemented")

    def _add_word_operation_constraints(self, component):
        op = component.description[0]
        if op == "XOR":
            self.add_xor_constraints(component)
        elif op == "ROTATE":
            self.add_rotate_constraints(component)
        elif op == "SHIFT":
            self.add_shift_constraints(component)
        elif op == "AND":
            self.add_and_constraints(component)
        elif op == "NOT":
            self.add_not_constraints(component)
        elif op == "OR":
            self.add_or_constraints(component)
        elif op == "MODADD":
            self.add_modadd_constraints(component)
        elif "MODMUL" in op:
            self.add_modmul_constraints(component)
        else:
            raise NotImplementedError(f"Word operation {op} is not yet implemented")

    def get_where_component_is_used(self, predecessors, input_id_link_needed, block_needed, skip_components=None):
        occurences = {}
        ids = self._cipher.inputs + predecessors
        for name in ids:
            self._fill_occurences_for_name(name, predecessors, skip_components, occurences)

        self._fill_occurences_for_link_needed(input_id_link_needed, block_needed, occurences)
        self._fill_occurences_for_cipher_output(input_id_link_needed, occurences)

        occurences_final = {comp_id: self.find_copy_indexes(pos_list) for comp_id, pos_list in occurences.items()}

        self._occurences = occurences_final
        return occurences_final

    def _fill_occurences_for_name(self, name, predecessors, skip_components, occurences):
        for component_id in predecessors:
            if component_id in self._cipher.inputs:
                continue
            # Skip components in the exclusion set (e.g., dead-end round_output tap at middle_round)
            if skip_components and component_id in skip_components:
                continue
            component = self._cipher.component_from_id(component_id)
            if name in component.input_id_links:
                indexes = [i for i, j in enumerate(component.input_id_links) if j == name]
                if name not in occurences:
                    occurences[name] = []
                for index in indexes:
                    occurences[name].append(component.input_bit_positions[index])

    def _fill_occurences_for_link_needed(self, input_id_link_needed, block_needed, occurences):
        if input_id_link_needed in self._cipher.inputs:
            occurences[input_id_link_needed] = [block_needed]
        else:
            component = self._cipher.component_from_id(input_id_link_needed)
            occurences[input_id_link_needed] = [[i for i in range(component.output_bit_size)]]

    def _fill_occurences_for_cipher_output(self, input_id_link_needed, occurences):
        cipher_id = self.get_cipher_output_component_id()
        if input_id_link_needed == cipher_id:
            component = self._cipher.component_from_id(cipher_id)
            occurences[cipher_id] = [[i for i in range(component.output_bit_size)]]

    def find_copy_indexes(self, input_bit_positions):
        copy_indexes = {}
        for input_bit_position in input_bit_positions:
            for position in input_bit_position:
                if position not in copy_indexes:
                    copy_indexes[position] = 0
                copy_indexes[position] += 1
        return copy_indexes

    def order_predecessors(self, used_predecessors):
        for component_id in self._cipher.inputs:
            if component_id in self._occurences:
                used_predecessors.remove(component_id)
        tmp = {}
        final = {}
        for r in range(self._cipher.number_of_rounds):
            tmp[r] = {}
            for component_id in used_predecessors:
                if int(component_id.split("_")[-2]) == r:
                    tmp[r][component_id] = int(component_id.split("_")[-1])
            final[r] = dict(sorted(tmp[r].items(), key=lambda item: item[1]))

        used_predecessors_sorted = []
        for r in range(self._cipher.number_of_rounds):
            used_predecessors_sorted += list(final[r].keys())

        component_ids_in_occurences = [
            component_id for component_id in self._cipher.inputs if component_id in self._occurences
        ]
        used_predecessors_sorted = component_ids_in_occurences + used_predecessors_sorted
        return used_predecessors_sorted

    def create_gurobi_vars_from_all_components(
        self, predecessors, input_id_link_needed, block_needed, skip_components=None
    ):
        occurences = self.get_where_component_is_used(
            predecessors, input_id_link_needed, block_needed, skip_components=skip_components
        )

        all_vars = {}
        used_predecessors_sorted = self.order_predecessors(list(occurences.keys()))
        cipher_id = self.get_cipher_output_component_id()
        for component_id in used_predecessors_sorted:
            all_vars[component_id] = {}
            if component_id != cipher_id:
                for pos in occurences[component_id]:
                    all_vars[component_id][pos] = {}
                    all_vars[component_id][pos]["original"] = self._model.addVar(
                        vtype=GRB.BINARY, name=component_id + f"[{pos}]"
                    )
                    all_vars[component_id][pos]["copies"] = []
            else:
                component = self._cipher.component_from_id(cipher_id)
                for pos in range(component.output_bit_size):
                    all_vars[component_id][pos] = {}
                    all_vars[component_id][pos]["original"] = self._model.addVar(
                        vtype=GRB.BINARY, name=component_id + f"[{pos}]"
                    )
                    all_vars[component_id][pos]["copies"] = []

        self._model.update()
        self._variables = all_vars

    def find_index_second_input(self):
        occurences = self._occurences
        return len(occurences[self._cipher.inputs[0]])

    def build_generic_model_for_specific_output_bit(
        self,
        output_bit_index,
        fixed_degree=None,
        which_var_degree=None,
        chosen_cipher_output=None,
        skip_components=None,
        do_pruning=True,
    ):
        start = time.time()
        if skip_components is None:
            # This prevents diversion to dead-end taps while preserving cipher paths (e.g. Trivium keystream bits).
            skip_components = self._get_default_skip_components(chosen_cipher_output)

        input_id_link_needed = (
            chosen_cipher_output if chosen_cipher_output is not None else self.get_cipher_output_component_id()
        )
        component = self._cipher.component_from_id(input_id_link_needed)
        block_needed = list(range(component.output_bit_size))
        output_bit_index_previous_comp = output_bit_index

        predecessors = self._get_predecessors_for_link(input_id_link_needed)

        self.add_constraints(predecessors, input_id_link_needed, block_needed, skip_components=skip_components)

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
            self._apply_fixed_degree_constraint(fixed_degree, which_var_degree)

        if do_pruning:
            self.set_unused_variables_to_zero()
        self.create_all_copies()
        self._model.update()
        if verbosity:
            end = time.time()
            building_time = end - start
            print(f"########## building_time : {building_time}")
        self._model.update()

    def _apply_fixed_degree_constraint(self, fixed_degree, which_var_degree):
        """Constrain the Hamming weight of the chosen input group to ``fixed_degree``.

        Extracted from ``build_generic_model_for_specific_output_bit`` so that
        method stays below the cognitive-complexity threshold; logic is unchanged.
        """
        if which_var_degree is not None:
            var_input_name = next((inp for inp in self._cipher.inputs if inp.startswith(which_var_degree)), None)
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

        self._model.addConstr(sum(vars_to_constrain) == fixed_degree, name=f"degree_{var_input_name}_{fixed_degree}")

    def build_model_with_input_output_constraints(
        self, output_indices, chosen_cipher_output=None, skip_components=None, do_pruning=True
    ):
        r"""
        Build an enumeration ready Gurobi MILP model with specific output constraints.

        This method extends the base model generation by allowing multiple output bits
        to be explicitly constrained to 1, or by leaving all output bits unconstrained
        (free variables) if ``output_indices`` is set to ``None``.
        """
        if skip_components is None:
            skip_components = self._get_default_skip_components(chosen_cipher_output)

        input_id_link_needed = (
            chosen_cipher_output if chosen_cipher_output is not None else self.get_cipher_output_component_id()
        )

        component = self._cipher.component_from_id(input_id_link_needed)
        block_needed = list(range(component.output_bit_size))

        predecessors = self._get_predecessors_for_link(input_id_link_needed)

        self.add_constraints(predecessors, input_id_link_needed, block_needed, skip_components=skip_components)

        var_from_block_needed = self._get_vars_from_block_needed(input_id_link_needed, block_needed)

        # Map to dictionary, then create a distinct list variable to avoid shadowing
        output_vars_dict = self._model.addVars(list(range(len(block_needed))), vtype=GRB.BINARY, name="output")
        self._variables["output"] = output_vars_dict
        output_vars = list(output_vars_dict.values())
        self._model.update()

        for i in range(len(block_needed)):
            self._model.addConstr(output_vars[i] == var_from_block_needed[i])
            self.set_as_used_variables([output_vars[i], var_from_block_needed[i]])

        self._apply_output_indices_constraints(output_indices, output_vars, block_needed)

        if do_pruning:
            self.set_unused_variables_to_zero()
        self.create_all_copies()
        self._model.update()

    def _get_default_skip_components(self, chosen_cipher_output):
        G = create_networkx_graph_from_input_ids(self._cipher)
        skip_components = {
            n for n, d in G.out_degree() if d == 0 and self._cipher.component_from_id(n).type == INTERMEDIATE_OUTPUT
        }
        skip_components.discard(chosen_cipher_output)
        return skip_components

    def _get_predecessors_for_link(self, input_id_link_needed):
        G = create_networkx_graph_from_input_ids(self._cipher)
        predecessors = list(_get_predecessors_subgraph(G, [input_id_link_needed]))
        for input_id in self._cipher.inputs + [""]:
            if input_id in predecessors:
                predecessors.remove(input_id)
        return predecessors

    def _get_vars_from_block_needed(self, input_id_link_needed, block_needed):
        var_from_block_needed = []
        if input_id_link_needed in self._variables:
            for i in block_needed:
                var_from_block_needed.append(self._variables[input_id_link_needed][i]["original"])
        else:
            # Fallback if component not populated in variables
            for i in block_needed:
                var_from_block_needed.append(self._model.getVarByName(f"{input_id_link_needed}[{i}]"))
        return var_from_block_needed

    def _apply_output_indices_constraints(self, output_indices, output_vars, block_needed):
        if output_indices is not None:
            output_set = set(output_indices)
            for i in range(len(block_needed)):
                val = 1 if i in output_set else 0
                self._model.addConstr(output_vars[i] == val)

    def _prefix_for_input(self, name: str) -> str:
        return name[:1].lower()

    def get_solutions(self):
        if not self._verify_pool_completeness("ANF/solution collection"):
            return self.get_boolean_polynomial_ring()(0)
        start = time.time()
        sol_count = self._model.SolCount
        inputs = []
        for prio, inp_name in enumerate(self._cipher.inputs):
            if inp_name not in self._variables:
                continue
            prefix = self._prefix_for_input(inp_name)
            for idx, d in self._variables[inp_name].items():
                inputs.append((prio, prefix, idx, d["original"]))
        inputs.sort(key=lambda t: (t[0], t[1], t[2]))

        mono_set = set()
        for sn in range(sol_count):
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
            print("Number of solutions (might cancel each other) found: " + str(sol_count))
            print(f"########## printing_time : {printing_time}")
            print(f"Number of monomials found: {len(mono_set)}")
        monomials_list = sorted(mono_set)
        return self.anf_list_to_boolean_poly(monomials_list)

    def optimize_model(self):
        start = time.time()
        self._model.optimize()
        end = time.time()
        solving_time = end - start
        
        if self._model.Status != GRB.OPTIMAL:
            if self._model.Status == GRB.SUBOPTIMAL:
                print("[ERROR] Gurobi returned SUBOPTIMAL status. Result is unreliable.")
            raise ValueError(f"MILP model optimization failed with status {self._model.Status}")

        if verbosity:
            print(self._model)
            print(f"########## solving_time : {solving_time}")

    def anf_list_to_boolean_poly(self, anf_list):
        B = self.get_boolean_polynomial_ring()
        variables = B.variable_names()
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
                    digits = ""
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
        prefix_totals = {}
        for index, input_name in enumerate(self._cipher.inputs):
            bit_size = self._cipher.inputs_bit_size[index]
            prefix = input_name[0]
            start = prefix_totals.get(prefix, 0)
            variables.extend([f"{prefix}{i}" for i in range(start, start + bit_size)])
            prefix_totals[prefix] = start + bit_size
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
        current_offset = {}
        for index, input_name in enumerate(self._cipher.inputs):
            prefix = input_name[0]
            bit_size = self._cipher.inputs_bit_size[index]
            offset = current_offset.get(prefix, 0)
            input_map[f"{prefix}_{offset}"] = (input_name, bit_size, offset)
            current_offset[prefix] = offset + bit_size

        results = []
        for var in var_list:
            prefix = var[0]
            total_idx = int(var[1:])

            # Find which input component this total_idx belongs to
            found = False
            curr = 0
            for index, input_name in enumerate(self._cipher.inputs):
                if input_name[0] == prefix:
                    bit_size = self._cipher.inputs_bit_size[index]
                    if curr <= total_idx < curr + bit_size:
                        results.append((input_name, total_idx - curr))
                        found = True
                        break
                    curr += bit_size
            if not found:
                raise ValueError(f"Variable {var} out of range for prefix {prefix}")
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
        self._sbox_valid_cache = {}
        self._sbox_ineq_cache = {}

    def find_anf_of_specific_output_bit(
        self, output_bit_index, fixed_degree=None, which_var_degree=None, chosen_cipher_output=None
    ):
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
            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher # doctest: +SKIP
            sage: cipher = SimonBlockCipher(number_of_rounds=1) # doctest: +SKIP
            sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import MilpMonomialPredictionModel # doctest: +SKIP
            sage: milp = MilpMonomialPredictionModel(cipher) # doctest: +SKIP
            sage: milp.find_anf_of_specific_output_bit(0) # doctest: +SKIP
            sage: R = milp.get_boolean_polynomial_ring() # doctest: +SKIP
            sage: anf == R("p1*p8 + p2 + p16 + k48") # doctest: +SKIP
            ...

            # Example 2: Restrict the analysis to degree-2 monomials on plaintext variables
            sage: anf = milp.find_anf_of_specific_output_bit(0, fixed_degree=2, which_var_degree="p") # doctest: +SKIP
            sage: anf == R("p1*p8") # doctest: +SKIP
            ...

            # Example 3: Restrict the analysis to degree-1 monomials on key variables
            sage: milp.find_anf_of_specific_output_bit(0, fixed_degree=1, which_var_degree="k") # doctest: +SKIP
            sage: anf == R("k48") # doctest: +SKIP
            ...
        """

        self.build_generic_model_for_specific_output_bit(
            output_bit_index, fixed_degree, which_var_degree, chosen_cipher_output
        )
        self._model.setParam("PoolSolutions", 200000000)
        self._model.setParam(GRB.Param.PoolSearchMode, 2)

        self.optimize_model()
        anf = self.get_solutions()
        self._log_experiment(
            "anf",
            {
                "output_bit_index": output_bit_index,
                "fixed_degree": fixed_degree,
                "which_var_degree": which_var_degree,
                "chosen_cipher_output": chosen_cipher_output,
            },
            anf,
        )

        return anf

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

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher # doctest: +SKIP
            sage: cipher = SimonBlockCipher(number_of_rounds=2) # doctest: +SKIP
            sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import MilpMonomialPredictionModel # doctest: +SKIP
            sage: milp = MilpMonomialPredictionModel(cipher) # doctest: +SKIP
            sage: milp.check_anf_correctness(0, endian="msb") # doctest: +SKIP
            ...
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
            cipher_output = self._cipher.evaluate([assign[inp] for inp in self._cipher.inputs])
            if endian == "msb":
                real_index = output_size - 1 - output_bit_index
            else:
                real_index = output_bit_index

            expected_bit = (cipher_output >> real_index) & 1
            computed_bit = evaluate_poly(assign)

            if expected_bit != computed_bit:
                return False
        return True

    def find_partial_anf_at_cube_of_specific_output_bit(self, output_bit_index, cube, chosen_cipher_output=None):
        """
        Compute the partial ANF (symbolic cube coefficient) of a specific cipher output bit under a given cube.
        Leaves non-cube public variables symbolic.

        INPUT:

        - ``output_bit_index`` -- **integer**; index of the cipher output bit.

        - ``cube`` -- **list of strings**; variable names forming the cube.
          Example: ``["i9", "i19", "i29", "i39", "i49", "i59", "i69", "i79"]``.

        - ``chosen_cipher_output`` -- **string** (default: ``None``); intermediate component ID.

        OUTPUT:

        - **BooleanPolynomial**; the resulting partial ANF.

        EXAMPLES::

            sage: from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher
            sage: cipher = TriviumStreamCipher(keystream_bit_len=1, number_of_initialization_clocks=590)
            sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import MilpMonomialPredictionModel
            sage: milp = MilpMonomialPredictionModel(cipher) # doctest: +SKIP
            sage: cube = ["i9", "i19", "i29", "i39", "i49", "i59", "i69", "i79"]
            sage: partial_anf = milp.find_partial_anf_at_cube_of_specific_output_bit(output_bit_index=0, cube=cube) # doctest: +SKIP
            sage: R = milp.get_boolean_polynomial_ring() # doctest: +SKIP
            sage: partial_anf == R("k20*i60*i61 + k20*i60*i74 + k20*i60 + k20*i73 + i8*i60*i61 + i8*i60*i74 + i8*i60 + i8*i73 + i60*i61*i71 + i60*i61*i72*i73 + i60*i71*i74 + i60*i71 + i60*i72*i73*i74 + i60*i72*i73 + i71*i73 + i72*i73") # doctest: +SKIP
            ...
        """
        fixed_degree = None
        which_var_degree = None
        self.build_generic_model_for_specific_output_bit(
            output_bit_index, fixed_degree, which_var_degree, chosen_cipher_output
        )
        self._model.setParam("PoolSolutions", 200000000)
        self._model.setParam(GRB.Param.PoolSearchMode, 2)

        # Convert compact cube names like "i9" -> ("initialisation_vector", 9)
        cube_verbose = self.var_list_to_input_positions(cube)

        for term in cube_verbose:
            var_term = self._model.getVarByName(f"{term[0]}[{term[1]}]")
            self._model.update()
            self._model.addConstr(var_term == 1)

        self._model.update()
        self.optimize_model()
        poly = self.get_solutions()

        assignments = {v: 1 for v in cube}
        poly_sub = poly.subs(assignments)

        self._log_experiment(
            "partial_anf",
            {
                "output_bit_index": output_bit_index,
                "chosen_cipher_output": chosen_cipher_output,
                "cube": cube,
            },
            poly_sub,
        )

        return poly_sub

    def find_tight_upper_bound_degree_via_parity_of_partial_anf_at_cube_of_specific_output_bit(
        self, output_bit_index, cube, chosen_cipher_output=None
    ):
        """
        Compute a tight upper bound on the algebraic degree of the partial ANF
        corresponding to a specific output bit under a given cube.

        If the highest degree monomials have even parity, it returns d-1 as the bound.

        INPUT:

        - ``output_bit_index`` -- **integer**; index of the cipher output bit.

        - ``cube`` -- **list of strings**; variable names forming the cube.

        - ``chosen_cipher_output`` -- **string** (default: ``None``); intermediate component ID.

        OUTPUT:

        - **integer**; tight upper bound on the algebraic degree.

        EXAMPLES::

            sage: from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher # doctest: +SKIP
            sage: cipher = TriviumStreamCipher(keystream_bit_len=1, number_of_initialization_clocks=590) # doctest: +SKIP
            sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import MilpMonomialPredictionModel # doctest: +SKIP
            sage: milp = MilpMonomialPredictionModel(cipher) # doctest: +SKIP
            sage: cube = ["i9", "i19", "i29", "i39", "i49", "i59", "i69", "i79"] # doctest: +SKIP
            sage: milp.find_tight_upper_bound_degree_via_parity_of_partial_anf_at_cube_of_specific_output_bit(0, cube) # doctest: +SKIP
            ...
        """
        self.build_generic_model_for_specific_output_bit(
            output_bit_index, None, None, chosen_cipher_output
        )
        m = self._model
        self._set_pool_enumeration_params()

        cube_verbose = self.var_list_to_input_positions(cube)
        for term in cube_verbose:
            var_term = m.getVarByName(f"{term[0]}[{term[1]}]")
            if var_term is not None:
                m.addConstr(var_term == 1)
        m.update()

        key_vars = self._resolve_key_vars()
        m.setObjective(sum(key_vars), GRB.MAXIMIZE)
        m.update()
        m.optimize()

        if m.Status == GRB.OPTIMAL:
            d = int(round(m.ObjVal))
            tight_degree = self._tight_upper_bound_degree_from_solution_pool(key_vars, d)
        elif m.Status == GRB.INFEASIBLE:
            tight_degree = -1
        else:
            raise RuntimeError(
                f"Gurobi failed to find a guaranteed optimal solution (Status: {m.Status}). "
                "A guaranteed optimal solution is required for parity-based results."
            )
        
        self._log_experiment(
            "tight upper bound degree partial anf",
            {"output_bit_index": output_bit_index, "cube": cube},
            tight_degree,
        )
        return tight_degree

    def find_tight_upper_bound_degree_via_parity_of_partial_anf_at_cube_of_all_output_bits(
        self, cube, chosen_cipher_output=None
    ):
        """
        Compute a tight upper bound on the algebraic degree of the partial ANF
        for all output bits under a given cube.
        If the highest degree monomials have even parity, it returns d-1 as the bound.

        INPUT:
        - ``cube`` -- **list of strings**; variable names forming the cube.
        - ``chosen_cipher_output`` -- **string** (default: ``None``); intermediate component ID.

        OUTPUT:
        - **list[int]**; tight upper bounds for each output bit.
        """
        output_vars = self._init_master_for_all_output_bits(chosen_cipher_output)
        m = self._model
        for term in self.var_list_to_input_positions(cube):
            var_term = m.getVarByName(f"{term[0]}[{term[1]}]")
            if var_term is not None:
                m.addConstr(var_term == 1)

        key_vars = self._resolve_key_vars()
        m.setObjective(sum(key_vars), GRB.MAXIMIZE)
        self._set_pool_enumeration_params()
        m.update()

        degrees = self._run_tight_upper_bound_degree_per_bit_loop(output_vars, key_vars)
        self._log_experiment(
            "all bits tight upper bound degree partial anf",
            {"cube": cube},
            degrees,
        )
        return degrees

    def find_tight_upper_bound_degree_via_parity_of_superpoly_of_specific_output_bit(self, output_bit_index, cube, chosen_cipher_output=None):
        """
        Compute a tight upper bound on the algebraic degree of the superpoly
        corresponding to a specific output bit under a given cube.
        Fixes all non-cube public variables to zero.

        If the highest degree monomials have even parity, it returns d-1 as the bound.

        INPUT:

        - ``output_bit_index`` -- **integer**; index (0-based, counting from the most
          significant bit) of the cipher output bit.

        - ``cube`` -- **list of strings**; variable names forming the cube.

        - ``chosen_cipher_output`` -- **string** (default: ``None``); specify a cipher component
          ID if targeting an intermediate output.

        OUTPUT:

        - **integer**; tight upper bound on the algebraic degree of the superpoly.

        EXAMPLES::

            sage: from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher # doctest: +SKIP
            sage: cipher = TriviumStreamCipher(keystream_bit_len=1, number_of_initialization_clocks=200) # doctest: +SKIP
            sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import MilpMonomialPredictionModel # doctest: +SKIP
            sage: milp = MilpMonomialPredictionModel(cipher) # doctest: +SKIP
            sage: cube = ["i53"] # doctest: +SKIP
            sage: milp.find_tight_upper_bound_degree_via_parity_of_superpoly_of_specific_output_bit(0, cube) # doctest: +SKIP
            ...
        """
        self.build_generic_model_for_specific_output_bit(
            output_bit_index, None, None, chosen_cipher_output
        )

        m = self._model
        self._set_pool_enumeration_params()

        self._constrain_cube_and_public_vars(cube, None)
        m.update()

        key_vars = self._resolve_key_vars()

        m.setObjective(sum(key_vars), GRB.MAXIMIZE)
        m.update()
        m.optimize()

        if m.Status == GRB.OPTIMAL:
            d = int(round(m.ObjVal))
            tight_degree = self._tight_upper_bound_degree_from_solution_pool(key_vars, d)
        elif m.Status == GRB.INFEASIBLE:
            print(MODEL_INFEASIBLE_MSG) if verbosity else None
            tight_degree = -1
        else:
            raise RuntimeError(
                f"Gurobi failed to find a guaranteed optimal solution (Status: {m.Status}). "
                "A guaranteed optimal solution is required for parity-based results."
            )

        self._log_experiment(
            "tight upper bound degree superpoly",
            {
                "output_bit_index": output_bit_index,
                "chosen_cipher_output": chosen_cipher_output,
                "cube": cube,
            },
            tight_degree,
        )

        return tight_degree

    def _init_master_for_all_output_bits(self, chosen_cipher_output):
        """Build the MILP master used by the three ``find_*_of_all_output_bits``
        methods: full cipher constraints, the output-variable array and the
        Hamming-weight-1 constraint on the output. Returns the list of
        output binary variables. The caller then sets its own objective and
        solver parameters before iterating per output bit.
        """
        self.re_init()
        self.build_model_with_input_output_constraints(
            output_indices=None,
            chosen_cipher_output=chosen_cipher_output,
        )
        output_vars = list(self._variables["output"].values())
        self._model.addConstr(sum(output_vars) == 1, name="hw_one_output")
        return output_vars

    def _resolve_input_group_vars(self, which_var_degree):
        """Return the binary variables of the chosen input group, used as
        the objective by ``find_upper_bound_degree_of_all_output_bits`` and
        ``find_tight_upper_bound_degree_via_parity_of_all_output_bits``.
        """
        if which_var_degree is None:
            target_inputs = [(self._cipher.inputs[0], self._cipher.inputs_bit_size[0])]
        else:
            target_inputs = [
                (inp, size)
                for inp, size in zip(self._cipher.inputs, self._cipher.inputs_bit_size)
                if inp.startswith(which_var_degree)
            ]
        target_vars = []
        for inp, size in target_inputs:
            for bit in range(size):
                v = self._model.getVarByName(f"{inp}[{bit}]")
                if v is not None:
                    target_vars.append(v)
        return target_vars

    def _resolve_key_vars(self):
        """Return the Gurobi variables of the cipher's key input.

        Raises ``ValueError`` if the cipher definition has no key input.
        """
        key_input_index = next(
            (i for i, inp in enumerate(self._cipher.inputs) if inp.startswith("k")),
            None,
        )
        if key_input_index is None:
            raise ValueError("No key input found in cipher definition.")
        key_size = self._cipher.inputs_bit_size[key_input_index]
        m = self._model
        return [m.getVarByName(f"key[{i}]") for i in range(key_size) if m.getVarByName(f"key[{i}]") is not None]

    def _set_pool_enumeration_params(self):
        """Configure Gurobi to enumerate every optimal solution in the pool."""
        m = self._model
        m.Params.OutputFlag = 0
        m.setParam(GRB.Param.PoolSearchMode, 2)
        m.setParam(GRB.Param.PoolSolutions, 200000000)
        m.setParam(GRB.Param.PoolGap, 0.0)

    def _verify_pool_completeness(self, experiment_name="computation", model=None):
        """
        Verify that the solver status is optimal and the solution pool was not
        truncated. Missing trails can flip parity results, leading to incorrect
        ANF or degree reports. ``model`` defaults to ``self._model`` but may be a
        sub-model (e.g. a divide-and-conquer core model).
        """
        m = model if model is not None else self._model
        if m.Status == GRB.SUBOPTIMAL:
            msg = f"[ERROR] Gurobi returned SUBOPTIMAL status for {experiment_name}. Result is unreliable."
            print(msg)
            return False

        if m.SolCount >= m.Params.PoolSolutions:
            msg = (f"[ERROR] Solution pool reached limit ({m.Params.PoolSolutions}) during {experiment_name}. "
                   "Some trails were likely missed, making parity-based results incorrect.")
            print(msg)
            return False
        return True

    def _collect_input_vars_info(self):
        """Return ``[(prefix, idx, gurobi_var), ...]`` for every symbolic input bit,
        in a fixed order so that identical monomials always stringify identically.
        """
        inputs_info = []
        for inp_name in self._cipher.inputs:
            if inp_name not in self._variables:
                continue
            prefix = self._prefix_for_input(inp_name)
            for idx, var_d in self._variables[inp_name].items():
                inputs_info.append((prefix, idx, var_d["original"]))
        return inputs_info

    def _solution_full_monomial(self, inputs_info, target_vars_set):
        """For the currently selected pool solution, return
        ``(full_monomial_string, degree_in_target_vars)``. The monomial string is
        built over the complete input support so distinct monomials are not merged.
        """
        toks = []
        deg = 0
        for prefix, idx, var in inputs_info:
            if var.Xn > 0.5:
                toks.append(f"{prefix}{idx}")
                if var in target_vars_set:
                    deg += 1
        mono = "1" if not toks else "".join(toks)
        return mono, deg

    def _tight_upper_bound_degree_from_solution_pool(self, target_vars, candidate_degree):
        """Walk the current Gurobi solution pool and apply the parity /
        degree-drop rule. If the highest degree monomials have even parity, it returns d-1 as the bound.

        Aggregates parity over the complete input monomial (all symbolic inputs)
        to avoid incorrect cancellations.
        """
        m = self._model
        # Reject suboptimal or truncated pools
        if m.Status != GRB.OPTIMAL:
            return -1
        if not self._verify_pool_completeness("tight upper bound degree"):
            return -1

        target_vars_set = set(target_vars)
        inputs_info = self._collect_input_vars_info()

        monomial_parity = {}
        for s in range(m.SolCount):
            m.Params.SolutionNumber = s
            mono, deg = self._solution_full_monomial(inputs_info, target_vars_set)
            if deg == candidate_degree:
                monomial_parity[mono] = monomial_parity.get(mono, 0) ^ 1

        return candidate_degree if any(val == 1 for val in monomial_parity.values()) else candidate_degree - 1

    def _run_tight_upper_bound_degree_per_bit_loop(self, output_vars, target_vars):
        """Per-output-bit loop with parity enumeration.
        If the highest degree monomials have even parity, it returns d-1 as the bound.
        """
        m = self._model
        degrees = []
        for i in range(len(output_vars)):
            c = m.addConstr(output_vars[i] == 1)
            m.update()
            m.optimize()
            if m.Status == GRB.OPTIMAL:
                degrees.append(self._tight_upper_bound_degree_from_solution_pool(target_vars, int(round(m.ObjVal))))
            elif m.Status == GRB.INFEASIBLE:
                print(f"[INFO] Model infeasible for output bit {i}") if verbosity else None
                degrees.append(-1)
            else:
                raise RuntimeError(
                    f"Gurobi failed to find a guaranteed optimal solution for bit {i} (Status: {m.Status}). "
                    "A guaranteed optimal solution is required for parity-based results."
                )
            m.remove(c)
            m.update()
        return degrees

    def find_tight_upper_bound_degree_via_parity_of_superpoly_of_all_output_bits(self, cube, chosen_cipher_output=None):
        """
        Compute a tight upper bound on the algebraic degree of the superpoly
        for all output bits under a given cube.
        Fixes all non-cube public variables to zero.
        If the highest degree monomials have even parity, it returns d-1 as the bound.
        """
        global verbosity
        old_verbosity = verbosity
        verbosity = False

        output_vars = self._init_master_for_all_output_bits(chosen_cipher_output)
        m = self._model

        self._constrain_cube_and_public_vars(cube, None)

        key_vars = self._resolve_key_vars()
        m.setObjective(sum(key_vars), GRB.MAXIMIZE)
        self._set_pool_enumeration_params()
        m.update()

        degrees = self._run_tight_upper_bound_degree_per_bit_loop(output_vars, key_vars)

        verbosity = old_verbosity
        self._log_experiment(
            "all output bits tight upper bound degree superpoly",
            {"chosen_cipher_output": chosen_cipher_output, "cube": cube},
            degrees,
        )

        return degrees

    def find_upper_bound_degree_of_specific_output_bit(
        self, output_bit_index, which_var_degree=None, chosen_cipher_output=None
    ):
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

            sage: from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher # doctest: +SKIP
            sage: cipher = TriviumStreamCipher(keystream_bit_len=1, number_of_initialization_clocks=508) # doctest: +SKIP
            sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import MilpMonomialPredictionModel # doctest: +SKIP
            sage: milp = MilpMonomialPredictionModel(cipher) # doctest: +SKIP
            sage: milp.find_upper_bound_degree_of_specific_output_bit(0, which_var_degree="i") # doctest: +SKIP
            ...
        """
        fixed_degree = None
        self.build_generic_model_for_specific_output_bit(
            output_bit_index, fixed_degree, which_var_degree, chosen_cipher_output
        )

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
        self.optimize_model()

        if self._model.Status not in [GRB.OPTIMAL, GRB.SUBOPTIMAL]:
            print(MODEL_INFEASIBLE_MSG) if verbosity else None
            degree_upper_bound = -1
        else:
            degree_upper_bound = int(round(self._model.ObjVal))

        self._log_experiment(
            "upper bound degree",
            {
                "output_bit_index": output_bit_index,
                "chosen_cipher_output": chosen_cipher_output,
                "which_var_degree": which_var_degree,
            },
            degree_upper_bound,
        )

        return degree_upper_bound

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

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher # doctest: +SKIP
            sage: cipher = SimonBlockCipher(number_of_rounds=4) # doctest: +SKIP
            sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import MilpMonomialPredictionModel # doctest: +SKIP
            sage: milp = MilpMonomialPredictionModel(cipher) # doctest: +SKIP
            sage: milp.find_upper_bound_degree_of_all_output_bits(which_var_degree="p") # doctest: +SKIP
            ...
        """
        global verbosity
        old_verbosity = verbosity
        verbosity = False

        output_vars = self._init_master_for_all_output_bits(chosen_cipher_output)
        target_vars = self._resolve_input_group_vars(which_var_degree)
        m = self._model
        m.setObjective(sum(target_vars), GRB.MAXIMIZE)
        m.setParam(GRB.Param.PoolSearchMode, 0)
        m.setParam("MIPGap", 0)
        m.Params.OutputFlag = 0
        m.update()

        degrees = []
        for i in range(len(output_vars)):
            c = m.addConstr(output_vars[i] == 1)
            m.update()
            m.optimize()
            if m.Status in (GRB.OPTIMAL, GRB.SUBOPTIMAL):
                degrees.append(int(round(m.ObjVal)))
            else:
                print(f"[INFO] Model is infeasible for output bit {i}") if verbosity else None
                degrees.append(-1)
            m.remove(c)
            m.update()

        verbosity = old_verbosity

        self._log_experiment(
            "all output bits upper bound degree",
            {
                "chosen_cipher_output": chosen_cipher_output,
                "which_var_degree": which_var_degree,
            },
            degrees,
        )

        return degrees

    def find_tight_upper_bound_degree_via_parity_of_specific_output_bit(
        self, output_bit_index, which_var_degree=None, chosen_cipher_output=None
    ):
        """
        Compute a tight upper bound on the algebraic degree of the ANF
        for a specific cipher output bit with respect to a chosen input variable group.

        If the highest degree monomials have even parity, it returns d-1 as the bound.

        INPUT:

        - ``output_bit_index`` -- **integer**; index (0-based, counting from the most
          significant bit) of the cipher output bit to analyze.

        - ``which_var_degree`` -- **string** (default: ``None``); prefix identifying which
          input group the algebraic degree should be computed over:
            * ``"k"`` → degree with respect to key bits
            * ``"p"`` → degree with respect to plaintext bits
            * ``"i"`` → degree with respect to IV bits
          If ``None`` (default), the first input listed in ``self._cipher.inputs`` is used.

        - ``chosen_cipher_output`` -- **string** (default: ``None``); specify a cipher component
          ID if the computation targets an intermediate output instead of the final cipher output.

        OUTPUT:

        - **integer**; tight upper bound on the algebraic degree of the selected output bit.

        EXAMPLES::

            sage: from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher
            sage: cipher = TriviumStreamCipher(keystream_bit_len=1, number_of_initialization_clocks=508)
            sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import MilpMonomialPredictionModel
            sage: milp = MilpMonomialPredictionModel(cipher) # doctest: +SKIP
            sage: milp.find_tight_upper_bound_degree_via_parity_of_specific_output_bit(0, which_var_degree="i") # doctest: +SKIP
            ...
        """
        fixed_degree = None
        self.build_generic_model_for_specific_output_bit(
            output_bit_index, fixed_degree, which_var_degree, chosen_cipher_output
        )

        m = self._model
        self._set_pool_enumeration_params()

        vars_target = self._resolve_input_group_vars(which_var_degree)

        m.setObjective(sum(vars_target), GRB.MAXIMIZE)
        m.update()
        m.optimize()

        if m.Status == GRB.OPTIMAL:
            d = int(round(m.ObjVal))
            tight_degree = self._tight_upper_bound_degree_from_solution_pool(vars_target, d)
        elif m.Status == GRB.INFEASIBLE:
            print(MODEL_INFEASIBLE_MSG) if verbosity else None
            tight_degree = -1
        else:
            raise RuntimeError(
                f"Gurobi failed to find a guaranteed optimal solution (Status: {m.Status}). "
                "A guaranteed optimal solution is required for parity-based results."
            )

        self._log_experiment(
            "tight upper bound degree",
            {
                "output_bit_index": output_bit_index,
                "chosen_cipher_output": chosen_cipher_output,
                "which_var_degree": which_var_degree,
            },
            tight_degree,
        )

        return tight_degree

    def find_tight_upper_bound_degree_via_parity_of_all_output_bits(self, which_var_degree=None, chosen_cipher_output=None):
        """
        Compute a tight upper bound on the algebraic degree for all cipher output bits.

        If the highest degree monomials have even parity, it returns d-1 as the bound.

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

        - **list of integers**; tight upper bound on the algebraic degrees of all cipher output bits.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: cipher = SimonBlockCipher(number_of_rounds=4)
            sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import MilpMonomialPredictionModel
            sage: milp = MilpMonomialPredictionModel(cipher) # doctest: +SKIP
            sage: milp.find_tight_upper_bound_degree_via_parity_of_all_output_bits(which_var_degree="p") # doctest: +SKIP
            ...
        """
        global verbosity
        old_verbosity = verbosity
        verbosity = False

        output_vars = self._init_master_for_all_output_bits(chosen_cipher_output)
        target_vars = self._resolve_input_group_vars(which_var_degree)
        self._model.setObjective(sum(target_vars), GRB.MAXIMIZE)
        self._set_pool_enumeration_params()
        self._model.update()

        degrees = self._run_tight_upper_bound_degree_per_bit_loop(output_vars, target_vars)

        verbosity = old_verbosity

        self._log_experiment(
            "all output bits tight upper bound degree",
            {
                "chosen_cipher_output": chosen_cipher_output,
                "which_var_degree": which_var_degree,
            },
            degrees,
        )

        return degrees

    def find_degree_in_cube_vars_of_specific_output_bit(
        self,
        output_bit_index,
        cube,
        chosen_cipher_output=None,
    ):
        r"""
        Compute an upper bound degree of the cipher output bit with respect to the given cube variables.

        INPUT:

        - ``output_bit_index`` -- **integer**
          Index (0-based, counting from the most significant bit).

        - ``cube`` -- **list of strings**
          List of cube variable names (e.g. ``["p1", "p3", "p8"]``) to compute the degree over.

        - ``chosen_cipher_output`` -- **string** (default: ``None``)
          Optional component ID if the computation targets an intermediate output
          instead of the final cipher output.

        OUTPUT:

        - **integer**
          Upper bound degree of the given output bit in the given cube variables.
          Returns ``-1`` if the model is infeasible.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher # doctest: +SKIP
            sage: cipher = SimonBlockCipher(number_of_rounds=13) # doctest: +SKIP
            sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import MilpMonomialPredictionModel # doctest: +SKIP
            sage: milp = MilpMonomialPredictionModel(cipher)  # doctest: +SKIP
            sage: cube = [f"p{i}" for i in range(1, 32)] # doctest: +SKIP
            sage: d = milp.find_degree_in_cube_vars_of_specific_output_bit(16, cube)  # doctest: +SKIP
            ...
        """
        self.build_generic_model_for_specific_output_bit(
            output_bit_index, fixed_degree=None, which_var_degree=None, chosen_cipher_output=chosen_cipher_output
        )
        m = self._model
        m.Params.OutputFlag = 0
        m.setParam(GRB.Param.PoolSearchMode, 0)
        m.setParam("MIPGap", 0)
        m.setParam("OptimalityTol", 1e-9)

        cube_verbose = self.var_list_to_input_positions(cube)
        cube_set = {(a, b) for (a, b) in cube_verbose}

        # Objective: maximize degree in the cube variables
        cube_vars = [m.getVarByName(f"{inp_name}[{idx}]") for (inp_name, idx) in cube_verbose]
        m.setObjective(sum(cube_vars), GRB.MAXIMIZE)

        # Fix all other non-cube public input bits to 0
        for inp, sz in zip(self._cipher.inputs, self._cipher.inputs_bit_size):
            pref = inp[0]
            if pref in {"p", "i"}:
                for i in range(sz):
                    if (inp, i) in cube_set:
                        continue
                    v = m.getVarByName(f"{inp}[{i}]")
                    if v is not None:
                        m.addConstr(v == 0)

        m.update()
        m.optimize()

        if m.Status != GRB.OPTIMAL:
            if verbosity:
                print(f"[INFO] Model not optimal for output bit {output_bit_index}")
            return -1

        degree_in_cube_vars = int(round(m.ObjVal))

        self._log_experiment(
            "degree in cube vars",
            {"output_bit_index": output_bit_index, "chosen_cipher_output": chosen_cipher_output, "cube": cube},
            degree_in_cube_vars,
        )

        return degree_in_cube_vars

    def find_upper_bound_degree_of_cube_monomial_of_specific_output_bit(
        self,
        output_bit_index,
        cube,
        chosen_cipher_output=None,
    ):
        r"""
        Compute an upper bound degree of the given cube monomial relatively to the given cipher output bit.

        INPUT:

        - ``output_bit_index`` -- **integer**
          Index (0-based, counting from the most significant bit).

        - ``cube`` -- **list of strings**
          List of cube variable names (e.g. ``["p1", "p3", "p8"]``) representing the cube variables fixed to 1.

        - ``chosen_cipher_output`` -- **string** (default: ``None``)
          Optional component ID if the computation targets an intermediate output
          instead of the final cipher output.

        OUTPUT:

        - **integer**
          Upper bound degree of the given cube monomial. Maximum value is the number of variables involved in the cube.
          Returns ``-1`` if the model is infeasible.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher # doctest: +SKIP
            sage: cipher = SimonBlockCipher(number_of_rounds=13) # doctest: +SKIP
            sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import MilpMonomialPredictionModel # doctest: +SKIP
            sage: milp = MilpMonomialPredictionModel(cipher)  # doctest: +SKIP
            sage: cube = [f"p{i}" for i in range(1, 32)] # doctest: +SKIP
            sage: d = milp.find_upper_bound_degree_of_cube_monomial_of_specific_output_bit(16, cube)  # doctest: +SKIP
            ...
        """
        self.build_generic_model_for_specific_output_bit(
            output_bit_index, fixed_degree=None, which_var_degree=None, chosen_cipher_output=chosen_cipher_output
        )
        m = self._model
        m.Params.OutputFlag = 0
        m.setParam(GRB.Param.PoolSearchMode, 0)
        m.setParam("MIPGap", 0)

        # Fix cube bits to 1
        cube_verbose = self.var_list_to_input_positions(cube)
        for inp_name, idx in cube_verbose:
            v = m.getVarByName(f"{inp_name}[{idx}]")
            m.addConstr(v == 1)

        # Objective: maximize number of cube variables influencing the degree
        cube_vars = [m.getVarByName(f"{inp_name}[{idx}]") for (inp_name, idx) in cube_verbose]
        m.setObjective(sum(cube_vars), GRB.MAXIMIZE)
        m.update()
        m.optimize()

        if m.Status not in [GRB.OPTIMAL, GRB.SUBOPTIMAL]:
            if verbosity:
                print(f"[INFO] Model infeasible for output bit {output_bit_index}")
            return -1

        degree_upper_bound = int(round(m.ObjVal))

        self._log_experiment(
            "upper bound degree of cube monomial",
            {"output_bit_index": output_bit_index, "chosen_cipher_output": chosen_cipher_output, "cube": cube},
            degree_upper_bound,
        )

        return degree_upper_bound

    def _fix_non_cube_public_bits_to_zero(self, cube_set):
        """Constrain every public (plaintext/IV) input bit not in the cube to 0.

        ``cube_set`` is a set of ``(input_name, bit_index)`` tuples.
        """
        m = self._model
        for inp, sz in zip(self._cipher.inputs, self._cipher.inputs_bit_size):
            if inp[0] not in ("p", "i"):
                continue
            for i in range(sz):
                if (inp, i) in cube_set:
                    continue
                v = m.getVarByName(f"{inp}[{i}]")
                if v is not None:
                    m.addConstr(v == 0)

    def is_balanced_at_specific_output_bit_over_cube(
        self,
        output_bit_index,
        cube,
        chosen_cipher_output=None,
    ):
        r"""
        Feasibility-based integral distinguisher check.

        Fixes cube bits to 1 and non-cube public bits to 0. If the model is INFEASIBLE,
        the output bit is provably balanced over the cube (zero-sum).

        INPUT:
        - ``output_bit_index`` -- **integer**
        - ``cube`` -- **list of strings**
        - ``chosen_cipher_output`` -- **string** (default: ``None``)

        OUTPUT:
        - **bool**; ``True`` if balanced, ``False`` if not proved.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher # doctest: +SKIP
            sage: cipher = SimonBlockCipher(number_of_rounds=4) # doctest: +SKIP
            sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import MilpMonomialPredictionModel # doctest: +SKIP
            sage: milp = MilpMonomialPredictionModel(cipher)  # doctest: +SKIP
            sage: cube = ["p1", "p2"] # doctest: +SKIP
            sage: milp.is_balanced_at_specific_output_bit_over_cube(0, cube)  # doctest: +SKIP
            ...
        """
        self.build_generic_model_for_specific_output_bit(
            output_bit_index, fixed_degree=None, which_var_degree=None, chosen_cipher_output=chosen_cipher_output
        )
        m = self._model
        m.Params.OutputFlag = 0
        m.setParam(GRB.Param.PoolSearchMode, 0)

        cube_verbose = self.var_list_to_input_positions(cube)
        cube_set = set(cube_verbose)

        # public non-cube input bits (plaintext / IV) -> 0
        self._fix_non_cube_public_bits_to_zero(cube_set)
        # active cube bits -> 1
        for inp_name, idx in cube_verbose:
            v = m.getVarByName(f"{inp_name}[{idx}]")
            if v is not None:
                m.addConstr(v == 1)

        m.setObjective(0, GRB.MINIMIZE)
        m.update()
        m.optimize()

        balanced = (m.Status == GRB.INFEASIBLE)
        self._log_experiment(
            "balanced for cube",
            {
                "output_bit_index": output_bit_index,
                "chosen_cipher_output": chosen_cipher_output,
                "cube": cube,
            },
            balanced,
        )
        return balanced

    def find_superpoly_of_specific_output_bit(
        self,
        output_bit_index,
        cube,
        chosen_cipher_output=None,
    ):
        """
        Compute the superpoly of a specific cipher output bit under a given cube.
        Fixes all non-cube public variables to zero.

        INPUT:

        - ``output_bit_index`` -- **integer**; index (0-based, counting from the most
          significant bit) of the cipher output bit.

        - ``cube`` -- **list of strings**; variable names forming the cube.
          Example: ``["i53"]``.

        - ``chosen_cipher_output`` -- **string** (default: ``None``); specify a cipher component
          ID if targeting an intermediate output.

        OUTPUT:

        - **Sage BooleanPolynomial**; Boolean polynomial over key variables.

        EXAMPLES::

            sage: from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher
            sage: cipher = TriviumStreamCipher(keystream_bit_len=1, number_of_initialization_clocks=200)
            sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import MilpMonomialPredictionModel
            sage: milp = MilpMonomialPredictionModel(cipher) # doctest: +SKIP
            sage: cube = ["i53"]
            sage: superpoly = milp.find_superpoly_of_specific_output_bit(0, cube) # doctest: +SKIP
            sage: superpoly # doctest: +SKIP
            ...
        """
        self.build_generic_model_for_specific_output_bit(
            output_bit_index, fixed_degree=None, which_var_degree=None, chosen_cipher_output=chosen_cipher_output
        )
        m = self._model
        m.Params.OutputFlag = 0
        m.setParam(GRB.Param.PoolSearchMode, 2)
        m.setParam(GRB.Param.PoolSolutions, 200000000)
        m.setParam(GRB.Param.PoolGap, 0.0)

        cube_verbose = self.var_list_to_input_positions(cube)
        cube_set = {(a, b) for (a, b) in cube_verbose}

        # Fix cube bits to 1
        for inp_name, idx in cube_verbose:
            v = m.getVarByName(f"{inp_name}[{idx}]")
            m.addConstr(v == 1)

        cube_vars = [m.getVarByName(f"{a}[{b}]") for (a, b) in cube_verbose]
        m.addConstr(sum(cube_vars) == len(cube))

        # Fix all other non-cube public input bits to 0
        self._fix_non_cube_public_bits_to_zero(cube_set)

        m.setObjective(0.0, GRB.MAXIMIZE)
        m.update()
        m.optimize()

        if m.Status != GRB.OPTIMAL or m.SolCount == 0:
            if verbosity:
                print(f"[INFO] Model infeasible or no valid solutions for output bit {output_bit_index}")
            return self.get_boolean_polynomial_ring()(0)

        poly_full = self.get_solutions()

        # Substitute cube bits to 1
        subs_map = {f"{inp_name[0]}{idx}": 1 for (inp_name, idx) in cube_verbose}
        key_coef_poly = poly_full.subs(subs_map)

        self._log_experiment(
            "superpoly",
            {"output_bit_index": output_bit_index, "chosen_cipher_output": chosen_cipher_output, "cube": cube},
            key_coef_poly,
        )

        return key_coef_poly

    def _log_experiment(
        self,
        experiment_name: str,
        details: dict,
        content: object,
    ):
        """
        Internal helper to log experiment results to a timestamped text file.
        Used whenever verbosity is enabled to avoid code duplication.

        Args:
            experiment_name (str): Short label for the experiment (e.g., "ANF", "superpoly").
            details (dict): Key-value pairs to include in the header (e.g., output_bit_index, cube, etc.).
            content (object): The main content to log (e.g., a polynomial, integer, or list); stringified before writing.
            folder (str): Target folder name for logs (default: "monomial_prediction_experiments").
        """
        if not verbosity:
            return

        folder = "monomial_prediction_experiments"
        os.makedirs(folder, exist_ok=True)
        filename = os.path.join(folder, f"{self._cipher._id}.txt")
        try:
            with open(filename, "a", encoding="utf-8") as f:
                f.write("\n" + "=" * 80 + "\n")
                f.write(f"Experiment: {experiment_name}\n")
                for k, v in details.items():
                    f.write(f"{k}: {v}\n")
                f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("-" * 10 + "\n")
                f.write(str(content))
                f.write("\n\n")
            print(f"[INFO] {experiment_name} successfully saved to '{filename}'")
        except Exception as e:
            print(f"[WARNING] Failed to save {experiment_name} to file: {e}")

    def _setup_key_variables_and_ring(self):
        key_input_indices = [i for i, inp in enumerate(self._cipher.inputs) if "key" in inp.lower()]
        has_key = len(key_input_indices) > 0

        if not has_key:
            B = BooleanPolynomialRing(1, "k0")
            return key_input_indices, False, B, B.gens()

        key_var_names = []
        SUPERSCRIPTS = str.maketrans("0123456789", "⁰¹²³⁴⁵⁶⁷⁸⁹")
        for i in key_input_indices:
            inp_name = self._cipher.inputs[i]
            size = self._cipher.inputs_bit_size[i]
            parts = inp_name.split("_")

            if len(parts) >= 2 and "key" in parts[0].lower() and parts[1].isdigit():
                round_sup = parts[1].translate(SUPERSCRIPTS)
                key_var_names.extend([f"k{round_sup}{b}" for b in range(size)])
            else:
                for _ in range(size):
                    key_var_names.append(f"k{len(key_var_names)}")

        B = BooleanPolynomialRing(len(key_var_names), tuple(key_var_names))
        return key_input_indices, True, B, B.gens()

    def _get_split_ciphers(self, middle_round, verbosity):
        if not (0 < middle_round < self._cipher.number_of_rounds):
            raise ValueError(
                f"Middle round {middle_round} out of valid range (1 to {self._cipher.number_of_rounds - 1})"
            )

        cipher_copy = deepcopy(self._cipher)
        cipher1 = cipher_copy.get_partial_cipher(0, middle_round - 1)
        cipher2 = cipher_copy.get_partial_cipher(middle_round, self._cipher.number_of_rounds - 1)

        if "key" not in self._cipher.inputs:
            if verbosity:
                print("Propagating remove_key_schedule to sub-ciphers.")
            cipher2 = cipher2.remove_key_schedule()
        return cipher1, cipher2

    def _get_round_output_comp(self, middle_round):
        mid_round_obj = self._cipher.rounds_as_list[middle_round - 1]
        for comp in mid_round_obj.components:
            if comp.type == INTERMEDIATE_OUTPUT and "round_output" in comp.description:
                return comp

        c_idx = middle_round + self._cipher.components_before_round_starts + 1
        comp = self._cipher.component_from_id(f"intermediate_output_{middle_round}_{c_idx}")
        if comp is None:
            raise ValueError(f"Could not find round_output component at round {middle_round}")
        return comp

    def _get_skip_for_enum(self):
        skip_for_enum = set()
        G = create_networkx_graph_from_input_ids(self._cipher)
        for rnd in self._cipher.rounds_as_list:
            for c in rnd.components:
                if c.type == INTERMEDIATE_OUTPUT and G.out_degree(c.id) == 0:
                    skip_for_enum.add(c.id)
        return skip_for_enum

    def _constrain_cube_and_public_vars(self, cube, key_input_indices):
        cube_verbose = self.var_list_to_input_positions(cube)
        cube_vars_set = {f"{term[0]}[{term[1]}]" for term in cube_verbose}

        # If no key_input_indices provided, identify all key inputs
        if key_input_indices is None:
            key_input_indices = [i for i, inp in enumerate(self._cipher.inputs) if "key" in inp.lower()]

        for var_name in cube_vars_set:
            var_term = self._model.getVarByName(var_name)
            if var_term is not None:
                self._model.addConstr(var_term == 1)

        self._fix_non_key_non_cube_bits_to_zero(cube_vars_set, key_input_indices)

    def _fix_non_key_non_cube_bits_to_zero(self, cube_vars_set, key_input_indices):
        """Constrain every non-key input bit whose Gurobi name is not in
        ``cube_vars_set`` to 0. ``cube_vars_set`` holds ``"input[bit]"`` names.
        """
        for i, inp in enumerate(self._cipher.inputs):
            if i in key_input_indices:
                continue
            for bit in range(self._cipher.inputs_bit_size[i]):
                var_name = f"{inp}[{bit}]"
                if var_name in cube_vars_set:
                    continue
                var_term = self._model.getVarByName(var_name)
                if var_term is not None:
                    self._model.addConstr(var_term == 0)

    def _get_escape_idx(self, link_id, middle_round, skip_for_enum):
        used_predecessors = []
        for r_tmp in self._cipher.rounds_as_list:
            for comp in r_tmp.components:
                if link_id in comp.input_id_links and comp.id not in skip_for_enum:
                    used_predecessors.append(comp.id)

        tmp = {r: {} for r in range(self._cipher.number_of_rounds)}
        for c_id in used_predecessors:
            r = int(c_id.split("_")[-2])
            tmp[r][c_id] = int(c_id.split("_")[-1])

        used_predecessors_sorted = []
        for r in range(self._cipher.number_of_rounds):
            used_predecessors_sorted += list(dict(sorted(tmp[r].items(), key=lambda item: item[1])).keys())

        for idx, c_id in enumerate(used_predecessors_sorted):
            if int(c_id.split("_")[-2]) > middle_round - 1:
                return idx
        return -1

    def _get_mid_var_for_link(self, var_dict, link_id, middle_round, skip_for_enum):
        if not skip_for_enum:
            return var_dict.get("copies", [var_dict["original"]])[-1]

        escape_idx = self._get_escape_idx(link_id, middle_round, skip_for_enum)
        if escape_idx <= 0:
            return var_dict["original"]
        elif escape_idx < len(var_dict.get("copies", [])):
            return var_dict["copies"][escape_idx]
        return var_dict["original"]

    def _resolve_mid_var(self, link_id, pos, skip_for_enum, middle_round):
        if link_id in self._variables and pos in self._variables[link_id]:
            return self._get_mid_var_for_link(self._variables[link_id][pos], link_id, middle_round, skip_for_enum)

        src = self._model.getVarByName(f"{link_id}[{pos}]")
        if src is not None:
            return src

        dummy = self._model.addVar(vtype=GRB.BINARY, name=f"dead_end_{link_id}[{pos}]")
        self._model.addConstr(dummy == 0)
        return dummy

    def _identify_mid_vars_list(self, round_output_comp, skip_for_enum, middle_round):
        mid_vars_list = []
        for link_idx, link_id in enumerate(round_output_comp.input_id_links):
            for pos in round_output_comp.input_bit_positions[link_idx]:
                v = self._resolve_mid_var(link_id, pos, skip_for_enum, middle_round)
                mid_vars_list.append(v)

        self._model.update()
        if len(mid_vars_list) != round_output_comp.output_bit_size:
            raise ValueError("Could not collect mid-state bits")
        return mid_vars_list

    def _enumerate_feasible_states(self, mid_vars_list, verbosity):
        feasible_states = set()

        def mid_state_callback(model, where):
            if where == GRB.Callback.MIPSOL:
                state = tuple(round(model.cbGetSolution(v)) for v in mid_vars_list)
                if state not in feasible_states:
                    feasible_states.add(state)
                    if mid_vars_list:
                        lhs = sum((1 - v) if state[i] else v for i, v in enumerate(mid_vars_list))
                        model.cbLazy(lhs >= 1)

        self._model.setParam(GRB.Param.LazyConstraints, 1)
        self._model.setParam(GRB.Param.PoolSearchMode, 2)
        self._model.setParam(GRB.Param.PoolSolutions, 2000000000)
        self._model.setObjective(0.0, GRB.MAXIMIZE)
        self._model.optimize(mid_state_callback)

        if verbosity:
            print(f"Middle state enumeration complete. Found {len(feasible_states)} feasible states.")
            sys.stdout.flush()
        return feasible_states

    def _get_input_masks(self, active_model, wrapper_model, sub_cipher):
        if not self._verify_pool_completeness("divide-and-conquer enumeration", model=active_model):
            raise RuntimeError(
                "Divide-and-conquer pool enumeration is incomplete (suboptimal status or pool "
                "cap reached); the parity-based coefficient would be unreliable."
            )
        inputs = []
        for inp_name in sub_cipher.inputs:
            if not inp_name.startswith("intermediate_output") and inp_name in wrapper_model._variables:
                for idx in sorted(wrapper_model._variables[inp_name].keys()):
                    orig_var = wrapper_model._variables[inp_name][idx]["original"]
                    copy_var = active_model.getVarByName(orig_var.VarName)
                    inputs.append(copy_var)

        masks_parity = {}
        for sn in range(active_model.SolCount):
            active_model.setParam(GRB.Param.SolutionNumber, sn)
            mask = sum((1 << i) for i, var in enumerate(inputs) if var is not None and var.Xn > 0.5)
            masks_parity[mask] = masks_parity.get(mask, 0) ^ 1

        return {m: p for m, p in masks_parity.items() if p == 1}

    def _build_bit_map(self, sub_cipher, wrapper_model, ring_var_map):
        mapping, bit_pos = {}, 0
        for inp_name in sub_cipher.inputs:
            if not inp_name.startswith("intermediate_output") and inp_name in wrapper_model._variables:
                for b in sorted(wrapper_model._variables[inp_name].keys()):
                    global_name = f"{inp_name}[{b}]"
                    if global_name in ring_var_map:
                        mapping[bit_pos] = ring_var_map[global_name]
                    bit_pos += 1
        return mapping

    def _add_left_model_constraints(self, model_wrap, inp_name, size, cube_set):
        if inp_name not in model_wrap._variables:
            return
        for i in range(size):
            if i in model_wrap._variables[inp_name]:
                v = model_wrap._variables[inp_name][i]["original"]
                if v is not None:
                    val = 1 if (inp_name, i) in cube_set else 0
                    model_wrap._model.addConstr(v == val)

    def _prepare_left_model(self, model_wrap, cipher, cube):
        model_wrap.build_model_with_input_output_constraints(None, do_pruning=True)
        cube_locs = model_wrap.var_list_to_input_positions(cube)
        cube_set = {(p[0], p[1]) for p in cube_locs}

        for inp_name, size in zip(cipher.inputs, cipher.inputs_bit_size):
            if "key" not in inp_name.lower():
                self._add_left_model_constraints(model_wrap, inp_name, size, cube_set)

    def _get_model_key_vars(self, model_wrap, cipher):
        keys = []
        for inp_name, size in zip(cipher.inputs, cipher.inputs_bit_size):
            if "key" in inp_name.lower() and inp_name in model_wrap._variables:
                for i in range(size):
                    v = model_wrap._variables[inp_name].get(i, {}).get("original")
                    if v is not None:
                        keys.append(v)
        return keys

    def _prepare_model_for_counting(self, model_wrap, cipher, is_model1, cube, output_bit_index):
        if is_model1:
            self._prepare_left_model(model_wrap, cipher, cube)
        else:
            model_wrap.build_generic_model_for_specific_output_bit(output_bit_index, do_pruning=True)

        model_wrap._model.update()
        keys_m = self._get_model_key_vars(model_wrap, cipher)
        if keys_m:
            model_wrap._model.setObjective(sum(keys_m), GRB.MAXIMIZE)
        model_wrap._model.update()

    def _apply_state_to_outputs(self, m_core, state):
        for i, val in enumerate(state):
            v_copy = m_core.getVarByName(f"output[{i}]")
            if v_copy is not None:
                m_core.addConstr(v_copy == val)

    def _apply_state_to_inputs(self, m_core, model_wrap, state):
        inp_name = model_wrap._cipher.inputs[0]
        if inp_name not in model_wrap._variables:
            return
        for i, val in enumerate(state):
            if i in model_wrap._variables[inp_name]:
                v_orig = model_wrap._variables[inp_name][i]["original"]
                if v_orig is not None:
                    v_copy = m_core.getVarByName(v_orig.VarName)
                    if v_copy is not None:
                        m_core.addConstr(v_copy == val)

    def _setup_core_model(self, model_wrap, state, apply_to_inputs=False):
        m_core = model_wrap._model.copy()
        m_core.setParam(GRB.Param.PoolSearchMode, 2)
        m_core.setParam(GRB.Param.PoolSolutions, 2000000000)
        m_core.setParam(GRB.Param.OutputFlag, 0)
        m_core.setParam(GRB.Param.MIPFocus, 3)

        if not apply_to_inputs:
            self._apply_state_to_outputs(m_core, state)
        else:
            self._apply_state_to_inputs(m_core, model_wrap, state)
        return m_core

    def _compute_monomial(self, m1, m2, map1, map2, boolean_ring, k_vars):
        mon = boolean_ring(1)
        for sub_bit, ring_idx in map1.items():
            if (m1 >> sub_bit) & 1:
                mon *= k_vars[ring_idx]
        for sub_bit, ring_idx in map2.items():
            if (m2 >> sub_bit) & 1:
                mon *= k_vars[ring_idx]
        return mon

    def _accumulate_poly(
        self, c1, masks1, c2, masks2, map1, map2, total_poly, total_raw, has_key, boolean_ring, k_vars
    ):
        total_raw += c1 * c2
        if not has_key:
            total_poly += boolean_ring(c1 * c2)
            return total_poly, total_raw

        for m1 in masks1:
            for m2 in masks2:
                total_poly += self._compute_monomial(m1, m2, map1, map2, boolean_ring, k_vars)
        return total_poly, total_raw

    def _process_single_feasible_state(
        self, state, model1, cipher1, model2, cipher2, map1, map2, has_key, boolean_ring, k_vars
    ):
        m1_core = self._setup_core_model(model1, state, apply_to_inputs=False)
        m1_core.optimize()
        c1 = m1_core.SolCount

        if c1 == 0:
            m1_core.dispose()
            return boolean_ring(0), 0, c1

        masks1 = self._get_input_masks(m1_core, model1, cipher1)

        m2_core = self._setup_core_model(model2, state, apply_to_inputs=True)
        m2_core.optimize()
        c2 = m2_core.SolCount

        if c2 == 0:
            m1_core.dispose()
            m2_core.dispose()
            return boolean_ring(0), 0, c1 * c2

        masks2 = self._get_input_masks(m2_core, model2, cipher2)

        poly_delta, raw = self._accumulate_poly(
            c1, masks1, c2, masks2, map1, map2, boolean_ring(0), 0, has_key, boolean_ring, k_vars
        )
        m1_core.dispose()
        m2_core.dispose()
        return poly_delta, raw, c1 * c2

    def find_coefficient_of_cube_by_divide_and_conquer(
        self, output_bit_index, middle_round, cube, chosen_cipher_output=None, verbosity=False
    ):
        """
        Compute the superpoly (coefficient of the cube monomial) in terms of key variables.
        """
        key_input_indices, has_key, B, k_vars = self._setup_key_variables_and_ring()
        cipher1, cipher2 = self._get_split_ciphers(middle_round, verbosity)

        from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import MilpMonomialPredictionModel

        model1 = MilpMonomialPredictionModel(cipher1)
        model2 = MilpMonomialPredictionModel(cipher2)

        round_output_comp = self._get_round_output_comp(middle_round)
        skip_for_enum = self._get_skip_for_enum()

        self.build_generic_model_for_specific_output_bit(
            output_bit_index, None, None, chosen_cipher_output, skip_components=skip_for_enum
        )
        self._constrain_cube_and_public_vars(cube, key_input_indices)

        mid_vars_list = self._identify_mid_vars_list(round_output_comp, skip_for_enum, middle_round)
        feasible_states = self._enumerate_feasible_states(mid_vars_list, verbosity)

        ring_var_map = {}
        curr_ring_idx = 0
        for i in key_input_indices:
            inp_name, size = self._cipher.inputs[i], self._cipher.inputs_bit_size[i]
            for b in range(size):
                ring_var_map[f"{inp_name}[{b}]"] = curr_ring_idx
                curr_ring_idx += 1

        self._prepare_model_for_counting(model1, cipher1, True, cube, output_bit_index)
        self._prepare_model_for_counting(model2, cipher2, False, cube, output_bit_index)

        map1 = self._build_bit_map(cipher1, model1, ring_var_map)
        map2 = self._build_bit_map(cipher2, model2, ring_var_map)

        total_poly, parity, total_raw_solutions = B(0), 0, 0

        for idx, state in enumerate(feasible_states):
            if verbosity and (idx == 0 or (idx + 1) % 10 == 0 or (idx + 1) == len(feasible_states)):
                print(f"Processing state {idx + 1}/{len(feasible_states)}...")
                sys.stdout.flush()

            poly_delta, raw, prod = self._process_single_feasible_state(
                state, model1, cipher1, model2, cipher2, map1, map2, has_key, B, k_vars
            )
            total_poly += poly_delta
            total_raw_solutions += raw
            parity += prod

        if verbosity:
            print(f"Final Parity: {parity % 2}")
            print(f"Total counted solutions (with multiplicity): {total_raw_solutions}")

        return total_poly


################################
######## END OF CLASS ##########
################################


def _valuation_from_assign(cipher, full_assign_bits, allowed_prefixes=None):
    val = {}
    for name, size in zip(cipher.inputs, cipher.inputs_bit_size):
        pref = name[0]
        if allowed_prefixes is not None and pref not in allowed_prefixes:
            continue
        w = full_assign_bits[name]
        for i in range(size):  # i is MSB index
            bit = (w >> (size - 1 - i)) & 1
            val[f"{pref}{i}"] = bit
    return val


def _parse_cube_positions(cipher, cube_tokens):
    pref_map = {name[0]: (name, size) for name, size in zip(cipher.inputs, cipher.inputs_bit_size)}
    out = []
    for tok in cube_tokens:
        pref, msb_pos = tok[0], int(tok[1:])
        name, size = pref_map[pref]
        if msb_pos < 0 or msb_pos >= size:
            raise ValueError(f"{tok} out of range for input {name} (size {size})")
        out.append((name, msb_pos))
    return out


def _eval_boolean_poly(poly, valuation):
    vars_in_poly = [str(v) for v in poly.variables()]
    if not vars_in_poly:
        return int(GF(2)(poly))
    vals = {name: valuation.get(name, 0) for name in vars_in_poly}
    return int(GF(2)(poly(**vals)))


def _build_trial_assignment(cipher, needed_prefixes, public_assign_bits):
    """Build one input assignment for a correctness trial: random key bits and
    fixed/zero public bits. Extracted from
    ``check_correctness_of_partial_anf_or_superpoly``; logic unchanged.
    """
    assign = {}
    for name, size in zip(cipher.inputs, cipher.inputs_bit_size):
        if name.startswith("k"):
            assign[name] = secrets.randbits(size)
        elif needed_prefixes <= {"k"}:
            assign[name] = 0
        elif public_assign_bits and name in public_assign_bits:
            assign[name] = int(public_assign_bits[name])
        else:
            assign[name] = 0
    return assign


def _cube_sum_parity(cipher, assign, cube_pos, size_map, output_bit_index):
    """Cube-sum the chosen output bit over all ``2**len(cube_pos)`` settings of the
    cube variables, keeping the rest of ``assign`` fixed. Returns the parity (0/1).
    """
    acc = 0
    for a in range(1 << len(cube_pos)):
        cur = dict(assign)
        for j, (inp_name, msb_pos) in enumerate(cube_pos):
            size = size_map[inp_name]
            lsb_idx = size - 1 - msb_pos  # MSB is first
            mask = 1 << lsb_idx
            if (a >> j) & 1:
                cur[inp_name] |= mask
            else:
                cur[inp_name] &= ~mask

        output = cipher.evaluate([cur[name] for name in cipher.inputs])
        out_lsb_idx = cipher.output_bit_size - 1 - output_bit_index
        acc ^= (output >> out_lsb_idx) & 1
    return acc


def check_correctness_of_partial_anf_or_superpoly(
    cipher, output_bit_index, cube, poly, public_assign_bits=None, trials=16
):
    """
    Check the correctness of a computed cube monomial coefficient or superpoly
    for a specific cipher output bit, by evaluating the cipher multiple times
    with random key and public variable assignments.

    The method performs the full cube summation over the selected cube bits and
    compares the resulting bit parity with the evaluation of the provided Boolean
    polynomial (`poly`) under the same key assignment. A match across all trials
    confirms the correctness of the derived superpoly or key coefficient.

    INPUT:

    - ``cipher`` -- **Cipher object**
      The CLAASP cipher instance implementing the `evaluate()` method.

    - ``output_bit_index`` -- **integer**
      Index (0-based, counting from the most significant bit).

    - ``cube`` -- **list of strings**
      List of cube variable names (e.g. ``["p1", "p3"]`` or ``["i9", "i19", ...]``)
      that define the cube monomial being analyzed.

    - ``poly`` -- **Sage BooleanPolynomial**
      The candidate Boolean polynomial representing either the key coefficient
      or the superpoly predicted by the MILP model.

    - ``public_assign_bits`` -- **dict** (default: ``None``)
      Optional mapping specifying fixed assignments for public variables (e.g. plaintext or IV).
      If omitted, all non-cube public variables default to zero.
      Example: ``{"plaintext": 0xfda120472589641}`` or ``{"initialization_vector": (1 << 80) - 1}``.

    - ``trials`` -- **integer** (default: ``16``)
      Number of random key assignments to test. Each trial independently verifies the
      cube summation equivalence under new random key values.

    OUTPUT:

    - **boolean**
      ``True`` if the cube-summation result matches the polynomial evaluation for all trials,
      otherwise ``False``.

    Example::
        sage: from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher
        sage: cipher = TriviumStreamCipher(keystream_bit_len=1, number_of_initialization_clocks= 200)
        sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import *
        sage: milp = MilpMonomialPredictionModel(cipher) # doctest: +SKIP
        sage: cube = ["i53"]
        sage: coef_poly = milp.find_superpoly_of_specific_output_bit(0, cube) # doctest: +SKIP
        sage: check_correctness_of_partial_anf_or_superpoly(cipher, 0, cube, coef_poly) # doctest: +SKIP
        ...

        sage: from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher
        sage: cipher = TriviumStreamCipher(keystream_bit_len=1, number_of_initialization_clocks= 590)
        sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import *
        sage: milp = MilpMonomialPredictionModel(cipher) # doctest: +SKIP
        sage: cube = ['i9', 'i19', 'i29', 'i39', 'i49', 'i59', 'i69', 'i79']
        sage: superpoly = milp.find_superpoly_of_specific_output_bit(0, cube) # doctest: +SKIP
        sage: check_correctness_of_partial_anf_or_superpoly(cipher, 0, cube, superpoly) # doctest: +SKIP
        ...

        # by defult non-cube public variables assign to zero but that can be assigned
        # to any arbitrary constant values, for example see below
        # From the following dictionary 'pub' all non-cube public vars will be set to constant 1.

        sage: pub = {"initialization_vector": (1 << 80) - 1} # Every non cube vars set to 1.
        sage: check_correctness_of_partial_anf_or_superpoly(cipher, 0, cube, superpoly, public_assign_bits= pub) # doctest: +SKIP
        ...

        #  A short example
        sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
        sage: cipher = PresentBlockCipher(number_of_rounds=1)
        sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import *
        sage: milp = MilpMonomialPredictionModel(cipher) # doctest: +SKIP
        sage: cube = ['p2', 'p3']
        sage: superpoly = milp.find_superpoly_of_specific_output_bit(0, cube) # doctest: +SKIP
        sage: check_correctness_of_partial_anf_or_superpoly(cipher, 0, cube, superpoly) # doctest: +SKIP
        ...
        sage: pub = {"plaintext": 0xfda120472589641} # Set to 1 or 0 the plaintext vars according to the given pattern.
        sage: check_correctness_of_partial_anf_or_superpoly(cipher, 0, cube, superpoly, public_assign_bits= pub) # doctest: +SKIP
        ...

    """
    cube_pos = _parse_cube_positions(cipher, cube)
    size_map = dict(zip(cipher.inputs, cipher.inputs_bit_size))
    needed_prefixes = {str(v)[0] for v in poly.variables()}

    for _ in range(trials):
        assign = _build_trial_assignment(cipher, needed_prefixes, public_assign_bits)
        acc = _cube_sum_parity(cipher, assign, cube_pos, size_map, output_bit_index)

        vals = _valuation_from_assign(cipher, assign, allowed_prefixes=needed_prefixes)
        rhs = _eval_boolean_poly(poly, vals)

        if acc != rhs:
            return False
    return True
