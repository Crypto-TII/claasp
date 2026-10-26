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

from gurobipy import GRB

from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import MilpMonomialPredictionModel


class MilpTwoSubsetDivisionPropertyModel(MilpMonomialPredictionModel):
    """
    Two-subset bit-based division property (2SDP) model.

    Subclass of :class:`MilpMonomialPredictionModel` differing only in the two
    propagation rules where the two-subset property parts from the exact
    monomial-prediction model: the weight-preserving COPY (:meth:`create_all_copies`,
    :meth:`create_copies_for_linear_layer`) and the 2SDP S-box trail table
    (:meth:`get_valid_monomial_exponents_table`, which the parent's S-box encoders of
    :meth:`add_sbox_constraints` then encode), plus the XOR with a constant, which is
    transparent here (:meth:`_add_xor_bit_constraint`). The other linear components (ROTATE,
    SHIFT, permutation, constant, output) and the driver are inherited unchanged.

    An INFEASIBLE model proves the output bit balanced (an integral distinguisher).
    It is sound but coarser than the exact model (it certifies only a subset of its
    distinguishers), in exchange for a much cheaper, faster model. Being invariant
    under key addition, the round keys may be dropped and a keyless verdict still
    holds for every key (unsound for the exact model).

    The constructor's ``sbox_encoding`` flag picks the small-S-box encoder:
    ``"onehot"`` (default), ``"convexhull"``, or ``"espresso"`` (S-boxes over 5 bits
    always use Espresso). The flag applies to S-boxes only: the modular addition is encoded
    by the two inequalities that are the convex hull of its full-adder slice, which is
    already exact, so it has no encoding choice.
    Besides the SPN-style components, the bitwise AND and OR
    (:meth:`add_and_constraints`, :meth:`add_or_constraints`), the modular addition
    (:meth:`add_modadd_constraints`) and ``NOT`` (:meth:`add_not_constraints`, transparent)
    have their two-subset rules, and constants are transparent
    (:meth:`add_constant_constraints`); the components without a 2SDP rule yet
    (MODMUL, FSR) raise :class:`NotImplementedError` until an override is added.
    Requires a Gurobi license.
    """

    # Two trail-table caches, deliberately at different scopes. The full-adder table depends
    # on nothing but the full-adder ANF, so it is shared by every instance and derived once per
    # process; deriving it builds a PolyBoRi ring, which is what we want to keep out of the
    # per-model path. The S-box table varies with the S-box, so it is cached per instance and
    # keyed by the component description (``_sbox_2sdp_cache`` below).

    def __init__(self, cipher, sbox_encoding="onehot"):
        super().__init__(cipher, sbox_encoding)
        self._sbox_2sdp_cache = {}

    def create_all_copies(self):
        """Weight-preserving COPY for per-wire fan-out: ``sum(copies) == original``."""
        for name in list(self._variables.keys())[:-1]:
            for bit_position in self._variables[name].keys():
                copies = self._variables[name][bit_position]["copies"]
                original_var = self._variables[name][bit_position]["original"]

                if copies:
                    # redundant given the equality below, but tightens presolve (faster convex-hull)
                    for i in range(len(copies)):
                        self._model.addConstr(original_var >= copies[i])
                    self._model.addConstr(sum(copies[i] for i in range(len(copies))) == original_var)
                self._model.update()

    def create_copies_for_linear_layer(self, binary_matrix, input_vars_concat):
        """Weight-preserving COPY inside the linear layer: ``sum(copies) == var``."""
        copies = {}
        for index, var in enumerate(input_vars_concat):
            column = [row[index] for row in binary_matrix]
            number_of_1s = list(column).count(1)
            current = 1 if number_of_1s > 1 else 0
            copies[index] = {}
            copies[index][0] = var
            copies[index]["current"] = current
            self.set_as_used_variables([var])
            new_vars = self._model.addVars(list(range(number_of_1s)), vtype=GRB.BINARY, name="copy_" + var.VarName)
            self._model.update()
            # redundant given the equality below
            for i in range(number_of_1s):
                self._model.addConstr(var >= new_vars[i])
            self._model.addConstr(sum(new_vars[i] for i in range(number_of_1s)) == var)
            self._model.update()
            for i in range(1, number_of_1s + 1):
                copies[index][i] = new_vars[i - 1]
        return copies

    def _add_xor_bit_constraint(self, output_var, vars_sum, const_val):
        """Two-subset XOR: ``b == sum(a_i)``; a constant operand is transparent, whatever its value."""
        self._model.addConstr(output_var == vars_sum)

    def get_valid_monomial_exponents_table(self, component):
        r"""
        Todo's two-subset division-trail table of the S-box.

        Coarsens the parent's exact monomial table (obtained via ``super()``): a
        trail ``u -> v`` is valid iff some monomial ``x^w`` of ``g_v = prod_{q:
        v_q=1} S_q`` has ``w >= u`` (bitwise superset), and for each ``u`` only the
        ``<=``-minimal ``v`` are kept (SizeReduce). Returned in the parent's
        ``(table, n, m)`` shape, so both S-box encoders build their point set from
        it unchanged. For the uBlock S-box this yields 42 trails.
        """
        desc = tuple(component.description)
        if desc in self._sbox_2sdp_cache:
            return self._sbox_2sdp_cache[desc]

        # parent's exact table: w_of_v[v] = {w : x^w is a monomial of g_v}
        w_of_v, n, m = super().get_valid_monomial_exponents_table(component)

        def reachable(u):
            # v reachable from u iff some monomial x^w of g_v has w >= u
            return [v for v in range(1 << m) if any((w & u) == u for w in w_of_v[v])]

        def size_reduce(vs):
            # keep only minimal v (drop v that dominate some other reachable v')
            return [v for v in vs if not any(v2 != v and (v2 & v) == v2 for v2 in vs)]

        table = {v: set() for v in range(1 << m)}
        for u in range(1 << n):
            for v in size_reduce(reachable(u)):
                table[v].add(u)

        self._sbox_2sdp_cache[desc] = (table, n, m)
        return self._sbox_2sdp_cache[desc]

    def add_sbox_constraints_anf_circuit(self, component):
        """Refuse the exact ANF-circuit S-box: unsound mixed with the 2SDP weight-preserving COPY."""
        raise NotImplementedError(
            "2SDP does not use the exact ANF-circuit S-box model. Large S-boxes are handled"
            "by the Espresso encoding of the 2SDP trail table; ensure the 'espresso' binary is installed, "
            "or use the exact MilpMonomialPredictionModel."
        )

    def _unsupported(self, name):
        raise NotImplementedError(
            f"The two-subset division property model currently supports SPN-style components "
            f"(S-box, linear layer / bit-permutation, XOR, ROTATE, SHIFT, NOT, constant, output), AND, OR and MODADD. "
            f"Component '{name}' has a two-subset rule that is not yet implemented; use the exact "
            f"MilpMonomialPredictionModel, or add the corresponding 2SDP override to this class."
        )

    def add_and_constraints(self, component):
        r"""
        Two-subset division trail of the bitwise AND (Xiang et al., ASIACRYPT 2016, model (2),
        from their Prop. 2 ``k = max{k_0, k_1}``): for ``y = x_0 & ... & x_{k-1}`` with input
        exponents ``a_i`` and output exponent ``b``,

        ``b >= a_i`` for every ``i`` and ``b <= a_0 + ... + a_{k-1}``,

        i.e. the trails ``(0,...,0) -> 0`` and ``a -> 1`` for every nonzero ``a``. For two
        operands these are the four trails the paper lists after model (2).
        """
        self._add_max_rule_constraints(component, padded_output=True)

    def add_or_constraints(self, component):
        r"""
        Two-subset division trail of the bitwise OR. The ANF ``x_0 | x_1 = x_0 + x_1 + x_0 x_1``
        (and its ``k``-input analogue) contains the full product, so Todo's rule gives the same
        trails as the AND: ``b >= a_i`` for every ``i`` and ``b <= a_0 + ... + a_{k-1}``.
        """
        self._add_max_rule_constraints(component, padded_output=False)

    def _add_max_rule_constraints(self, component, padded_output):
        """
        ``b >= a_i``, ``b <= sum(a_i)`` per output bit, the operands being the ``k`` consecutive
        blocks of the concatenated input. AND outputs are padded (indexed by position), OR outputs
        are not (indexed in the order of the sorted used positions).
        """
        output_vars = self.get_output_vars(component)
        input_vars_concat = self.get_input_vars(component)
        self._model.update()

        number_of_operands = component.description[1]
        block_size = len(input_vars_concat) // number_of_operands
        for index, bit_pos in enumerate(sorted(self._occurences[component.id].keys())):
            output_var = output_vars[bit_pos] if padded_output else output_vars[index]
            operands = [input_vars_concat[bit_pos + t * block_size] for t in range(number_of_operands)]
            for operand in operands:
                self._model.addConstr(output_var >= operand)
            self._model.addConstr(output_var <= sum(operands))
            self.set_as_used_variables(operands + [output_var])
        self._model.update()

    def add_not_constraints(self, component):
        r"""
        Two-subset rule for ``NOT``: transparent, ``b == a`` bit by bit.

        ``NOT x = x + 1`` is an XOR with the constant 1, and the two-subset division property
        is invariant under that (Sun et al., ePrint 2016/1101). Todo's rule leaves two trails,
        ``0 -> 0`` and ``1 -> 1``: from ``a = 0`` the constant monomial also reaches ``b = 1``,
        but SizeReduce keeps the minimal ``b = 0``.
        """
        output_vars = self.get_output_vars(component)
        input_vars_concat = self.get_input_vars(component)
        self._model.update()

        for index, bit_pos in enumerate(sorted(self._occurences[component.id].keys())):
            self._model.addConstr(output_vars[index] == input_vars_concat[bit_pos])
            self.set_as_used_variables([input_vars_concat[bit_pos]])
        self._model.update()

    def _add_two_subset_adder(self, tag, a_bits, b_bits, z_bits):
        """
        Ripple-carry adder ``z = a + b mod 2^n`` on MSB-first variable lists. The carry into
        the least significant slice and out of the most significant one are both fixed to 0.
        """
        carry = self._model.addVar(vtype=GRB.BINARY, lb=0, ub=0, name=f"modadd_{tag}_carry_in")
        self._model.update()
        for i in reversed(range(len(z_bits))):                # i = n-1 is the least significant bit
            carry_out = self._model.addVar(
                vtype=GRB.BINARY, lb=0, ub=0 if i == 0 else 1, name=f"modadd_{tag}_carry_{i}"
            )
            self._model.update()
            x, y, c, s, c_out = a_bits[i], b_bits[i], carry, z_bits[i], carry_out
            # The two-subset rule (Xiang et al., ASIACRYPT 2016, Algorithm 2) on the full adder
            # s = x+y+c, c' = xy+xc+yc gives 11 trails, and their convex hull is this pair.
            self._model.addConstr(s + 2 * c_out >= x + y + c)        
            self._model.addConstr(2 * (s + c_out) <= 1 + x + y + c) 
            carry = carry_out
        self._model.update()

    def add_modadd_constraints(self, component):
        r"""
        Two-subset model of ``z = x_0 + x_1 + ... + x_{k-1} mod 2^n``: a ripple-carry chain of
        full-adder slices (:meth:`_add_two_subset_adder`), with more than two operands added
        one after the other through intermediate sums. Operands are the ``k`` consecutive
        ``n``-bit blocks of the concatenated input, most significant bit first, like the output.

        For ``k == 2`` the chain reproduces Todo's rule applied to the whole addition exactly,
        checked for ``n = 2..7``. For ``k >= 3`` the pairwise chaining is only a conservative
        over-approximation: ``(x_0 + x_1) + x_2`` on three 3-bit operands admits 46 trails
        where the rule gives 45. Verdicts stay sound, a balanced bit is still balanced, but a
        distinguisher may be missed.
        """
        output_vars = self.get_output_vars(component)
        input_vars_concat = self.get_input_vars(component)
        self._model.update()

        n = component.output_bit_size
        k = component.description[1]
        if len(input_vars_concat) != k * n:
            raise ValueError(f"add_modadd_constraints: {component.id} has {len(input_vars_concat)} input bits for {k} operands of {n} bits")
        operands = [input_vars_concat[t * n : (t + 1) * n] for t in range(k)]

        acc = operands[0]
        for t in range(1, k):
            if t == k - 1:
                result = output_vars
            else:
                result = [
                    self._model.addVar(vtype=GRB.BINARY, name=f"modadd_{component.id}_sum{t}_{i}") for i in range(n)
                ]
                self._model.update()
            self._add_two_subset_adder(f"{component.id}_{t}", acc, operands[t], result)
            acc = result

        self.set_as_used_variables(input_vars_concat + list(output_vars))
        self._model.update()

    def add_constant_constraints(self, component):
        """
        Constants carry no weight in the two-subset property: every constant bit is fixed to
        0, which makes XOR, AND, OR and modular addition with a constant transparent (Sun et
        al., ePrint 2016/1101). The exact model instead leaves the 1-bits free, since
        ``x + 1`` has the monomial ``1``.
        """
        self._constants[component.id] = {}
        output_vars = self.get_output_vars(component)
        for index, bit_pos in enumerate(sorted(self._occurences[component.id].keys())):
            self._model.addConstr(output_vars[index] == 0)
            self._constants[component.id][bit_pos] = 0
        self._model.update()

    def add_modmul_constraints(self, component):
        self._unsupported("MODMUL")

    def add_fsr_constraints(self, component):
        self._unsupported("FSR")

    def _keyless_submodel(self, keep_round_key_injection):
        """2SDP sub-model on the key-schedule-removed cipher, carrying the solver params and encoding."""
        if not keep_round_key_injection:
            self._check_round_keys_enter_by_xor()
        sub = type(self)(
            self._cipher.remove_key_schedule(keep_round_key_injection=keep_round_key_injection),
            sbox_encoding=self._sbox_encoding,
        )
        sub._gurobi_params = dict(self._gurobi_params)
        return sub

    def _check_round_keys_enter_by_xor(self):
        """
        Dropping the round keys is sound only where they are XORed in (invariance under XOR
        with a constant). ``remove_key_schedule(keep_round_key_injection=False)`` would also
        strip a key operand from a modular addition, AND or OR and rewire the rest as a plain
        wire, which is not a valid model; refuse, and point to the independent-round-key model.
        """
        with_round_keys = self._cipher.remove_key_schedule(keep_round_key_injection=True)
        for component in with_round_keys.all_components():
            takes_key = any(link == "key" or link.startswith("key_") for link in component.input_id_links)
            is_xor = component.type == "word_operation" and component.description[0] == "XOR"
            if takes_key and not is_xor and component.type != "intermediate_output":
                raise ValueError(
                    f"round keys enter component {component.id} ({component.description[0] if component.type == 'word_operation' else component.type}) "
                    "other than by XOR, so the keyless model is not sound; use the independent-round-key "
                    "methods (keep_round_key_injection=True) instead."
                )

    def is_balanced_at_specific_output_bit_over_cube_with_independent_round_keys(
        self, output_bit_index, cube, chosen_cipher_output=None
    ):
        r"""
        Sound balance check with the key schedule removed but the round-key
        injections kept (2SDP sub-model). The trail set is a superset of the real
        cipher's, so an INFEASIBLE (balanced) result, returned as ``True``, still
        proves the real bit balanced for every key.

        INPUT:
        - ``output_bit_index`` -- **integer**
        - ``cube`` -- **list of strings**
        - ``chosen_cipher_output`` -- **string** (default: ``None``)

        OUTPUT:
        - **bool**; ``True`` if balanced (proven), ``False`` if not proved.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.ublock_block_cipher import UblockBlockCipher  # doctest: +SKIP
            sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.two_subset_division_property import MilpTwoSubsetDivisionPropertyModel  # doctest: +SKIP
            sage: cipher = UblockBlockCipher(number_of_rounds=7)  # doctest: +SKIP
            sage: milp = MilpTwoSubsetDivisionPropertyModel(cipher)  # doctest: +SKIP
            sage: cube = [f"p{i}" for i in range(128) if i not in {0, 1, 2, 3}]  # doctest: +SKIP
            sage: milp.is_balanced_at_specific_output_bit_over_cube_with_independent_round_keys(0, cube)  # doctest: +SKIP
            True
        """
        sub = self._keyless_submodel(keep_round_key_injection=True)
        return sub.is_balanced_at_specific_output_bit_over_cube(output_bit_index, cube, chosen_cipher_output)

    def is_cube_monomial_feasible_at_specific_output_bit_over_cube_keyless(
        self, output_bit_index, cube, chosen_cipher_output=None
    ):
        r"""
        Reachability on the fully keyless cipher (key schedule **and** round-key
        injection removed), using a 2SDP sub-model.

        For the 2SDP this is *sound*, not just a pre-filter: the two-subset
        division property is invariant under XOR with a constant, so a verdict
        proved keyless holds for every round key. A ``False`` result therefore
        proves the output bit balanced for all keys. 
        :meth:`is_balanced_at_specific_output_bit_over_cube_with_independent_round_keys`.)

        INPUT:
        - ``output_bit_index`` -- **integer**
        - ``cube`` -- **list of strings**
        - ``chosen_cipher_output`` -- **string** (default: ``None``)

        OUTPUT:

        - **bool**; ``True`` if the cube monomial can reach the bit (feasible, not
          balanced), ``False`` if it cannot (balanced, proven for all keys).

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.ublock_block_cipher import UblockBlockCipher  # doctest: +SKIP
            sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.two_subset_division_property import MilpTwoSubsetDivisionPropertyModel  # doctest: +SKIP
            sage: cipher = UblockBlockCipher(number_of_rounds=6)  # doctest: +SKIP
            sage: milp = MilpTwoSubsetDivisionPropertyModel(cipher)  # doctest: +SKIP
            sage: cube = [f"p{i}" for i in range(36, 64)] + [f"p{i}" for i in range(100, 128)]  # doctest: +SKIP
            sage: milp.is_cube_monomial_feasible_at_specific_output_bit_over_cube_keyless(1, cube)  # doctest: +SKIP
            True
        """
        sub = self._keyless_submodel(keep_round_key_injection=False)
        return not sub.is_balanced_at_specific_output_bit_over_cube(output_bit_index, cube, chosen_cipher_output)

    def is_balanced_over_cube_scan(
        self, output_bit_indices, cube, chosen_cipher_output=None, independent_round_keys=False
    ):
        r"""
        Balancedness of several output bits over the *same* cube, building the MILP once.

        The build is the dominant cost, so it is paid once for the whole list: the
        target constraint the build adds is removed, the shared cube is fixed once, and each
        bit ``j`` is tested by toggling ``output[j] == 1`` and re-optimising. Results
        match :meth:`is_balanced_at_specific_output_bit_over_cube` per bit.

        INPUT:

        - ``output_bit_indices`` -- **list of integers**
        - ``cube`` -- **list of strings**
        - ``chosen_cipher_output`` -- **string** (default: ``None``)
        - ``independent_round_keys`` -- **bool** (default: ``False``); if ``True``, scan the
          key-schedule-removed cipher (cheaper to build, but the solve can be slower).

        OUTPUT:

        - **dict** ``{bit_index: bool}``; ``True`` iff that bit is provably balanced.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.ublock_block_cipher import UblockBlockCipher  # doctest: +SKIP
            sage: from claasp.cipher_modules.models.milp.milp_models.Gurobi.two_subset_division_property import MilpTwoSubsetDivisionPropertyModel  # doctest: +SKIP
            sage: cipher = UblockBlockCipher(number_of_rounds=8)  # doctest: +SKIP
            sage: milp = MilpTwoSubsetDivisionPropertyModel(cipher)  # doctest: +SKIP
            sage: cube = [f"p{i}" for i in range(128) if i not in {0, 1, 2, 3}]  # doctest: +SKIP
            sage: milp.is_balanced_over_cube_scan([0, 1, 2, 3], cube)  # doctest: +SKIP
            {0: True, 1: False, 2: True, 3: True}
        """
        if not output_bit_indices:
            return {}
        if independent_round_keys:
            sub = self._keyless_submodel(keep_round_key_injection=True)
            return sub.is_balanced_over_cube_scan(output_bit_indices, cube, chosen_cipher_output)

        # build once, without the target-fix (output[first] == 1), so the target can be toggled; shared cube fixed once
        self._build_balance_model(output_bit_indices[0], cube, chosen_cipher_output, any_output_bit=True)
        m = self._model

        results = {}
        for j in output_bit_indices:
            outj = m.getVarByName(f"output[{j}]")
            target = m.addConstr(outj == 1)
            m.update()
            m.optimize()
            results[j] = m.Status == GRB.INFEASIBLE
            m.remove(target)
            m.update()
        return results
