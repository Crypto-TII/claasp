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

import math
import time
from copy import deepcopy
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from operator import index
from types import SimpleNamespace

from minizinc import Instance, Model, Solver, Status

from claasp.cipher_modules.graph_normalization import binary_modadd_copy
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_approx_logarithm_predicate import (
    get_approx_logarithm_operation,
)
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_bct_predicates import (
    get_bct_operations,
)
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_boomerang_value_constraints import (
    build_boomerang_value_constraints,
)
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_ebct_predicates import (
    get_ebct_operations,
)
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_evaluation_bct_predicate import (
    get_evaluation_bct_operations,
)
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_evaluation_ebct_predicate import (
    get_evaluation_ebct_operations,
)
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_evaluation_lbct_predicate import (
    get_evaluation_lbct_operations,
)
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_evaluation_ubct_predicate import (
    get_evaluation_ubct_operations,
)
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_lbct_predicates import (
    get_lbct_operations,
)
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_sbox_switch_tables import (
    minizinc_sbox_switch_table,
)
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_ubct_predicates import (
    get_ubct_operations,
)
from claasp.cipher_modules.models.cp.mzn_model import MznModel
from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_model import (
    update_and_or_ddt_valid_probabilities,
)
from claasp.cipher_modules.models.cp.solvers import GECODE, SOLVER_DEFAULT
from claasp.cipher_modules.models.utils import convert_solver_solution_to_dictionary
from claasp.name_mappings import CONSTANT, INPUT_PLAINTEXT, SBOX, WORD_OPERATION

_UPPER = "upper"
_LOWER = "lower"
_UPPER_PREFIX = _UPPER + "_"
_LOWER_PREFIX = _LOWER + "_"
_MODEL_TYPE = "boomerang"
_MODULAR_OPERATIONS = ("MODADD", "MODSUB")
_UPPER_WEIGHT_LABEL = "Upper weight"
_MIDDLE_WEIGHT_LABEL = "Middle weight"
_LOWER_WEIGHT_LABEL = "Lower weight"
_TRAIL_WEIGHT_LABEL = "Trail weight"

_SWITCH_PREDICATES = {
    "bct": (get_bct_operations, get_evaluation_bct_operations),
    "ubct": (get_ubct_operations, get_evaluation_ubct_operations),
    "lbct": (get_lbct_operations, get_evaluation_lbct_operations),
    "ebct": (get_ebct_operations, get_evaluation_ebct_operations),
}


def _probability_from_weight(weight):
    """Convert a bit weight without representing float underflow as zero."""
    return 2 ** -weight if math.isfinite(weight) and weight <= 1074 else None


def _boomerang_probability_factors(weights, middle_model):
    factors = {
        "p": _probability_from_weight(weights[_UPPER_WEIGHT_LABEL]),
        "q": _probability_from_weight(weights[_LOWER_WEIGHT_LABEL]),
        "r": None,
        "p_squared_q_squared_r": None,
        "log2_p_squared_q_squared_r": None,
        "kind": "middle_probability_unavailable",
    }
    if middle_model == "local":
        factors["r"] = _probability_from_weight(weights[_MIDDLE_WEIGHT_LABEL])
        factors["p_squared_q_squared_r"] = _probability_from_weight(
            weights[_TRAIL_WEIGHT_LABEL]
        )
        factors["log2_p_squared_q_squared_r"] = -weights[_TRAIL_WEIGHT_LABEL]
        factors["kind"] = "local_characteristic_estimate"
        if None in (
            factors["p"], factors["q"], factors["r"],
            factors["p_squared_q_squared_r"],
        ):
            factors["reason"] = "below_float_range; use the bit weights"
    return factors


class MznHadipourBoomerangModel(MznModel):
    """Search single-key boomerang characteristics of ARX, AND, and S-box ciphers.

    The cipher is split into E0, Em, E1. Upper differences propagate through
    E0 and Em; lower differences are constrained by their output through E1 and Em.
    The upper and lower characteristics use forward component equations: fixing the lower output is
    equivalent to backward propagation, without constructing an inverse graph.
    BCT/UBCT/LBCT/EBCT constraints connect the two characteristics in Em.
    Exact-middle mode replaces local middle tables by four complete executions;
    its weight contains only the outer differential weights.
    Block-cipher key inputs have zero differences. For permutation models
    such as ChaCha, use ``fixed_values`` to fix the constant/key portion of
    the state when targeting a particular stream-cipher setting.

    A named plaintext input is placed first in an internal copy. This supports
    key-first descriptions such as CHAM without changing the supplied cipher.
    Exact-middle mode also supports two-input OR differential constraints, using the
    same DDT as AND. It also supports S-box differential constraints in the upper
    and lower characteristics.
    Their DDT weights use CLAASP's rounded centibit scale and rank retained
    characteristics; they are not full external probabilities. Local S-box
    switches use exact local BCT, UBCT, LBCT, and EBCT quartet counts for
    bijective S-boxes of at most eight bits. Their centibit weights estimate
    a characteristic under the same local independence assumptions as the
    other switch predicates.

    The local-middle objective is
    ``2 * upper_weight + middle_weight + 2 * lower_weight``.
    A solved candidate reports ``boomerang_probability_factors`` with
    ``p = 2^-upper_weight``, ``q = 2^-lower_weight``,
    ``r = 2^-middle_weight``, and ``p_squared_q_squared_r``. These are
    characteristic estimates, not a measured full-cipher probability.
    Exact-middle mode reports ``p`` and ``q`` but leaves ``r`` and the
    product as ``None``, because a quartet witness does not determine the
    middle connection probability. If a local estimate is too small for a
    Python float, its value is ``None``; the reported log2 product and bit
    weights retain its magnitude.
    It is a characteristic estimate under the usual independence assumptions,
    not the sum of all characteristics with the same external differences.
    Component ``weight`` entries are raw differential weights in each characteristic;
    the overlap is accounted for by ``middle_weight``, so summing component
    weights does not give the objective.
    Local-middle switch compatibility is imposed component by component. Valid boomerangs
    relying on cancellation between nonlinear terms combined by XOR may be
    excluded. Local table products also retain independence assumptions; they
    are not a proof of compatibility across the entire cipher.
    Modular connectivity restricts half-size transitions to half the word size,
    a search heuristic. The logarithm approximation saturates at 32 bits for
    probabilities at most 0.001021453702391378; its precision is not 0.01 bits.
    Modular-addition switch probabilities use the piecewise approximation in
    :func:`get_approx_logarithm_operation`; optimality refers to that model.

    References: Cid et al., *Boomerang Connectivity Table*, EUROCRYPT 2018,
    https://doi.org/10.1007/978-3-319-78375-8_22; Wang, Wang and Sun,
    *SAT-aided Automatic Search of Boomerang Distinguishers for ARX Ciphers*,
    ToSC 2023(1), https://doi.org/10.46586/tosc.v2023.i1.152-191; and
    Boukerrou et al., *On the Feistel Counterpart of the Boomerang Connectivity
    Table: Introduction and Analysis of the FBCT*, ToSC 2020(1),
    https://doi.org/10.13154/tosc.v2020.i1.331-362; and Yu and Teh,
    *Revisiting boomerang attacks on lightweight ARX and AND-RX ciphers with
    applications to KATAN, SIMON and CHAM*, JISA 89 (2025),
    https://doi.org/10.1016/j.jisa.2024.103950.

    INPUT:

    - ``cipher`` -- CLAASP cipher; local switches support two-input
      MODADD/MODSUB and AND, plus bijective S-boxes of up to eight input bits.
      Exact-middle mode also supports two-input OR constraints and middle
      components with exact CP encoders.
    - ``boomerang_structure`` -- dictionary containing nonnegative integer
      ``top_part_number_of_rounds``, positive ``middle_part_number_of_rounds``,
      and nonnegative ``bottom_part_number_of_rounds``. Their sum must equal
      ``cipher.number_of_rounds``. The upper and lower characteristics may have zero rounds.

    - ``enforce_value_compatibility`` -- bool (default: False). If True, add
      four exact forward executions sharing the actual master key and all other
      non-data inputs. SAT results include endpoint ``quartet_values`` that can
      be replayed with the original cipher, and ``value_compatibility`` equals
      ``'full_cipher'``. This certifies a retained quartet's existence, not its
      probability. It intersects the restricted local search space and can be
      substantially more expensive. The named plaintext is the data input;
      otherwise the first input is used as the state. Every original component
      must have an exact CP model. Fix actual
      input values through IDs such as ``quartet_0_key`` in ``fixed_values``.
      Other executions share the same non-data inputs automatically.
      Permutation key/constant words inside the first input must be fixed
      explicitly in each execution for a restricted oracle setting.
      All-solution enumeration is not supported in this mode: it would enumerate
      value witnesses instead of distinct difference trails.

    - ``middle_model`` -- ``'local'`` (default) retains componentwise switches.
      ``'exact'`` omits all middle difference propagation and local switch tables
      and enables four exact executions. This admits cancellation between middle
      components. Only the outer characteristics and external differences are
      retained. The objective is twice the sum of outer differential weights,
      an ordering heuristic, not a probability estimate. Results identify it as
      ``weight_type='outer_characteristic_weight'`` and set ``middle_weight=None``. Returned
      ``retained_difference_bits`` identifies physically anchored component bits;
      unretained auxiliary differences are omitted from ``components_values``.
      Fixing such auxiliary bits raises ValueError. Exact middle components need
      value encoders but do not need differential or connectivity encoders.

    - ``exclude_returning_quartets`` -- bool (default: False). If True, enable
      exact value compatibility and require ``X0 != X3``. Since both external
      differences are nonzero, all four plaintexts are then distinct. This
      excludes returning two-point quartets and certifies existence of a
      nondegenerate quartet, not its probability. Value-mode results record
      this option as ``exclude_returning_quartets``. Enumeration is unavailable
      with the value layer, including when enabled through this option.

    - ``fixed_parameters`` -- optional dictionary of actual non-data input
      values, for example ``{'key': 0}``. Names refer to the original graph.
      Values must fit their input widths; plaintext cannot be fixed here. This
      enables the exact value layer and holds these parameters equal to the
      specified values in all four executions. Difference constraints still
      describe XOR differences. A result for a chosen key does not establish
      an all-key or uniformly averaged probability.

    OUTPUT: a model. Construction does not change ``cipher`` or write files.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_hadipour_boomerang_model import MznHadipourBoomerangModel
        sage: structure = dict(top_part_number_of_rounds=1, middle_part_number_of_rounds=1, bottom_part_number_of_rounds=1)
        sage: model = MznHadipourBoomerangModel(SpeckBlockCipher(number_of_rounds=3), structure)
        sage: model.build_hadipour_boomerang_model(weight=4)
        sage: 'constraint weight = 400;' in model.model_constraints
        True
        sage: result = model.find_one_boomerang_trail(solver_name='gecode', timeout_in_seconds=3)  # optional - minizinc
        sage: exact = MznHadipourBoomerangModel(SpeckBlockCipher(number_of_rounds=3), structure, enforce_value_compatibility=True)
        sage: exact.build_hadipour_boomerang_model(weight=None)
        sage: 'quartet_0_key' in exact.assemble_model()
        True
        sage: joint = MznHadipourBoomerangModel(SpeckBlockCipher(number_of_rounds=3), structure, middle_model='exact')
        sage: joint.build_hadipour_boomerang_model(weight=None)
        sage: joint.enforce_value_compatibility
        True
        sage: proper = MznHadipourBoomerangModel(SpeckBlockCipher(number_of_rounds=3), structure, exclude_returning_quartets=True)
        sage: proper.enforce_value_compatibility, proper.exclude_returning_quartets
        (True, True)
        sage: fixed = MznHadipourBoomerangModel(SpeckBlockCipher(number_of_rounds=3), structure, middle_model='exact', fixed_parameters={'key': 0})
        sage: fixed.fixed_parameters
        {'key': 0}

    """

    def __init__(
        self,
        cipher,
        boomerang_structure,
        enforce_value_compatibility=False,
        middle_model="local",
        exclude_returning_quartets=False,
        fixed_parameters=None,
    ):
        if middle_model not in ("local", "exact"):
            raise ValueError("middle_model must be local or exact")
        self.middle_model = middle_model
        self.fixed_parameters = self._validate_fixed_parameters(cipher, fixed_parameters)
        self._value_difference_bits = {}
        if not isinstance(enforce_value_compatibility, bool):
            raise ValueError("enforce_value_compatibility must be a boolean")
        if not isinstance(exclude_returning_quartets, bool):
            raise ValueError("exclude_returning_quartets must be a boolean")
        self.exclude_returning_quartets = exclude_returning_quartets
        self.enforce_value_compatibility = (
            enforce_value_compatibility
            or middle_model == "exact"
            or exclude_returning_quartets
            or bool(self.fixed_parameters)
        )
        self._value_witness_names = []
        keys = (
            "top_part_number_of_rounds",
            "middle_part_number_of_rounds",
            "bottom_part_number_of_rounds",
        )
        if set(boomerang_structure) != set(keys):
            raise ValueError(
                "boomerang_structure must specify top, middle and bottom round counts"
            )
        try:
            counts = [index(boomerang_structure[key]) for key in keys]
        except TypeError as exc:
            raise ValueError("Round counts must be nonnegative integers") from exc
        if any(isinstance(boomerang_structure[key], bool) for key in keys) or any(
            n < 0 for n in counts
        ):
            raise ValueError("Round counts must be nonnegative integers")
        if counts[1] == 0 or sum(counts) != cipher.number_of_rounds:
            raise ValueError(
                "The middle must be nonempty and round counts must sum to the cipher rounds"
            )
        self.boomerang_structure = dict(zip(keys, counts))
        (
            self.top_part_number_of_rounds,
            self.middle_part_number_of_rounds,
            self.bottom_part_number_of_rounds,
        ) = counts
        self.original_cipher = self._data_first_copy(cipher)
        unified = self._unify_cipher(self.original_cipher)
        super().__init__(unified)
        self.c_upper = self.c_lower = 0
        self._middle_probabilities = {}

    def validate_boomerang_candidate(self, candidate, trials, **options):
        """Measure the full-cipher event selected by a boomerang trail.

        ``trials='exhaustive'`` is available for data inputs up to 16 bits;
        otherwise use a positive sample count. ``fixed_key`` is required for
        a keyed cipher. The result reports successes, trials, the empirical
        probability and the matched random-permutation baseline. This does
        not reinterpret the local trail weight as a measured probability.
        Sampled byte-aligned keyless permutations and keyed block ciphers use
        vectorized evaluation; small exhaustive checks use scalar evaluation.
        Supply ``inverse_cipher`` if CLAASP cannot construct a permutation's
        inverse automatically.
        """
        if candidate.get("model_type") != _MODEL_TYPE:
            raise ValueError("Expected a boomerang candidate")
        return self.validate_candidate(candidate, trials, **options)

    def validate_boomerang_characteristic(self, candidate, trials, **options):
        """Measure the external event and the candidate's four-path event.

        This checks every retained physical difference on both copies of
        its upper or lower path. ``trials='exhaustive'`` is exact for at most
        16 data bits; sampled results have 95% Wilson intervals. The
        need to measure joint path events follows Kidmose and Tiessen,
        *A Formal Analysis of Boomerang Probabilities*, ToSC 2022. See
        :func:`claasp.cipher_modules.models.candidate_validation.validate_boomerang_characteristic`
        for the event definition, citations, inputs, and output fields.

        EXAMPLES::

            sage: from claasp.cipher import Cipher
            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_hadipour_boomerang_model import (
            ....:     MznHadipourBoomerangModel)
            sage: toy = Cipher('tiny', 'permutation', ['plaintext'], [4], 4)
            sage: toy.add_round()
            sage: _ = toy.add_cipher_output_component(['plaintext'], [list(range(4))], 4)
            sage: split = dict(top_part_number_of_rounds=0,
            ....:              middle_part_number_of_rounds=1,
            ....:              bottom_part_number_of_rounds=0)
            sage: model = MznHadipourBoomerangModel(toy, split)
            sage: candidate = {'model_type': 'boomerang', 'components_values': {
            ....:     'upper_plaintext': {'value': '0x1'},
            ....:     'lower_cipher_output_0_0': {'value': '0x1'}}}
            sage: model.validate_boomerang_characteristic(candidate, 'exhaustive')['characteristic']['successes']
            16
        """
        from claasp.cipher_modules.models.candidate_validation import (
            validate_boomerang_characteristic,
        )

        return validate_boomerang_characteristic(
            self.original_cipher, candidate, trials, **options
        )

    @staticmethod
    def _validate_fixed_parameters(cipher, fixed_parameters):
        if fixed_parameters is None:
            return {}
        if not isinstance(fixed_parameters, dict):
            raise ValueError("fixed_parameters must map non-data input names to integers")
        data = INPUT_PLAINTEXT if INPUT_PLAINTEXT in cipher.inputs else cipher.inputs[0]
        widths = dict(zip(cipher.inputs, cipher.inputs_bit_size))
        result = {}
        for name, value in fixed_parameters.items():
            if name not in widths or name == data or isinstance(value, bool):
                raise ValueError("Only named non-data parameters can be fixed")
            try:
                value = index(value)
            except TypeError as exc:
                raise ValueError("Fixed parameters must be nonnegative width-sized integers") from exc
            if not 0 <= value < 1 << widths[name]:
                raise ValueError("Fixed parameter does not fit its input width")
            result[name] = value
        return result

    @staticmethod
    def _data_first_copy(cipher):
        result = binary_modadd_copy(cipher)
        if INPUT_PLAINTEXT in cipher.inputs:
            data_index = cipher.inputs.index(INPUT_PLAINTEXT)
            order = [data_index] + [
                i for i in range(len(cipher.inputs)) if i != data_index
            ]
            result.inputs[:] = [cipher.inputs[i] for i in order]
            result.inputs_bit_size[:] = [
                cipher.inputs_bit_size[i] for i in order
            ]
        return result

    def _unify_cipher(self, cipher):
        top = self.top_part_number_of_rounds
        middle = self.middle_part_number_of_rounds
        bottom = self.bottom_part_number_of_rounds
        upper = deepcopy(cipher).get_partial_cipher(
            0, top + middle - 1, keep_key_schedule=False
        )
        lower = deepcopy(cipher).get_partial_cipher(
            top, cipher.number_of_rounds - 1, keep_key_schedule=False
        )
        self._data_inputs = {
            _UPPER_PREFIX + upper.inputs[0],
            _LOWER_PREFIX + lower.inputs[0],
        }
        self._external_differences = {
            _UPPER_PREFIX + upper.inputs[0],
            _LOWER_PREFIX + lower.all_components_ids()[-1],
        }
        upper.add_prefix(_UPPER_PREFIX)
        lower.add_prefix(_LOWER_PREFIX)
        for round_number in range(top, cipher.number_of_rounds):
            upper.rounds.round_at(round_number).components.extend(
                lower.rounds.round_at(round_number).components
            )
        upper.inputs.extend(lower.inputs)
        upper.inputs_bit_size.extend(lower.inputs_bit_size)
        upper.upper_rounds, upper.middle_rounds, upper.lower_rounds = (
            top,
            middle,
            bottom,
        )
        upper.rounds._invalidate_indexes()
        return upper

    @staticmethod
    def _scaled_weight(weight):
        try:
            scaled = Decimal(str(weight)) * 100
        except InvalidOperation as exc:
            raise ValueError(
                "Weight must be a finite nonnegative multiple of 0.01"
            ) from exc
        if not scaled.is_finite() or scaled < 0 or scaled != scaled.to_integral_value():
            raise ValueError("Weight must be a finite nonnegative multiple of 0.01")
        return int(scaled)

    def _arm_differential_constraints(self, component):
        side = _UPPER if component.id.startswith(_UPPER_PREFIX) else _LOWER
        counter = "c_" + side
        characteristic_model = SimpleNamespace(
            c=getattr(self, counter),
            modadd_twoterms_mant=self.modadd_twoterms_mant,
            component_and_probability={},
            sbox_cache=self.sbox_cache,
        )
        declarations, constraints = (
            component.cp_xor_differential_propagation_constraints(characteristic_model)
        )
        self.component_and_probability.update(
            {
                name: [indices] if isinstance(indices, int) else indices
                for name, indices in characteristic_model.component_and_probability.items()
            }
        )
        setattr(self, counter, characteristic_model.c)
        # Replace only probability identifiers, preserving every component bit index.
        constraints = [
            line.replace("p[", side + "_p[").replace(
                "and2inputs_DDT", side + "_and2inputs_DDT"
            )
            for line in constraints
        ]
        return declarations, constraints

    def _differential_components(self):
        end = self.top_part_number_of_rounds + self.middle_part_number_of_rounds
        for number, round_ in enumerate(self._cipher.rounds_as_list):
            for component in round_.components:
                if (
                    self.middle_model == "local"
                    or number < self.top_part_number_of_rounds
                    or number >= end
                    or component.type == CONSTANT
                ):
                    yield component

    def _component_constraints(self, component):
        operation = component.description[0]
        if component.type == SBOX:
            if component.input_bit_size > 8:
                raise NotImplementedError(
                    "S-box differential tables support at most eight input bits"
                )
            return self._arm_differential_constraints(component)
        if operation == "OR" and self.middle_model != "exact":
            raise NotImplementedError("OR differential constraints require middle_model='exact'")
        if component.type == WORD_OPERATION and operation in (
            "OR",
            "MODADD",
            "MODSUB",
            "AND",
        ):
            if component.description[1] != 2:
                raise NotImplementedError(
                    "Boomerang nonlinear components must have two operands"
                )
            return self._arm_differential_constraints(component)
        method = getattr(component, "cp_xor_differential_propagation_constraints", None)
        if method is None:
            raise NotImplementedError(
                f"Unsupported boomerang component: {component.id}"
            )
        return method(self)

    def _build_components(self):
        for component in self._differential_components():
            declarations, constraints = self._component_constraints(component)
            self._variables_list.extend(declarations)
            self._model_constraints.extend(constraints)

    def _declare_bits_and_characteristic_weights(self):
        declarations = [
            f"array[0..{size - 1}] of var 0..1: {name};"
            for name, size in zip(self._cipher.inputs, self._cipher.inputs_bit_size)
        ]
        declarations.extend(
            f"array[0..{component.output_bit_size - 1}] of var 0..1: {component.id};"
            for component in self._cipher.all_components()
            if component.type != CONSTANT
        )
        for side in (_UPPER, _LOWER):
            probabilities = {0}
            tables = []
            already_added = []
            for component in self._differential_components():
                if (
                    component.id.startswith(side + "_")
                    and component.type == WORD_OPERATION
                    and component.description[0] in ("AND", "OR")
                ):
                    update_and_or_ddt_valid_probabilities(
                        already_added, component, tables, probabilities
                    )
            declarations.extend(
                line.replace("and2inputs_DDT", side + "_and2inputs_DDT")
                for line in tables
            )
            max_weight = 100 * max(
                component.output_bit_size for component in self._cipher.all_components()
            )
            declarations.append(
                f"array[0..{getattr(self, 'c_' + side) - 1}] of var 0..{max_weight}: {side}_p;"
            )
        return declarations

    def _middle_keys(self):
        upper = {
            key.removeprefix(_UPPER_PREFIX)
            for key in self.component_and_probability
            if key.startswith(_UPPER_PREFIX)
        }
        lower = {
            key.removeprefix(_LOWER_PREFIX)
            for key in self.component_and_probability
            if key.startswith(_LOWER_PREFIX)
        }
        return sorted(
            upper & lower, key=lambda key: tuple(map(int, key.split("_")[1:]))
        )

    def _add_and_switch(self, key, kind, start):
        upper = self._cipher.component_from_id(_UPPER_PREFIX + key)
        lower = self._cipher.component_from_id(_LOWER_PREFIX + key)
        inputs = []
        for component in (upper, lower):
            bits = [
                f"{link}[{bit}]"
                for link, positions in zip(
                    component.input_id_links, component.input_bit_positions
                )
                for bit in positions
            ]
            inputs.append(
                (bits[: component.output_bit_size], bits[component.output_bit_size :])
            )
        for bit in range(upper.output_bit_size):
            a, b = inputs[0][0][bit], inputs[0][1][bit]
            c, d = inputs[1][0][bit], inputs[1][1][bit]
            upper_weight = f"upper_p[{self.component_and_probability[upper.id][bit]}]"
            lower_weight = f"lower_p[{self.component_and_probability[lower.id][bit]}]"
            self._model_constraints.extend(
                self._and_switch_constraints(
                    a,
                    b,
                    c,
                    d,
                    f"{upper.id}[{bit}]",
                    f"{lower.id}[{bit}]",
                    upper_weight,
                    lower_weight,
                    f"middle_p[{start + bit}]",
                    kind,
                )
            )

    @staticmethod
    def _and_switch_constraints(
        a, b, c, d, upper_output, lower_output, upper_weight, lower_weight, target, kind
    ):
        # D_(a,b)(xy) = bx + ay + ab. Vanishing second derivative forces
        # the two linear equations to have rank at most one. When both
        # directions are nonzero they coincide, so their outputs must agree.
        constraints = [f"constraint {a} * {d} = {b} * {c};"]
        if kind == "ebct":
            constraints.append(
                f"constraint ({a} + {b} > 0 /\\ {c} + {d} > 0) -> "
                f"({upper_output} = {lower_output});"
            )
            weight = f"max([{upper_weight}, {lower_weight}])"
        else:
            weight = {"ubct": upper_weight, "lbct": lower_weight}.get(kind, "0")
        constraints.append(f"constraint {target} = {weight};")
        return constraints

    def _add_modular_switch(self, key, kind, index):
        upper, lower = _UPPER_PREFIX + key, _LOWER_PREFIX + key
        component = self._cipher.component_from_id(upper)
        size = component.output_bit_size
        if size < 2:
            raise NotImplementedError("Modular switches require at least two bits")
        args = [f"pre_{upper}_0", f"pre_{upper}_1", lower, f"pre_{lower}_1"]
        upper_output, lower_input = upper, f"pre_{lower}_0"
        if component.description[0] == "MODSUB":
            # The triangular subtraction permutation is addition's inverse.
            # BCT(F^-1)(a,b)=BCT(F)(b,a); upper/lower conditions exchange roles.
            args = args[2:] + args[:2]
            upper_output, lower_input = lower_input, upper_output
            kind = {"ubct": "lbct", "lbct": "ubct"}.get(kind, kind)
        if kind in ("ubct", "ebct"):
            args.append(upper_output)
        if kind in ("lbct", "ebct"):
            args.append(lower_input)
        self._model_constraints.extend(self._switch_constraint(kind, args, size))
        self._model_constraints.extend(self._switch_constraint(kind, args, size, index))
        return kind, size

    def _add_sbox_switch(self, key, kind, index, declared_tables):
        upper = self._cipher.component_from_id(_UPPER_PREFIX + key)
        lower = self._cipher.component_from_id(_LOWER_PREFIX + key)
        if (
            upper.output_bit_size != upper.input_bit_size
            or lower.output_bit_size != lower.input_bit_size
        ):
            raise NotImplementedError("Local S-box switches require square S-boxes")
        name, declaration = minizinc_sbox_switch_table(upper.description, kind)
        if name not in declared_tables:
            self._model_constraints.append(declaration)
            declared_tables.add(name)
        upper_input = [
            f"{link}[{bit}]"
            for link, positions in zip(upper.input_id_links, upper.input_bit_positions)
            for bit in positions
        ]
        lower_input = [
            f"{link}[{bit}]"
            for link, positions in zip(lower.input_id_links, lower.input_bit_positions)
            for bit in positions
        ]
        differences = {
            "upper_input": upper_input,
            "upper_output": [
                f"{upper.id}[{bit}]" for bit in range(upper.output_bit_size)
            ],
            "lower_input": lower_input,
            "lower_output": [
                f"{lower.id}[{bit}]" for bit in range(lower.output_bit_size)
            ],
        }
        order = {
            "bct": ("upper_input", "lower_output"),
            "ubct": ("upper_input", "upper_output", "lower_output"),
            "lbct": ("upper_input", "lower_input", "lower_output"),
            "ebct": ("upper_input", "upper_output", "lower_input", "lower_output"),
        }[kind]
        values = [bit for difference in order for bit in differences[difference]]
        values.append(f"middle_p[{index}]")
        self._model_constraints.append(
            f"constraint table([{', '.join(values)}], {name});"
        )

    @staticmethod
    def _switch_constraint(kind, ids, size, index=None):
        indices = range(size) if index is not None else reversed(range(size))
        indices = list(indices)
        arrays = [
            f"array1d(0..{size}-1, [" + ",".join(f"{name}[{i}]" for i in indices) + "])"
            for name in ids
        ]
        if index is None:
            suffix = f", {size // 2}, {size}) = true;"
            predicate = f"only_large_switch_{kind}_enum"
        else:
            suffix = f", {size}, middle_p[{index}]);"
            predicate = kind + "_compute"
        return ["constraint " + predicate + "(" + ", ".join(arrays) + suffix]

    def _switch_kind(self, round_number):
        if self.middle_part_number_of_rounds == 1:
            return "bct"
        last_middle_round = (
            self.top_part_number_of_rounds + self.middle_part_number_of_rounds - 1
        )
        return {self.top_part_number_of_rounds: "ubct", last_middle_round: "lbct"}.get(
            round_number, "ebct"
        )

    def _build_switches(self):
        keys = self._middle_keys()
        index = 0
        predicates = {}
        declared_tables = set()
        for key in keys:
            round_number = int(key.split("_")[1])
            kind = self._switch_kind(round_number)
            component = self._cipher.component_from_id(_UPPER_PREFIX + key)
            count = (
                component.output_bit_size if component.description[0] == "AND" else 1
            )
            self._middle_probabilities[key] = list(range(index, index + count))
            if component.description[0] == "AND":
                self._add_and_switch(key, kind, index)
            elif component.type == SBOX:
                self._add_sbox_switch(key, kind, index, declared_tables)
            else:
                kind, size = self._add_modular_switch(key, kind, index)
                if predicates and size not in predicates.values():
                    raise NotImplementedError(
                        "Modular switches must have the same word size"
                    )
                predicates[kind] = size
            index += count
        self._variables_list.append(f"array[0..{index - 1}] of var 0..3200: middle_p;")
        for kind, size in predicates.items():
            connectivity, evaluation = _SWITCH_PREDICATES[kind]
            self._model_constraints.extend([connectivity(), evaluation(size)])
        if predicates:
            self._model_constraints.append(get_approx_logarithm_operation())
        return keys

    def _weight_constraints(self, middle_keys):
        for side in (_UPPER, _LOWER):
            terms = [
                f"{side}_p[{index}]"
                for key, indices in self.component_and_probability.items()
                if key.startswith(side + "_")
                and key.removeprefix(side + "_") not in middle_keys
                for index in indices
            ]
            self._variables_list.append(
                f"var int: {side}_weight = " + (" + ".join(terms) or "0") + ";"
            )
        self._variables_list.extend(
            [
                "var int: middle_weight = sum(middle_p);",
                "var int: weight = 2 * upper_weight + middle_weight + 2 * lower_weight;",
            ]
        )

    def _output_constraints(self):
        lines = []
        for name in (
            self._cipher.inputs
            + self._cipher.all_components_ids()
            + self._value_witness_names
        ):
            if (
                self.middle_model == "exact"
                and name not in self._value_difference_bits
                and name not in self._value_witness_names
            ):
                continue
            lines.append(f'"{name} = " ++ show({name}) ++ "\\n"')
        for name, indices in self.component_and_probability.items():
            side = name.split("_")[0]
            expression = " + ".join(f"{side}_p[{index}]" for index in indices) or "0"
            lines.append(f'"weight {name} = " ++ show(({expression})/100) ++ "\\n"')
        for label, variable in [
            (_UPPER_WEIGHT_LABEL, "upper_weight"),
            (_MIDDLE_WEIGHT_LABEL, "middle_weight"),
            (_LOWER_WEIGHT_LABEL, "lower_weight"),
            (_TRAIL_WEIGHT_LABEL, "weight"),
        ]:
            lines.append(f'"{label} = " ++ show({variable}/100) ++ "\\n"')
        return "output [" + " ++ ".join(lines) + "];"

    def build_hadipour_boomerang_model(self, weight=-1, fixed_variables=None):
        """Build the constraints without invoking a solver or writing a file.

        INPUT:

        - ``weight`` -- local estimated weight, or outer-characteristic weight in exact-middle
          mode; -1 minimizes the weight,
          None finds any trail; otherwise fixes it to a nonnegative multiple
          of 0.01 bits.
        - ``fixed_variables`` -- optional list from ``set_fixed_variables``.
          IDs refer to the unified cipher (e.g. ``upper_plaintext`` and
          ``lower_cipher_output_2_12``). Keys default to zero differences;
          both external state differences must be nonzero. With exact value
          compatibility enabled, ``quartet_0_`` input IDs fix actual values
          (e.g. ``quartet_0_key``), rather than differences.

        OUTPUT: None; access ``model_constraints`` or ``assemble_model()``.
        For the assumptions and references see the class documentation.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_hadipour_boomerang_model import MznHadipourBoomerangModel
            sage: model = MznHadipourBoomerangModel(SpeckBlockCipher(number_of_rounds=3), dict(top_part_number_of_rounds=1, middle_part_number_of_rounds=1, bottom_part_number_of_rounds=1))
            sage: model.build_hadipour_boomerang_model(4)
            sage: 'solve satisfy;' in model.model_constraints
            True
        """
        scaled = None if weight in (-1, None) else self._scaled_weight(weight)
        self.initialise_model()
        self._variables_list = []
        self.c_upper = self.c_lower = 0
        self._middle_probabilities = {}
        self._build_components()
        self._variables_list.extend(self._declare_bits_and_characteristic_weights())
        middle_keys = self._build_switches()
        self._weight_constraints(middle_keys)
        self._model_constraints.extend(
            self.fix_variables_value_constraints(fixed_variables or [])
        )
        for name in self._cipher.inputs:
            if name not in self._data_inputs:
                self._model_constraints.append(f"constraint sum({name}) = 0;")
        for name in sorted(self._external_differences):
            self._model_constraints.append(f"constraint sum({name}) > 0;")
        if weight is None:
            self._model_constraints.append("solve satisfy;")
        elif scaled is None:
            self._model_constraints.append("solve minimize weight;")
        else:
            self._model_constraints.extend(
                [f"constraint weight = {scaled};", "solve satisfy;"]
            )
        self._value_witness_names = []
        if self.enforce_value_compatibility:
            value_constraints, self._value_witness_names = (
                build_boomerang_value_constraints(self)
            )
            self._model_constraints.extend(value_constraints)
            if self.exclude_returning_quartets:
                data = self.original_cipher.inputs[0]
                width = self.original_cipher.inputs_bit_size[0]
                self._model_constraints.append(
                    f"constraint exists(i in 0..{width - 1})(quartet_0_{data}[i] != quartet_3_{data}[i]);"
                )
            if self.middle_model == "exact":
                self._validate_retained_fixed_values(fixed_variables or [])
        self._model_constraints = (
            self._variables_list
            + self._model_constraints
            + [self._output_constraints()]
        )

    def _validate_retained_fixed_values(self, fixed_variables):
        for fixed in fixed_variables:
            name = fixed["component_id"]
            if name.startswith(("upper_", "lower_")) and not (
                name in self._cipher.inputs and name not in self._data_inputs
            ):
                retained = self._value_difference_bits.get(name, set())
                if not set(fixed["bit_positions"]).issubset(retained):
                    raise ValueError(
                        f"Cannot fix unretained middle difference bits: {name}"
                    )

    def _parse_boomerang_solution(self, solution, status, solver_name, statistics):
        components = {}
        weights = {}
        for line in solution.__dict__["_output_item"].splitlines():
            name, separator, value = line.partition(" = ")
            if not separator:
                continue
            if value.startswith("["):
                bits = "".join(value.strip("[]").replace(",", " ").split())
                components[name] = {
                    "value": "0x"
                    + format(int(bits, 2), f"0{math.ceil(len(bits) / 4)}x"),
                    "weight": 0,
                }
            elif name.startswith("weight "):
                components[name[7:]]["weight"] = float(value)
            elif name.endswith("weight"):
                weights[name] = float(value)
        elapsed = statistics.get("time", timedelta()).total_seconds()
        result = convert_solver_solution_to_dictionary(
            self.original_cipher,
            _MODEL_TYPE,
            solver_name,
            elapsed,
            statistics.get("peakMem", -1),
            components,
            str(weights[_TRAIL_WEIGHT_LABEL]),
        )
        result.update(
            status="SATISFIABLE",
            solver_status=str(status),
            upper_weight=weights[_UPPER_WEIGHT_LABEL],
            middle_weight=weights[_MIDDLE_WEIGHT_LABEL],
            lower_weight=weights[_LOWER_WEIGHT_LABEL],
            boomerang_structure=dict(self.boomerang_structure),
        )
        result["boomerang_probability_factors"] = _boomerang_probability_factors(
            weights, self.middle_model
        )
        if self.enforce_value_compatibility:
            result["quartet_values"] = {
                name: components.pop(name) for name in self._value_witness_names
            }
            result["value_compatibility"] = "full_cipher"
            result["exclude_returning_quartets"] = self.exclude_returning_quartets
            result["retained_difference_bits"] = {
                name: sorted(bits) for name, bits in self._value_difference_bits.items()
            }
        if self.middle_model == "exact":
            self._retain_exact_components(components)
            result["middle_weight"] = None
            result["weight_type"] = "outer_characteristic_weight"
        else:
            result["weight_type"] = "local_characteristic_weight_estimate"
        return result

    def _retain_exact_components(self, components):
        """Keep only differences constrained by the exact quartet values."""
        for name in [*components]:
            if name not in self._value_difference_bits:
                del components[name]
            else:
                components[name]["retained_bit_positions"] = sorted(
                    self._value_difference_bits[name]
                )

    def _search(
        self,
        weight,
        fixed_values,
        solver_name,
        timeout_in_seconds,
        processes,
        all_solutions=False,
        max_weight=None,
        min_weight=0,
    ):
        start = time.perf_counter()
        self.build_hadipour_boomerang_model(weight, fixed_values)
        if max_weight is not None:
            lower, upper = (
                self._scaled_weight(min_weight),
                self._scaled_weight(max_weight),
            )
            if lower > upper:
                raise ValueError("min_weight must not exceed max_weight")
            self._model_constraints.extend(
                [
                    f"constraint weight >= {lower};",
                    f"constraint weight <= {upper};",
                ]
            )
        build_time = time.perf_counter() - start
        result = self.solve(
            solver_name=solver_name,
            timeout_in_seconds_=timeout_in_seconds,
            processes_=processes,
            all_solutions_=all_solutions,
        )
        for solution in result if isinstance(result, list) else [result]:
            solution["building_time_seconds"] = build_time
        return result

    @staticmethod
    def _solver_options(timeout_in_seconds, processes, all_solutions):
        options = {"all_solutions": all_solutions}
        if timeout_in_seconds is not None:
            if timeout_in_seconds <= 0:
                raise ValueError("timeout_in_seconds must be positive")
            options["timeout"] = timedelta(seconds=float(timeout_in_seconds))
        if processes is not None:
            if processes <= 0:
                raise ValueError("processes must be positive")
            options["processes"] = index(processes)
        return options

    def _default_solver(self, solver_name):
        if solver_name is not None:
            return solver_name
        modular = any(
            component.type == WORD_OPERATION
            and component.description[0] in _MODULAR_OPERATIONS
            for component in self._cipher.all_components()
        )
        return GECODE if modular and self.middle_model == "local" else SOLVER_DEFAULT

    def _solver_result(self, result, solver_name, multiple, intermediate):
        if result.status == Status.ERROR:
            raise RuntimeError(f"MiniZinc solver {solver_name} reported ERROR")
        no_solution = result.solution is None or (
            isinstance(result.solution, list) and not result.solution
        )
        if no_solution:
            if multiple:
                return []
            status = (
                "UNSATISFIABLE" if result.status == Status.UNSATISFIABLE else "UNKNOWN"
            )
            empty = convert_solver_solution_to_dictionary(
                self.original_cipher,
                _MODEL_TYPE,
                solver_name,
                result.statistics.get("time", timedelta()).total_seconds(),
                -1,
                {},
                None,
            )
            empty.update(status=status, solver_status=str(result.status))
            return empty
        solutions = (
            result.solution if isinstance(result.solution, list) else [result.solution]
        )
        parsed = [
            self._parse_boomerang_solution(
                solution, result.status, solver_name, result.statistics
            )
            for solution in solutions
        ]
        if intermediate:
            for solution in parsed[:-1]:
                solution["solver_status"] = str(Status.SATISFIED)
        return parsed if multiple else parsed[-1]

    def solve(
        self,
        model_type=_MODEL_TYPE,
        solve_external=False,
        solver_name=None,
        timeout_in_seconds_=None,
        processes_=None,
        nr_solutions_=None,
        random_seed_=None,
        all_solutions_=False,
        intermediate_solutions_=False,
        free_search_=False,
        optimisation_level_=None,
    ):
        """Solve a built boomerang model through the CLAASP solver interface.

        INPUT:

        - ``model_type`` -- ``'boomerang'`` (default); other models are rejected.
        - ``solve_external`` -- bool compatibility flag (default: False).
          Both modes use MiniZinc's CLI through its Python client and the same
          boomerang parser; neither requires manual terminal output parsing.
        - ``solver_name`` -- installed MiniZinc solver ID. None selects gecode
          for modular switches and CLAASP's default for AND-only models.
        - ``timeout_in_seconds_`` -- optional positive time limit in seconds.
        - ``processes_`` -- optional positive integer solver process count.
        - ``nr_solutions_`` -- optional number of satisfaction solutions to find.
        - ``random_seed_`` -- optional integer solver random seed.
        - ``all_solutions_`` -- bool (default: False); enumerate a satisfaction model.
        - ``intermediate_solutions_`` -- bool (default: False); return optimization
          incumbents as a list. Only the final entry can be proven optimal.
        - ``free_search_`` -- bool (default: False); let the solver choose its search.
        - ``optimisation_level_`` -- optional MiniZinc compiler level, 0 through 5.

        OUTPUT: a CLAASP solution dictionary, or a list when requesting multiple
        solutions, enumerating, or requesting optimization incumbents. Weights are in bits. Check ``status``
        and ``solver_status`` for satisfiability and completion. A timeout without
        a solution is UNKNOWN; list searches return an empty list if none were
        found. A solver-reported ERROR raises RuntimeError rather than being
        reported as UNKNOWN. Solver options depend on the selected backend's capabilities.
        Call ``build_hadipour_boomerang_model`` first. See the class documentation
        for probability assumptions and references.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_hadipour_boomerang_model import MznHadipourBoomerangModel
            sage: model = MznHadipourBoomerangModel(SimonBlockCipher(number_of_rounds=3), dict(top_part_number_of_rounds=1, middle_part_number_of_rounds=1, bottom_part_number_of_rounds=1))
            sage: model.build_hadipour_boomerang_model(weight=None)
            sage: result = model.solve(solver_name='gecode', timeout_in_seconds_=1)  # optional - minizinc
        """
        if self.enforce_value_compatibility and all_solutions_:
            raise NotImplementedError(
                "Exact value compatibility currently supports single-trail search; "
                "enumeration would enumerate value witnesses instead of distinct trails"
            )
        if model_type != _MODEL_TYPE:
            raise ValueError("This model only solves boomerang characteristics")
        if not isinstance(solve_external, bool):
            raise ValueError("solve_external must be a boolean")
        if not self._model_constraints:
            raise ValueError("Build the boomerang model before solving")
        solver_name = self._default_solver(solver_name)
        model = Model()
        model.add_string(self.assemble_model())
        options = self._solver_options(timeout_in_seconds_, processes_, all_solutions_)
        options.update(
            nr_solutions=nr_solutions_,
            random_seed=random_seed_,
            intermediate_solutions=intermediate_solutions_,
            free_search=free_search_,
            optimisation_level=optimisation_level_,
        )
        result = Instance(Solver.lookup(solver_name), model).solve(**options)
        multiple = (
            all_solutions_
            or intermediate_solutions_
            or (nr_solutions_ is not None and nr_solutions_ > 1)
        )
        return self._solver_result(
            result, solver_name, multiple, intermediate_solutions_
        )

    def find_one_boomerang_trail(
        self,
        fixed_values=None,
        solver_name=None,
        timeout_in_seconds=None,
        processes=None,
    ):
        """Find one characteristic using MiniZinc.

        INPUT:

        - ``fixed_values`` -- optional list from ``set_fixed_variables``;
          component IDs include ``upper_`` or ``lower_``. Defaults to the
          single-key setting and nonzero external state differences.
        - ``solver_name`` -- installed MiniZinc solver ID. By default, gecode is used
          for modular switches and CLAASP's default solver for AND-only models.
          Local modular probability predicates require float support (e.g. gecode).
          Exact-middle mode uses CLAASP's default integer solver instead.
        - ``timeout_in_seconds`` -- optional positive time limit, including
          flattening. A time limit may leave optimality unproved.
        - ``processes`` -- optional positive number of solver processes.

        OUTPUT: CLAASP solution dictionary with hexadecimal component values,
        ``total_weight``, ``upper_weight``, ``middle_weight``, ``lower_weight``,
        ``boomerang_probability_factors`` with ``p``, ``q``, ``r``, and
        ``p_squared_q_squared_r`` (the last two are ``None`` in exact-middle mode),
        solver statistics, build time, and ``solver_status``. ``status`` is
        SATISFIABLE, UNSATISFIABLE or UNKNOWN (e.g. a timeout without a solution).
        Check ``solver_status`` for proof of optimality. See the class
        documentation for assumptions and citations.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_hadipour_boomerang_model import MznHadipourBoomerangModel
            sage: model = MznHadipourBoomerangModel(SimonBlockCipher(number_of_rounds=3), dict(top_part_number_of_rounds=1, middle_part_number_of_rounds=1, bottom_part_number_of_rounds=1))
            sage: result = model.find_one_boomerang_trail(solver_name='gecode', timeout_in_seconds=1)  # optional - minizinc
        """
        return self._search(
            None,
            fixed_values,
            solver_name,
            timeout_in_seconds,
            processes,
            all_solutions=False,
        )

    def find_one_boomerang_trail_with_fixed_weight(
        self,
        weight,
        fixed_values=None,
        solver_name=None,
        timeout_in_seconds=None,
        processes=None,
    ):
        """Find one characteristic of the given weight using MiniZinc.

        INPUT:

        - ``weight`` -- estimated weight (outer-characteristic weight for exact middle), a nonnegative
          multiple of 0.01. The objective uses the class-level approximation.
        - ``fixed_values`` -- optional list from ``set_fixed_variables``;
          component IDs include ``upper_`` or ``lower_``. Defaults to the
          single-key setting and nonzero external state differences.
        - ``solver_name`` -- installed MiniZinc solver ID. By default, gecode is used
          for modular switches and CLAASP's default solver for AND-only models.
          Local modular probability predicates require float support (e.g. gecode).
          Exact-middle mode uses CLAASP's default integer solver instead.
        - ``timeout_in_seconds`` -- optional positive time limit, including
          flattening. A time limit may leave optimality unproved.
        - ``processes`` -- optional positive number of solver processes.

        OUTPUT: CLAASP solution dictionary with hexadecimal component values,
        ``total_weight``, ``upper_weight``, ``middle_weight``, ``lower_weight``,
        solver statistics, build time, and ``solver_status``. ``status`` is
        SATISFIABLE, UNSATISFIABLE or UNKNOWN (e.g. a timeout without a solution).
        Check ``solver_status`` for proof of optimality. See the class
        documentation for assumptions and citations.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_hadipour_boomerang_model import MznHadipourBoomerangModel
            sage: model = MznHadipourBoomerangModel(SimonBlockCipher(number_of_rounds=3), dict(top_part_number_of_rounds=1, middle_part_number_of_rounds=1, bottom_part_number_of_rounds=1))
            sage: result = model.find_one_boomerang_trail_with_fixed_weight(4, solver_name='gecode', timeout_in_seconds=1)  # optional - minizinc
        """
        return self._search(
            weight,
            fixed_values,
            solver_name,
            timeout_in_seconds,
            processes,
            all_solutions=False,
        )

    def find_lowest_weight_boomerang_trail(
        self,
        fixed_values=None,
        solver_name=None,
        timeout_in_seconds=None,
        processes=None,
        optimize_round_split=False,
    ):
        """Find one minimum-weight characteristic using MiniZinc.

        INPUT:

        - ``fixed_values`` -- optional list from ``set_fixed_variables``;
          component IDs include ``upper_`` or ``lower_``. Defaults to the
          single-key setting and nonzero external state differences.
        - ``solver_name`` -- installed MiniZinc solver ID. By default, gecode is used
          for modular switches and CLAASP's default solver for AND-only models.
          Local modular probability predicates require float support (e.g. gecode).
          Exact-middle mode uses CLAASP's default integer solver instead.
        - ``timeout_in_seconds`` -- optional positive time limit, including
          flattening. A time limit may leave optimality unproved.
        - ``processes`` -- optional positive number of solver processes.
        - ``optimize_round_split`` -- bool (default: False). Search every split
          with a nonempty middle and the same total number of rounds, including
          zero-round outer parts. Each split is solved separately with the given
          time limit. Only local-middle weights can be compared this way;
          exact-middle weights omit the middle probability. The returned
          ``round_split_search`` lists every result and marks whether all splits
          were proved optimal or unsatisfiable. A timeout or an incumbent without
          an optimality proof makes that overall flag False.

        OUTPUT: CLAASP solution dictionary with hexadecimal component values,
        ``total_weight``, ``upper_weight``, ``middle_weight``, ``lower_weight``,
        solver statistics, build time, and ``solver_status``. ``status`` is
        SATISFIABLE, UNSATISFIABLE or UNKNOWN (e.g. a timeout without a solution).
        Check ``solver_status`` for proof of optimality. See the class
        documentation for assumptions and citations.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_hadipour_boomerang_model import MznHadipourBoomerangModel
            sage: model = MznHadipourBoomerangModel(SimonBlockCipher(number_of_rounds=3), dict(top_part_number_of_rounds=1, middle_part_number_of_rounds=1, bottom_part_number_of_rounds=1))
            sage: result = model.find_lowest_weight_boomerang_trail(solver_name='gecode', timeout_in_seconds=1)  # optional - minizinc
            sage: split = model.find_lowest_weight_boomerang_trail(solver_name='gecode', timeout_in_seconds=1, optimize_round_split=True)  # optional - minizinc
            sage: len(split['round_split_search']['results']) == 6  # optional - minizinc
            True
        """
        if not isinstance(optimize_round_split, bool):
            raise TypeError("optimize_round_split must be a boolean")
        if optimize_round_split:
            return self._find_optimal_round_split(
                fixed_values, solver_name, timeout_in_seconds, processes
            )
        return self._search(
            -1,
            fixed_values,
            solver_name,
            timeout_in_seconds,
            processes,
            all_solutions=False,
        )

    def _find_optimal_round_split(
        self, fixed_values, solver_name, timeout_in_seconds, processes
    ):
        """Compare independently optimized local models for every valid split."""
        if self.middle_model != "local":
            raise ValueError(
                "Round-split optimization requires middle_model='local': "
                "exact-middle weights do not include the middle probability"
            )
        best = None
        fallback = None
        results = []
        all_proved = True
        for structure, model in self._round_split_models():
            result = model._search(
                -1, fixed_values, solver_name, timeout_in_seconds, processes
            )
            if fallback is None or result["status"] == "UNKNOWN":
                fallback = result
            results.append(
                {
                    "boomerang_structure": structure,
                    "status": result["status"],
                    "solver_status": result["solver_status"],
                    "total_weight": result["total_weight"],
                }
            )
            if result["solver_status"] not in (
                "OPTIMAL_SOLUTION", "UNSATISFIABLE"
            ):
                all_proved = False
            if self._better_round_split_result(result, best):
                best = result
        chosen = best if best is not None else fallback
        chosen["round_split_search"] = {
            "results": results,
            "all_splits_proven": all_proved,
            "best_split": best["boomerang_structure"] if best else None,
        }
        return chosen

    def _round_split_models(self):
        """Yield every valid split with its model, reusing the current one."""
        rounds = self.original_cipher.number_of_rounds
        for top in range(rounds):
            for middle in range(1, rounds - top + 1):
                structure = {
                    "top_part_number_of_rounds": top,
                    "middle_part_number_of_rounds": middle,
                    "bottom_part_number_of_rounds": rounds - top - middle,
                }
                if structure == self.boomerang_structure:
                    yield structure, self
                else:
                    yield structure, type(self)(
                        self.original_cipher,
                        structure,
                        enforce_value_compatibility=self.enforce_value_compatibility,
                        middle_model=self.middle_model,
                        exclude_returning_quartets=self.exclude_returning_quartets,
                        fixed_parameters=self.fixed_parameters,
                    )

    @staticmethod
    def _better_round_split_result(result, best):
        """Check whether a solved split improves the current incumbent."""
        return result["status"] == "SATISFIABLE" and (
            best is None
            or float(result["total_weight"]) < float(best["total_weight"])
        )

    def find_all_boomerang_trails_with_fixed_weight(
        self,
        weight,
        fixed_values=None,
        solver_name=None,
        timeout_in_seconds=None,
        processes=None,
    ):
        """Enumerate all characteristics of the given weight using MiniZinc.

        INPUT:

        - ``weight`` -- estimated weight (outer-characteristic weight for exact middle), a nonnegative
          multiple of 0.01. The objective uses the class-level approximation.
        - ``fixed_values`` -- optional list from ``set_fixed_variables``;
          component IDs include ``upper_`` or ``lower_``. Defaults to the
          single-key setting and nonzero external state differences.
        - ``solver_name`` -- installed MiniZinc solver ID. By default, gecode is used
          for modular switches and CLAASP's default solver for AND-only models.
          Local modular probability predicates require float support (e.g. gecode).
          Exact-middle mode uses CLAASP's default integer solver instead.
        - ``timeout_in_seconds`` -- optional positive time limit, including
          flattening. A time limit may leave optimality unproved.
        - ``processes`` -- optional positive number of solver processes.

        OUTPUT: list of CLAASP solution dictionaries. Empty for an unsatisfiable
        model or a timeout before any solution; ``solver_status`` records
        completeness on returned solutions. Enumeration is of the encoded
        assignments, not aggregated external-difference probabilities.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_hadipour_boomerang_model import MznHadipourBoomerangModel
            sage: model = MznHadipourBoomerangModel(SimonBlockCipher(number_of_rounds=3), dict(top_part_number_of_rounds=1, middle_part_number_of_rounds=1, bottom_part_number_of_rounds=1))
            sage: result = model.find_all_boomerang_trails_with_fixed_weight(4, solver_name='gecode', timeout_in_seconds=1)  # optional - minizinc
        """
        return self._search(
            weight,
            fixed_values,
            solver_name,
            timeout_in_seconds,
            processes,
            all_solutions=True,
        )

    def find_all_boomerang_trails_with_weight_at_most(
        self,
        max_weight,
        min_weight=0,
        fixed_values=None,
        solver_name=None,
        timeout_in_seconds=None,
        processes=None,
    ):
        """Enumerate all characteristics up to the given weight using MiniZinc.

        INPUT:

        - ``max_weight`` -- estimated weight (outer-characteristic weight for exact middle), a nonnegative
          multiple of 0.01. The objective uses the class-level approximation.
        - ``min_weight`` -- nonnegative lower weight bound in bits (default: 0).
        - ``fixed_values`` -- optional list from ``set_fixed_variables``;
          component IDs include ``upper_`` or ``lower_``. Defaults to the
          single-key setting and nonzero external state differences.
        - ``solver_name`` -- installed MiniZinc solver ID. By default, gecode is used
          for modular switches and CLAASP's default solver for AND-only models.
          Local modular probability predicates require float support (e.g. gecode).
          Exact-middle mode uses CLAASP's default integer solver instead.
        - ``timeout_in_seconds`` -- optional positive time limit, including
          flattening. A time limit may leave optimality unproved.
        - ``processes`` -- optional positive number of solver processes.

        OUTPUT: list of CLAASP solution dictionaries. Empty for an unsatisfiable
        model or a timeout before any solution; ``solver_status`` records
        completeness on returned solutions. Enumeration is of the encoded
        assignments, not aggregated external-difference probabilities.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_hadipour_boomerang_model import MznHadipourBoomerangModel
            sage: model = MznHadipourBoomerangModel(SimonBlockCipher(number_of_rounds=3), dict(top_part_number_of_rounds=1, middle_part_number_of_rounds=1, bottom_part_number_of_rounds=1))
            sage: result = model.find_all_boomerang_trails_with_weight_at_most(4, solver_name='gecode', timeout_in_seconds=1)  # optional - minizinc
        """
        return self._search(
            None,
            fixed_values,
            solver_name,
            timeout_in_seconds,
            processes,
            all_solutions=True,
            max_weight=max_weight,
            min_weight=min_weight,
        )
