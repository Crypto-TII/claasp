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
import re
import time as tm

from claasp.cipher_modules.models.cp.minizinc_utils.mzn_continuous_predicates import (
    active_bit_correlation_expression,
    piecewise_log2_approximation_expression,
)
from claasp.cipher_modules.models.cp.mzn_model import SOLVE_SATISFY, MznModel
from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_linear_model import MznXorLinearModel
from claasp.cipher_modules.models.cp.solvers import SOLVER_DEFAULT
from claasp.cipher_modules.models.utils import get_bit_bindings, integer_to_bit_list, set_fixed_variables
from claasp.name_mappings import (
    CIPHER_OUTPUT,
    CONSTANT,
    INPUT_KEY,
    INPUT_PLAINTEXT,
    INPUT_TWEAK,
    INTERMEDIATE_OUTPUT,
    LINEAR_LAYER,
    MIX_COLUMN,
    SBOX,
    WORD_OPERATION,
    XOR_DIFFERENTIAL_LINEAR_ONE_SOLUTION,
    XOR_DIFFERENTIAL_LINEAR_OPTIMAL_SOLUTION,
)


class MznDifferentialLinearModel(MznModel):
    """
    CP model combining three parts:
    - top: XOR differential
    - middle: deterministic/semi-deterministic truncated XOR differential
    - bottom: XOR linear

    If ``single_key`` is True, the linear-weight contribution only counts
    bottom components that remain after removing the key schedule from the
    cipher.
    """

    _ALLOWED_MIDDLE_MODELS = {
        "cp_deterministic_truncated_xor_differential_constraints",
        "cp_semi_deterministic_truncated_xor_differential_constraints",
        "cp_deterministic_truncated_xor_differential_trail_constraints",
        "cp_continuous_differential_propagation_constraints",
    }

    _ALLOWED_WORD_OPERATIONS = {
        "MODADD",
        "MODSUB",
        "XOR",
        "ROTATE",
        "SHIFT",
        "SHIFT_BY_VARIABLE_AMOUNT",
        "NOT",
        "OR",
        "AND",
    }

    def __init__(
        self,
        cipher,
        list_of_components,
        middle_part_model="cp_semi_deterministic_truncated_xor_differential_constraints",
        standard_differential_part=True,
        single_key=False,
    ):
        super().__init__(cipher)
        self.standard_differential_part = standard_differential_part

        middle_part_components = list_of_components.get("middle_part_components", [])
        bottom_part_components = list_of_components.get("bottom_part_components", [])

        self.middle_part_component_ids = set(middle_part_components)
        self.bottom_part_component_ids = set(bottom_part_components)
        self.top_part_component_ids = {
            component.id
            for component in self._cipher.get_all_components()
            if component.id not in self.middle_part_component_ids | self.bottom_part_component_ids
        }

        self.middle_part_model = middle_part_model
        self.single_key = single_key
        self._cached_weight_bottom_component_ids = None
        if self.middle_part_model not in self._ALLOWED_MIDDLE_MODELS:
            raise ValueError(
                f"middle_part_model should be one of {sorted(self._ALLOWED_MIDDLE_MODELS)}"
            )

        self._validate_component_partitioning()
        self._validate_arx_only_cipher()

        # Only bottom-part components are modeled with linear input/output arrays
        # (<component>_i / <component>_o). Top and middle components keep their
        # plain state arrays (<component>), so mixed-part bindings must preserve
        # that distinction.
        def format_func(record):
            component_id, bit_index, side = record
            if component_id in self.bottom_part_component_ids:
                return f"{component_id}_{side}[{bit_index}]"
            return f"{component_id}[{bit_index}]"

        self.bit_bindings, self.bit_bindings_for_intermediate_output = get_bit_bindings(cipher, format_func)
        self.raw_bit_bindings, self.raw_bit_bindings_for_intermediate_output = get_bit_bindings(cipher)

        # HOTFIX: Registry of middle-part output bits that cross into the bottom
        # part via an IntermediateOutput. Used by _collect_border_sources to
        # consolidate fork constraints in linear_border_mask.
        self.continuous_border_bits = set()

    def _is_continuous_middle(self):
        """Return True when the middle part uses continuous correlation propagation."""
        return self.middle_part_model == "cp_continuous_differential_propagation_constraints"

    def _validate_component_partitioning(self):
        allowed_overlapping_ids = set(self._get_truncated_xor_differential_components_in_border())
        overlap = (self.middle_part_component_ids & self.bottom_part_component_ids) - allowed_overlapping_ids
        if overlap:
            raise ValueError(f"middle and bottom parts overlap: {sorted(overlap)}")

    def _validate_arx_only_cipher(self):
        for component in self._cipher.get_all_components():
            if component.type in (SBOX, LINEAR_LAYER, MIX_COLUMN):
                raise NotImplementedError("MznDifferentialLinearModel currently supports ARX ciphers only")
            if component.type == WORD_OPERATION and component.description[0] not in self._ALLOWED_WORD_OPERATIONS:
                raise NotImplementedError(
                    f"Unsupported ARX word operation for differential-linear CP model: {component.description[0]}"
                )

    def _get_component_by_id(self, component_id):
        return self._cipher.component_from_id(component_id)

    def _weight_bottom_component_ids(self):
        if not self.single_key:
            return self.bottom_part_component_ids

        if self._cached_weight_bottom_component_ids is not None:
            return self._cached_weight_bottom_component_ids

        try:
            cipher_without_key_schedule = self._cipher.remove_key_schedule()
            no_key_schedule_ids = set(cipher_without_key_schedule.get_all_components_ids())
            effective_bottom_component_ids = self.bottom_part_component_ids & no_key_schedule_ids
        except Exception:
            effective_bottom_component_ids = set(self.bottom_part_component_ids)

        self._cached_weight_bottom_component_ids = effective_bottom_component_ids
        return self._cached_weight_bottom_component_ids

    def _parse_linear_bit_id(self, bit_id):
        match = re.match(r"^(.*)_([io])\[(\d+)\]$", bit_id)
        if not match:
            match = re.match(r"^(.*)\[(\d+)\]$", bit_id)
            if match:
                return match.group(1), None, int(match.group(2))
        if not match:
            raise ValueError(f"Invalid linear bit identifier: {bit_id}")
        return match.group(1), match.group(2), int(match.group(3))

    def _component_model_entries(self):
        entries = []
        for component in self._cipher.get_all_components():
            if component.id in self.bottom_part_component_ids:
                model_type = "cp_xor_linear_mask_propagation_constraints"
            elif component.id in self.middle_part_component_ids:
                model_type = self.middle_part_model
            else:
                model_type = "cp_xor_differential_propagation_constraints"
            entries.append({"component_object": component, "model_type": model_type})
        return entries

    def _state_declarations(self):
        declarations = []
        input_domain = "0..2" if not self.standard_differential_part else "0..1"
        for input_name, bit_size in zip(self._cipher.inputs, self._cipher.inputs_bit_size):
            declarations.append(f"array[0..{bit_size - 1}] of var {input_domain}: {input_name};")

        for component in self._cipher.get_all_components():
            if component.type == CONSTANT:
                continue

            if component.id in self.middle_part_component_ids:
                if self._is_continuous_middle():
                    # Continuous components self-declare their variables
                    # (x1_<id>, x2_<id>, <id>) in cp_continuous_differential_propagation_constraints
                    continue
                else:
                    domain = "0..2"
            elif component.id in self.bottom_part_component_ids:
                # Linear components self-declare their variables
                # (<id>_i, <id>_o) in cp_xor_linear_mask_propagation_constraints
                continue
            else:
                domain = "0..1"
            declarations.append(
                f"array[0..{component.output_bit_size - 1}] of var {domain}: {component.id};"
            )

        return declarations

    def _partition_fixed_value_constraints(self, fixed_variables):
        top_and_middle_constraints = []
        linear_constraints = []

        for fixed_variable in fixed_variables:
            component_id = fixed_variable["component_id"]
            if component_id in self.bottom_part_component_ids:
                linear_constraints.append(fixed_variable)
            else:
                if component_id in self.top_part_component_ids and 2 in fixed_variable["bit_values"]:
                    raise ValueError("The fixed value in a top (differential) component cannot be 2")
                top_and_middle_constraints.append(fixed_variable)

        constraints = self.fix_variables_value_constraints(top_and_middle_constraints)
        constraints.extend(self.fix_variables_value_xor_linear_constraints(linear_constraints))
        return constraints

    def _get_regular_xor_differential_components_in_border(self):
        regular_component_ids = set(self.top_part_component_ids)
        border_components = []

        for middle_component_id in self.middle_part_component_ids:
            component_obj = self.cipher.component_from_id(middle_component_id)
            for input_id in component_obj.input_id_links:
                if input_id in regular_component_ids:
                    border_components.append(input_id)

        return list(set(border_components))

    def _get_truncated_xor_differential_components_in_border(self):
        truncated_component_ids = set(self.middle_part_component_ids)
        border_components = []

        for linear_component_id in self.bottom_part_component_ids:
            component_obj = self.cipher.component_from_id(linear_component_id)
            for input_id in component_obj.input_id_links:
                if input_id in truncated_component_ids:
                    border_components.append(input_id)

        return list(set(border_components))

    def _continuous_middle_input_expr(self, component_id, input_bit_index):
        component = self._get_component_by_id(component_id)
        accumulated = 0
        for input_idx, bit_positions in enumerate(component.input_bit_positions, start=1):
            input_size = len(bit_positions)
            if input_bit_index < accumulated + input_size:
                local_index = input_bit_index - accumulated
                return f"x{input_idx}_{component_id}[{local_index}]"
            accumulated += input_size

        raise ValueError(
            f"Invalid continuous input bit index {input_bit_index} for component {component_id}"
        )

    def _continuous_middle_connecting_constraints(self, include_middle_sources=True):
        """
        Build wiring constraints for the continuous middle part.

        Continuous component generators declare x1_<id>, x2_<id>, ... input arrays,
        but they do not connect them to predecessor components. This method links
        all incoming arcs to those x* arrays.
        """
        constraints = []
        constraints.extend(self._continuous_middle_connecting_from_raw_bindings(include_middle_sources))
        constraints.extend(self._continuous_middle_connecting_for_intermediate_outputs(include_middle_sources))
        return constraints

    def _is_valid_continuous_middle_source(self, source_component_id, source_side, include_middle_sources):
        is_input = source_component_id in self._cipher.inputs
        if not is_input and source_side != "o":
            return False
        if not include_middle_sources and source_component_id in self.middle_part_component_ids:
            return False
        return True

    def _is_valid_continuous_middle_successor(self, successor_component_id, successor_side):
        successor_is_output = successor_component_id in (
            self._cipher.outputs if hasattr(self._cipher, "outputs") else []
        )
        return (successor_side == "i" or successor_is_output) and (
            successor_component_id in self.middle_part_component_ids
        )

    @staticmethod
    def _continuous_middle_source_expr(source_component_id, source_bit_index):
        return f"{source_component_id}[{int(source_bit_index)}]"

    def _continuous_middle_assignment_constraint(self, source_component_id, source_bit_expr, successor_bit_expr):
        if source_component_id in self.middle_part_component_ids:
            return f"constraint {successor_bit_expr} = {source_bit_expr};"
        return f"constraint {successor_bit_expr} = if {source_bit_expr} = 1 then 1 else -1 endif;"

    def _continuous_middle_constraints_for_successors(self, source_component_id, source_bit_expr, successor_bits):
        constraints = []
        for successor_component_id, successor_bit_index, successor_side in successor_bits:
            if not self._is_valid_continuous_middle_successor(successor_component_id, successor_side):
                continue

            successor_bit_expr = self._continuous_middle_input_expr(
                successor_component_id, int(successor_bit_index)
            )
            constraints.append(
                self._continuous_middle_assignment_constraint(
                    source_component_id, source_bit_expr, successor_bit_expr
                )
            )
        return constraints

    def _continuous_middle_connecting_from_raw_bindings(self, include_middle_sources):
        constraints = []
        for output_bit_id, successor_bits in self.raw_bit_bindings.items():
            source_component_id, source_bit_index, source_side = output_bit_id
            if not self._is_valid_continuous_middle_source(
                source_component_id, source_side, include_middle_sources
            ):
                continue

            source_bit_expr = self._continuous_middle_source_expr(source_component_id, source_bit_index)
            constraints.extend(
                self._continuous_middle_constraints_for_successors(
                    source_component_id, source_bit_expr, successor_bits
                )
            )
        return constraints

    def _continuous_middle_intermediate_source_pin(self, pins):
        return next((pin for pin in pins if pin[2] == "o" or pin[0] in self._cipher.inputs), None)

    def _should_skip_continuous_middle_intermediate_source(self, source_id, include_middle_sources):
        return (not include_middle_sources) and (source_id in self.middle_part_component_ids)

    def _continuous_middle_constraint_from_intermediate_pin(
        self, inter_id, inter_bit, source_pin, include_middle_sources
    ):
        if not source_pin:
            return None

        source_id, source_bit, _ = source_pin
        if self._should_skip_continuous_middle_intermediate_source(source_id, include_middle_sources):
            return None

        source_expr = self._continuous_middle_source_expr(source_id, source_bit)
        successor_expr = self._continuous_middle_input_expr(inter_id, int(inter_bit))
        return self._continuous_middle_assignment_constraint(source_id, source_expr, successor_expr)

    def _continuous_middle_constraints_for_intermediate_bit_dict(self, bit_dict, include_middle_sources):
        constraints = []
        for inter_bit_tuple, pins in bit_dict.items():
            inter_id, inter_bit, _ = inter_bit_tuple
            source_pin = self._continuous_middle_intermediate_source_pin(pins)
            constraint = self._continuous_middle_constraint_from_intermediate_pin(
                inter_id, inter_bit, source_pin, include_middle_sources
            )
            if constraint:
                constraints.append(constraint)
        return constraints

    def _continuous_middle_connecting_for_intermediate_outputs(self, include_middle_sources):
        constraints = []
        for comp_id, bit_dict in self.raw_bit_bindings_for_intermediate_output.items():
            if comp_id not in self.middle_part_component_ids:
                continue
            constraints.extend(
                self._continuous_middle_constraints_for_intermediate_bit_dict(
                    bit_dict, include_middle_sources
                )
            )
        return constraints

    def _top_to_middle_connecting_constraints(self):
        if self._is_continuous_middle():
            return self._continuous_middle_connecting_constraints(include_middle_sources=False)

        constraints = []
        border_components = set(self._get_regular_xor_differential_components_in_border())
        border_components.update(set(self._cipher.inputs))

        for output_bit_id, successor_bits in self.raw_bit_bindings.items():
            source_component_id, source_bit_index, source_side = output_bit_id
            is_input = source_component_id in self._cipher.inputs
            if (not is_input and source_side != "o") or source_component_id not in border_components:
                continue

            source_bit_expr = f"{source_component_id}[{int(source_bit_index)}]"
            constraints.extend(self._top_to_middle_successor_constraints(successor_bits, source_bit_expr))

        return constraints

    def _top_to_middle_successor_constraints(self, successor_bits, source_bit_expr):
        constraints = []
        for successor_bit in successor_bits:
            successor_component_id, successor_bit_index, successor_side = successor_bit
            if successor_side != "i" or successor_component_id not in self.middle_part_component_ids:
                continue

            successor_bit_expr = f"{successor_component_id}[{int(successor_bit_index)}]"
            if self._is_continuous_middle():
                constraints.append(f"constraint {successor_bit_expr} = if {source_bit_expr} = 1 then 1 else -1 endif;")
            else:
                constraints.append(f"constraint {successor_bit_expr} = if {source_bit_expr} = 1 then 1 else 0 endif;")
        return constraints

    def _middle_to_bottom_connecting_constraints(self):
        if self._is_continuous_middle():
            return self._continuous_middle_to_bottom_connecting_constraints()

        constraints = []
        truncated_border_components = set(self._get_truncated_xor_differential_components_in_border())
        # ensure that at least one bit difference exist in the concatenation of the output of the truncated border components
        truncated_border_components_list = []
        for component_id in truncated_border_components:
            truncated_border_components_list.append(component_id)
        constraints.append(f"constraint count({' ++ '.join(truncated_border_components_list)}, 1) > 0;")

        for output_bit_id, successor_bits in self.bit_bindings.items():
            source_component_id, _, _ = self._parse_linear_bit_id(output_bit_id)
            if source_component_id not in truncated_border_components:
                continue

            source_bit_expr = output_bit_id.replace("_o[", "[")
            for successor_bit in successor_bits:
                successor_component_id, _, _ = self._parse_linear_bit_id(successor_bit)
                if successor_component_id in self.bottom_part_component_ids:
                    constraints.append(f"constraint (({source_bit_expr} + {successor_bit}) != 3);")

        return constraints

    def _continuous_middle_to_bottom_connecting_constraints(self):
        """
        Connection from differential-linear (continuous) part to linear part.

        Implements the semantics from [BGGMP2023]::

            combined[i] = if linear_mask[i] == 0 then 1
                          else linear_mask[i] * abs(continuous_correlation[i])

            differential_linear_correlation = product(combined)

        When the linear mask bit is 0 (inactive), the contribution is 1 (neutral
        in the product).  When it is 1 (active), the contribution is the absolute
        value of the continuous correlation at that position.
        """
        constraints = []
        border_components = set(self._get_truncated_xor_differential_components_in_border())
        border_components = self._filter_border_components_for_single_key(border_components)

        border_sources = self._collect_border_sources(border_components)
        if not border_sources:
            return constraints

        ordered_border_sources = self._order_border_sources(border_sources)
        n = len(ordered_border_sources)

        self._variables_declarations.append(f"array[0..{n - 1}] of var 0..1: linear_border_mask;")
        self._add_linear_border_mask_constraints(constraints, ordered_border_sources)

        self._variables_declarations.append(f"array[0..{n - 1}] of var -1.0..1.0: linear_mask_times_diff_lin_output;")
        for idx, (cont_bit, _) in enumerate(ordered_border_sources):
            constraints.append(
                f"constraint linear_mask_times_diff_lin_output[{idx}] = "
                f"{active_bit_correlation_expression(f'linear_border_mask[{idx}]', cont_bit)};"
            )

        self._variables_declarations.append("var -1.0..1.0: differential_linear_correlation;")
        constraints.append("constraint differential_linear_correlation = product(linear_mask_times_diff_lin_output);")
        constraints.append("constraint differential_linear_correlation != 0.0;")

        self.mzn_output_directives.append('output ["linear_border_mask="++show(linear_border_mask)++"\\n"];')
        self.mzn_output_directives.append('output ["linear_mask_times_diff_lin_output="++show(linear_mask_times_diff_lin_output)++"\\n"];')
        self.mzn_output_directives.append('output ["differential_linear_correlation="++show(differential_linear_correlation)++"\\n"];')

        return constraints

    def _filter_border_components_for_single_key(self, border_components):
        if not self.single_key:
            return border_components
        last_middle_round = max(
            self._cipher.get_round_from_component_id(cid) for cid in self.middle_part_component_ids
        )
        state_input_ids = set()
        for comp in self._cipher.get_components_in_round(last_middle_round):
            if comp.id in self.middle_part_component_ids and comp.type == "intermediate_output":
                if comp.output_bit_size > 16:
                    state_input_ids.update(comp.input_id_links)
        if state_input_ids:
            return border_components & state_input_ids
        return border_components

    def _collect_border_sources(self, border_components):
        border_sources = {}

        # --- Original scan: regular bit_bindings ---
        for output_bit_id, successor_bits in self.bit_bindings.items():
            source_component_id, _, _ = self._parse_linear_bit_id(output_bit_id)
            if source_component_id not in border_components:
                continue

            source_bit_expr = output_bit_id.replace("_o[", "[")
            for successor_bit in successor_bits:
                successor_component_id, _, _ = self._parse_linear_bit_id(successor_bit)
                if successor_component_id in self.bottom_part_component_ids:
                    border_sources.setdefault(source_bit_expr, set()).add(successor_bit)

        # --- HOTFIX: Also scan bit_bindings_for_intermediate_output ---
        # When an IntermediateOutput (IO) in the bottom_part consumes a
        # middle_part border bit, include the IO as a consumer in border_sources
        # so the central model emits a single unified fork constraint:
        #   linear_border_mask[idx] = (regular_consumer + IO_consumer) mod 2
        for io_comp_id, bit_dict in self.bit_bindings_for_intermediate_output.items():
            if io_comp_id not in self.bottom_part_component_ids:
                continue

            for io_input_bit, linked_components in bit_dict.items():
                if not linked_components:
                    continue

                source_output_bit = linked_components[0]
                source_component_id, _, _ = self._parse_linear_bit_id(source_output_bit)
                if source_component_id not in border_components:
                    continue

                source_bit_expr = source_output_bit.replace("_o[", "[")
                border_sources.setdefault(source_bit_expr, set()).add(io_input_bit)
                self.continuous_border_bits.add(source_output_bit)

        return border_sources

    def _order_border_sources(self, border_sources):
        def _sort_bit_expr(bit_expr):
            component_id, _, bit_index = self._parse_linear_bit_id(bit_expr)
            return component_id, bit_index

        ordered_border_sources = []
        for source_bit_expr in sorted(border_sources, key=_sort_bit_expr):
            ordered_successors = sorted(border_sources[source_bit_expr], key=_sort_bit_expr)
            ordered_border_sources.append((source_bit_expr, ordered_successors))
        return ordered_border_sources

    def _add_linear_border_mask_constraints(self, constraints, ordered_border_sources):
        for idx, (_, successors) in enumerate(ordered_border_sources):
            if len(successors) == 1:
                constraints.append(f"constraint linear_border_mask[{idx}] = {successors[0]};")
            else:
                constraints.append(f"constraint linear_border_mask[{idx}] = ({' + '.join(successors)}) mod 2;")

    def _branch_xor_linear_constraints_for_bottom_part(self):
        constraints = []

        for output_bit_id, input_bit_ids in self.bit_bindings.items():
            output_component_id, _, _ = self._parse_linear_bit_id(output_bit_id)
            if output_component_id not in self.bottom_part_component_ids:
                continue

            if len(input_bit_ids) == 1:
                constraints.append(f"constraint {output_bit_id} = {input_bit_ids[0]};")
            else:
                constraints.append(f"constraint {output_bit_id} = ({' + '.join(input_bit_ids)}) mod 2;")

        return constraints

    def _build_weight_constraints(self, weight):
        if self._is_continuous_middle():
            declarations = ["var float: weight;"]
        else:
            declarations = ["var int: weight;"]

        def _sum_component_probability(component_ids):
            terms = []
            for component_id in sorted(component_ids):
                probability_expr = self._component_probability_expression(component_id)
                if probability_expr:
                    terms.append(f"({probability_expr})")
            if not terms:
                return "0"
            return "(" + " + ".join(terms) + ")"

        # Keep model-assignment semantics consistent with _component_model_entries:
        # if a component appears in both middle and bottom, it is modeled as bottom.
        effective_middle_component_ids = self.middle_part_component_ids - self.bottom_part_component_ids
        effective_bottom_component_ids = self._weight_bottom_component_ids()

        top_probability_sum = _sum_component_probability(self.top_part_component_ids)
        bottom_probability_sum = _sum_component_probability(effective_bottom_component_ids)

        constraints = []
        
        if self._is_continuous_middle():
            # Continuous middle correlation is converted via a piece-wise linear approximation
            # of log2(abs(correlation)) scaled for integer weights.
            declarations.append("var float: correlation_log2_approximation;")
            constraints.append(
                "constraint correlation_log2_approximation = "
                f"{piecewise_log2_approximation_expression('differential_linear_correlation', scale=100.0)};"
            )
            constraints.append(
                f"constraint weight = {top_probability_sum} + correlation_log2_approximation + 2*{bottom_probability_sum};"
            )
        else:
            middle_probability_sum = _sum_component_probability(effective_middle_component_ids)
            # Approximate DL objective in log-domain:
            # weight ≈ p + r + 2q
            # where p = top, r = middle, q = bottom.
            # The factor 2*bottom reflects that the exact term is 2^(2q),
            # and the middle term (2·2^r - 1) is approximated by r.
            constraints = [
                f"constraint weight = {top_probability_sum} + {middle_probability_sum} + 2*{bottom_probability_sum};"
            ]

        if weight != -1:
            constraints.append(f"constraint weight <= {100 * weight};")

        return declarations, constraints

    def _component_probability_expression(self, component_id):
        probability_var = self.component_probability_var.get(component_id)
        if probability_var:
            return probability_var

        if component_id not in self.component_and_probability:
            return None

        probability_idx = self.component_and_probability[component_id]
        if isinstance(probability_idx, (list, tuple)):
            return "(" + " + ".join(f"p[{idx}]" for idx in probability_idx) + ")"

        return f"p[{probability_idx}]"

    @staticmethod
    def _normalize_probability_expression_for_output(probability_expression):
        if not probability_expression:
            return None

        if "p[" in probability_expression and "/100" not in probability_expression:
            return f"({probability_expression})/100"

        return probability_expression

    @staticmethod
    def _append_probability_output(output, probability_output):
        if probability_output:
            return output + f"show({probability_output}) ++ \"\\n\" ++"
        return output + '"0" ++ "\\n" ++'

    def _component_output_header(self, component):
        if component.id in self.bottom_part_component_ids:
            if component.type == CONSTANT:
                return f'"{component.id}_o = "++ show({component.id}_o)++ "\\n" ++ '
            if CIPHER_OUTPUT in component.type:
                return f'"{component.id}_o = "++ show({component.id}_i)++ "\\n" ++ '
            return (
                f'"{component.id}_i = "++ show({component.id}_i)++ "\\n" ++ '
                f'"{component.id}_o = "++ show({component.id}_o)++ "\\n" ++ '
            )
        return f'"{component.id} = "++ show({component.id})++ "\\n" ++'

    def _component_probability_output(self, component, probability_output):
        if not probability_output:
            return None
        if component.id in self.middle_part_component_ids and "/100" not in probability_output:
            return f"({probability_output})/100"
        return probability_output

    def _build_output_block(self, weight):
        solve_directive = "solve minimize weight;" if weight == -1 else SOLVE_SATISFY
        constraints = [solve_directive]

        output = "output["
        for cipher_input in self._cipher.inputs:
            output += f'"{cipher_input} = "++ show({cipher_input}) ++ "\\n" ++'

        for component in self._cipher.get_all_components():
            probability_expr = self._component_probability_expression(component.id)
            probability_output = self._normalize_probability_expression_for_output(probability_expr)
            output += self._component_output_header(component)
            output_probability = self._component_probability_output(component, probability_output)
            output = self._append_probability_output(output, output_probability)

        output += '"Trail weight = " ++ show(weight)'

        # Include the DL correlation in the output for continuous models
        if self._is_continuous_middle():
            output += ' ++ "\\n" ++ "differential_linear_correlation = " ++ show(differential_linear_correlation)'

        output += '];'
        constraints.append(output)

        constraints.extend(self.mzn_output_directives)
        return constraints

    def _probability_value_upper_bound(self):
        # Probability values are scaled by 100 in CP constraints. Use a model-dependent
        # bound from cipher bit-sizes instead of a fixed constant.
        max_component_bits = 0
        for component in self._cipher.get_all_components():
            max_component_bits = max(max_component_bits, int(component.output_bit_size))

        max_input_bits = 0
        if self._cipher.inputs_bit_size:
            max_input_bits = max(int(bit_size) for bit_size in self._cipher.inputs_bit_size)

        max_bits = max(1, max_component_bits, max_input_bits)
        return 100 * max_bits

    def _probability_array_declaration_from_component_map(self):
        used_indices = []
        for probability_idx in self.component_and_probability.values():
            if isinstance(probability_idx, (list, tuple)):
                used_indices.extend(int(idx) for idx in probability_idx)
            else:
                used_indices.append(int(probability_idx))

        if not used_indices:
            return None

        def _is_probability_array_declaration(var):
            normalized = " ".join(var.strip().split())
            return normalized.startswith("array[") and "] of var " in normalized and normalized.endswith(": p;")

        has_declaration = any(_is_probability_array_declaration(var) for var in self._variables_declarations)
        if has_declaration:
            return None

        max_index = max(used_indices)
        upper_bound = self._probability_value_upper_bound()
        return f"array[0..{max_index}] of var 0..{upper_bound}: p;"

    @staticmethod
    def _normalize_total_weight(solution):
        if not isinstance(solution, dict):
            return
        total_weight = solution.get("total_weight")
        if isinstance(total_weight, list) and len(total_weight) == 1:
            solution["total_weight"] = total_weight[0]

    def set_component_solution_value(self, component_solution, truncated, value):
        if self._is_continuous_middle() and ("." in value or "-" in value):
            component_solution["value"] = value
            return
        if "2" in value:
            component_solution["value"] = value
            return
        super().set_component_solution_value(component_solution, truncated, value)

    def _normalize_middle_part_components_values(self, solution):
        if not isinstance(solution, dict):
            return

        components_values = solution.get("components_values", {})
        if not isinstance(components_values, dict):
            return

        ids_to_normalize = set(self.middle_part_component_ids)
        if not self.standard_differential_part:
            ids_to_normalize.update(self._cipher.inputs)

        for component_id in ids_to_normalize:
            component_solution = components_values.get(component_id)
            if not isinstance(component_solution, dict):
                continue

            value = component_solution.get("value")
            if not isinstance(value, str):
                continue

            if value.startswith("0x"):
                if component_id in self._cipher.inputs:
                    idx = list(self._cipher.inputs).index(component_id)
                    bit_size = self._cipher.inputs_bit_size[idx]
                else:
                    bit_size = self._get_component_by_id(component_id).output_bit_size
                component_solution["value"] = bin(int(value, 16))[2:].zfill(bit_size)
            else:
                component_solution["value"] = value.replace("?", "2")

    @staticmethod
    def _base_component_id(component_id):
        if component_id.endswith(("_i", "_o")):
            return component_id[:-2]
        return component_id

    def _collect_differential_linear_component_weights(self, components_values):
        p_weight = 0.0
        middle_sum = 0.0
        q_weight = 0.0
        seen_middle = set()
        seen_bottom = set()
        effective_bottom_component_ids = self._weight_bottom_component_ids()

        for component_id, component_solution in components_values.items():
            if not isinstance(component_solution, dict):
                continue

            weight = float(component_solution.get("weight", 0))
            base_component_id = self._base_component_id(component_id)

            if base_component_id in self.top_part_component_ids:
                p_weight += weight
                continue

            if base_component_id in self.middle_part_component_ids:
                if base_component_id not in seen_middle:
                    middle_sum += weight
                    seen_middle.add(base_component_id)
            elif base_component_id in effective_bottom_component_ids:
                if base_component_id not in seen_bottom:
                    q_weight += weight
                    seen_bottom.add(base_component_id)

        return p_weight, middle_sum, q_weight, bool(seen_middle)

    def _differential_linear_total_weight_from_components(self, components_values):
        p_weight, middle_sum, q_weight, has_middle_components = (
            self._collect_differential_linear_component_weights(components_values)
        )
        return round(p_weight + middle_sum + (2 * q_weight), 10)

    def _set_differential_linear_total_weight(self, solution):
        if not isinstance(solution, dict):
            return

        components_values = solution.get("components_values")
        if not isinstance(components_values, dict):
            return

        solution["total_weight"] = str(self._differential_linear_total_weight_from_components(components_values))

    def _parse_solver_output(
        self, output_to_parse, model_type, truncated=False, solve_external=False, solver_name=SOLVER_DEFAULT
    ):
        continuous_xor_differential_linear_model = self._is_continuous_middle() and model_type in (
            XOR_DIFFERENTIAL_LINEAR_ONE_SOLUTION,
            XOR_DIFFERENTIAL_LINEAR_OPTIMAL_SOLUTION,
        )

        parsed = super()._parse_solver_output(
            output_to_parse,
            model_type,
            truncated=truncated or continuous_xor_differential_linear_model,
            solve_external=solve_external,
            solver_name=solver_name,
        )

        if model_type not in (
            XOR_DIFFERENTIAL_LINEAR_ONE_SOLUTION,
            XOR_DIFFERENTIAL_LINEAR_OPTIMAL_SOLUTION,
        ):
            return parsed

        return self._process_differential_linear_parsed_output(parsed, solve_external, continuous_xor_differential_linear_model, output_to_parse=output_to_parse)

    def _process_differential_linear_parsed_output(self, parsed, solve_external, continuous_xor_differential_linear_model, output_to_parse=None):
        if not solve_external:
            if isinstance(parsed, list):
                for solution in parsed:
                    self._set_differential_linear_total_weight(solution)
                    if continuous_xor_differential_linear_model and output_to_parse is not None:
                        try:
                            # if output_to_parse is a Result list, this might be tricky, but usually it's just one Result
                            if hasattr(output_to_parse, "__getitem__"):
                                solution["differential_linear_correlation"] = float(output_to_parse["differential_linear_correlation"])
                                solution["correlation_log2_approximation"] = float(output_to_parse["correlation_log2_approximation"])
                        except Exception:
                            pass
                return parsed

            self._set_differential_linear_total_weight(parsed)
            if continuous_xor_differential_linear_model and output_to_parse is not None:
                try:
                    parsed["differential_linear_correlation"] = float(output_to_parse["differential_linear_correlation"])
                    parsed["correlation_log2_approximation"] = float(output_to_parse["correlation_log2_approximation"])
                except Exception:
                    pass
            return parsed

        if continuous_xor_differential_linear_model:
            solver_time, memory, components_values = parsed
        else:
            solver_time, memory, components_values, _ = parsed
            
        diff_lin_corrs = []
        log2_approxs = []
        if continuous_xor_differential_linear_model and output_to_parse is not None:
            lines = output_to_parse if isinstance(output_to_parse, list) else (
                output_to_parse.splitlines() if isinstance(output_to_parse, str) else []
            )
            for line in lines:
                if isinstance(line, str):
                    if line.startswith("differential_linear_correlation ="):
                        try:
                            diff_lin_corrs.append(float(line.split("=", 1)[1].strip()))
                        except ValueError:
                            pass
                    elif line.startswith("correlation_log2_approximation ="):
                        try:
                            log2_approxs.append(float(line.split("=", 1)[1].strip()))
                        except ValueError:
                            pass

        total_weight = []
        solution_keys = sorted(
            components_values.keys(),
            key=lambda key: int(key.replace("solution", "")) if key.startswith("solution") else 0,
        )
        
        for i, solution_key in enumerate(solution_keys):
            solution_components_values = components_values.get(solution_key, {})
            total_weight.append(str(self._differential_linear_total_weight_from_components(solution_components_values)))
            if continuous_xor_differential_linear_model:
                if i < len(diff_lin_corrs):
                    solution_components_values["differential_linear_correlation"] = diff_lin_corrs[i]
                elif diff_lin_corrs:
                    solution_components_values["differential_linear_correlation"] = diff_lin_corrs[-1]
                
                if i < len(log2_approxs):
                    solution_components_values["correlation_log2_approximation"] = log2_approxs[i]
                elif log2_approxs:
                    solution_components_values["correlation_log2_approximation"] = log2_approxs[-1]
                    
        return solver_time, memory, components_values, total_weight

    def _ensure_components_values(self, solution):
        if not isinstance(solution, dict):
            return
        if solution.get("status") != "SATISFIABLE":
            return
        self._normalize_middle_part_components_values(solution)

    def get_fixed_variable_from_hex(self, component_id, hex_value, endianness="big"):
        if component_id in self._cipher.inputs:
            idx = list(self._cipher.inputs).index(component_id)
            bit_size = self._cipher.inputs_bit_size[idx]
        else:
            bit_size = self._cipher.component_from_id(component_id).output_bit_size

        if isinstance(hex_value, str) and hex_value.startswith("0x"):
            int_val = int(hex_value, 16)
        else:
            int_val = int(hex_value)

        return set_fixed_variables(
            component_id=component_id,
            constraint_type="equal",
            bit_positions=list(range(bit_size)),
            bit_values=integer_to_bit_list(int_val, bit_size, endianness),
        )

    def build_xor_differential_linear_model(self, weight=-1, fixed_variables=None, optimization_objective=None):
        if fixed_variables is None:
            fixed_variables = []

        self.initialise_model()

        # Include continuous predicates (continuous_modadd, continuous_xor, etc.)
        if self._is_continuous_middle():
            from claasp.cipher_modules.models.cp.minizinc_utils.mzn_continuous_predicates import (
                get_continuous_operations,
            )
            self._model_prefix.append(get_continuous_operations())

        model_entries = self._component_model_entries()
        fixed_constraints = self._partition_fixed_value_constraints(fixed_variables)

        self.build_generic_cp_model_from_dictionary(model_entries)
        self._model_constraints = fixed_constraints + self._model_constraints

        continuous_middle_constraints = []
        if self._is_continuous_middle():
            continuous_middle_constraints = self._continuous_middle_connecting_constraints()

        probability_array_declaration = self._probability_array_declaration_from_component_map()

        middle_bottom_constraints = self._middle_to_bottom_connecting_constraints()
        branch_constraints = self._branch_xor_linear_constraints_for_bottom_part()

        weight_declarations, weight_constraints = self._build_weight_constraints(weight)

        declarations = self._state_declarations() + self._variables_declarations
        if probability_array_declaration is not None:
            declarations.append(probability_array_declaration)
        declarations.extend(weight_declarations)

        self._variables_declarations = declarations

        self._model_constraints.extend(continuous_middle_constraints)
        self._model_constraints.extend(middle_bottom_constraints)
        self._model_constraints.extend(branch_constraints)
        self._model_constraints.extend(weight_constraints)
        output_block = self._build_output_block(weight)
        if optimization_objective:
            output_block[0] = optimization_objective

        self._model_constraints.extend(output_block)

    def find_one_differential_linear_trail_with_fixed_weight(
        self,
        weight,
        fixed_values=None,
        solver_name=SOLVER_DEFAULT,
        num_of_processors=None,
        timelimit=None,
        solve_external=False,
        optimization_objective=None,
    ):
        if fixed_values is None:
            fixed_values = []

        start = tm.time()
        self.build_xor_differential_linear_model(weight=weight, fixed_variables=fixed_values, optimization_objective=optimization_objective)
        build_time = tm.time() - start

        solution = self.solve(
            XOR_DIFFERENTIAL_LINEAR_ONE_SOLUTION,
            solver_name=solver_name,
            timeout_in_seconds_=timelimit,
            processes_=num_of_processors,
            solve_external=solve_external,
        )
        if isinstance(solution, list):
            for partial_solution in solution:
                partial_solution["model_type"] = XOR_DIFFERENTIAL_LINEAR_ONE_SOLUTION
                self._normalize_total_weight(partial_solution)
                self._ensure_components_values(partial_solution)
                partial_solution["building_time_seconds"] = build_time
                partial_solution["test_name"] = "find_one_differential_linear_trail_with_fixed_weight"
            if len(solution) == 1:
                return solution[0]
            return solution

        solution["model_type"] = XOR_DIFFERENTIAL_LINEAR_ONE_SOLUTION
        self._normalize_total_weight(solution)
        self._ensure_components_values(solution)
        solution["building_time_seconds"] = build_time
        solution["test_name"] = "find_one_differential_linear_trail_with_fixed_weight"

        return solution

    def find_optimal_weight_xor_differential_linear_trail(
        self,
        fixed_values=None,
        solver_name=SOLVER_DEFAULT,
        num_of_processors=None,
        timelimit=None,
        solve_external=False,
        include_non_optimal_solutions=False,
        optimization_objective=None,
    ):
        if fixed_values is None:
            fixed_values = []

        start = tm.time()
        self.build_xor_differential_linear_model(weight=-1, fixed_variables=fixed_values, optimization_objective=optimization_objective)
        build_time = tm.time() - start

        solution = self.solve(
            XOR_DIFFERENTIAL_LINEAR_OPTIMAL_SOLUTION,
            solver_name=solver_name,
            timeout_in_seconds_=timelimit,
            processes_=num_of_processors,
            solve_external=solve_external,
            intermediate_solutions_=include_non_optimal_solutions,

        )
        if isinstance(solution, list):
            for partial_solution in solution:
                partial_solution["model_type"] = XOR_DIFFERENTIAL_LINEAR_OPTIMAL_SOLUTION
                self._normalize_total_weight(partial_solution)
                self._ensure_components_values(partial_solution)
                partial_solution["building_time_seconds"] = build_time
                partial_solution["test_name"] = "find_optimal_weight_xor_differential_linear_trail"
            if len(solution) == 1:
                return solution[0]
            return solution

        solution["model_type"] = XOR_DIFFERENTIAL_LINEAR_OPTIMAL_SOLUTION
        self._normalize_total_weight(solution)
        self._ensure_components_values(solution)
        solution["building_time_seconds"] = build_time
        solution["test_name"] = "find_optimal_weight_xor_differential_linear_trail"

        return solution

    def fix_variables_value_xor_linear_constraints(self, fixed_variables=None):
        if fixed_variables is None:
            fixed_variables = []

        return MznXorLinearModel.fix_variables_value_xor_linear_constraints(self, fixed_variables)

    def _parse_solver_output(
        self, output_to_parse, model_type, truncated=False, solve_external=False, solver_name=SOLVER_DEFAULT
    ):
        result = super()._parse_solver_output(
            output_to_parse, model_type, truncated, solve_external, solver_name
        )
        if not solve_external:
            return result

        components_values = result[2]
        aux_vars = ["linear_border_mask", "linear_mask_times_diff_lin_output", "differential_linear_correlation"]
        solution_number = 1
        for string in output_to_parse:
            if "----------" in string:
                solution_number += 1
                continue
            for aux_var in aux_vars:
                prefix = f"{aux_var}="
                if string.startswith(prefix):
                    val = string[len(prefix):].strip().strip(";")
                    if val.startswith("[") and val.endswith("]"):
                        val = "".join(val[1:-1].split(", "))
                    if f"solution{solution_number}" not in components_values:
                        components_values[f"solution{solution_number}"] = {}
                    components_values[f"solution{solution_number}"][aux_var] = {"value": val, "weight": 0.0}
                elif string.startswith(f"{aux_var}_"):
                    val = string.split("=")[1].strip().strip(";")
                    if f"solution{solution_number}" not in components_values:
                        components_values[f"solution{solution_number}"] = {}
                    if aux_var not in components_values[f"solution{solution_number}"]:
                        components_values[f"solution{solution_number}"][aux_var] = {"value": "", "weight": 0.0}
                    components_values[f"solution{solution_number}"][aux_var]["value"] += val

        return result

    def get_linear_border_mask_as_int(self, component_id: str, linear_border_mask_str: str) -> int:
        """
        Reconstructs the linear input mask for a specific component at the boundary
        using the linear_border_mask array output from the solver.
        """
        mask_str = linear_border_mask_str.strip("[]")
        if not mask_str:
            return 0
            
        bool_vals = [x.strip().lower() == "true" for x in mask_str.split(",")]
        
        border_components = self._get_truncated_xor_differential_components_in_border()
        border_sources = self._collect_border_sources(border_components)
        ordered_sources = self._order_border_sources(border_sources)
        
        mask_int = 0
        for idx, (source_bit_expr, _) in enumerate(ordered_sources):
            comp_id, _, bit_index = self._parse_linear_bit_id(source_bit_expr)
            if comp_id == component_id and idx < len(bool_vals) and bool_vals[idx]:
                mask_int |= (1 << bit_index)
                
        return mask_int
