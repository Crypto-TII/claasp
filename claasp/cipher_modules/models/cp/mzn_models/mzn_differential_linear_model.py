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

from claasp.cipher_modules.models.cp.mzn_model import MznModel, SOLVE_SATISFY
from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_linear_model import MznXorLinearModel
from claasp.cipher_modules.models.cp.solvers import SOLVER_DEFAULT
from claasp.cipher_modules.models.utils import get_bit_bindings
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
    """

    _ALLOWED_MIDDLE_MODELS = {
        "cp_deterministic_truncated_xor_differential_constraints",
        "cp_semi_deterministic_truncated_xor_differential_constraints",
        "cp_deterministic_truncated_xor_differential_trail_constraints",
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
    ):
        super().__init__(cipher)

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
        return self._cipher.get_component_from_id(component_id)

    def _parse_linear_bit_id(self, bit_id):
        match = re.match(r"^(.*)_([io])\[(\d+)\]$", bit_id)
        if not match:
            match = re.match(r"^(.*)\[(\d+)\]$", bit_id)
            if match:
                return match.group(1), None, int(match.group(2))
        if not match:
            raise ValueError(f"Invalid linear bit identifier: {bit_id}")
        return match.group(1), match.group(2), int(match.group(3))

    def _input_bit_size(self, input_id):
        for idx, cipher_input in enumerate(self._cipher.inputs):
            if cipher_input == input_id:
                return self._cipher.inputs_bit_size[idx]
        raise ValueError(f"Unknown cipher input: {input_id}")

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
        for input_name, bit_size in zip(self._cipher.inputs, self._cipher.inputs_bit_size):
            declarations.append(f"array[0..{bit_size - 1}] of var 0..1: {input_name};")

        for component in self._cipher.get_all_components():
            if component.type == CONSTANT:
                continue

            if component.id in self.middle_part_component_ids:
                domain = "0..2"
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
            component_obj = self.cipher.get_component_from_id(middle_component_id)
            for input_id in component_obj.input_id_links:
                if input_id in regular_component_ids:
                    border_components.append(input_id)

        return list(set(border_components))

    def _get_truncated_xor_differential_components_in_border(self):
        truncated_component_ids = set(self.middle_part_component_ids)
        border_components = []

        for linear_component_id in self.bottom_part_component_ids:
            component_obj = self.cipher.get_component_from_id(linear_component_id)
            for input_id in component_obj.input_id_links:
                if input_id in truncated_component_ids:
                    border_components.append(input_id)

        return list(set(border_components))

    def _top_to_middle_connecting_constraints(self):
        constraints = []
        border_components = set(self._get_regular_xor_differential_components_in_border())
        border_components.update(set(self._cipher.inputs))

        for output_bit_id, successor_bits in self.raw_bit_bindings.items():
            source_component_id, source_bit_index, source_side = output_bit_id
            if source_side != "o" or source_component_id not in border_components:
                continue

            source_bit_expr = f"{source_component_id}[{int(source_bit_index)}]"
            for successor_bit in successor_bits:
                successor_component_id, successor_bit_index, successor_side = successor_bit
                if (
                    successor_side != "i"
                    or successor_component_id not in self.middle_part_component_ids
                ):
                    continue

                successor_bit_expr = f"{successor_component_id}[{int(successor_bit_index)}]"
                constraints.append(
                    f"constraint {successor_bit_expr} = if {source_bit_expr} = 1 then 1 else 0 endif;"
                )

        return constraints

    def _middle_to_bottom_connecting_constraints(self):
        constraints = []
        truncated_border_components = set(self._get_truncated_xor_differential_components_in_border())

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

        top_probability_sum = _sum_component_probability(self.top_part_component_ids)
        middle_probability_sum = _sum_component_probability(effective_middle_component_ids)+"*100"
        bottom_probability_sum = _sum_component_probability(self.bottom_part_component_ids)

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

        output += '"Trail weight = " ++ show(weight)];'
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

        has_declaration = any(_is_probability_array_declaration(var) for var in self._variables_list)
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
        if "2" in value:
            component_solution["value"] = value
            return
        super().set_component_solution_value(component_solution, truncated, value)

    @staticmethod
    def _bits_to_hex_string(bits):
        bit_string = "".join(str(bit) for bit in bits)
        if not bit_string:
            return "0x0"
        as_int = int(bit_string, 2)
        hex_value = f"{as_int:x}"
        expected_len = math.ceil(len(bit_string) / 4)
        return "0x" + ("0" * (expected_len - len(hex_value))) + hex_value

    def _default_component_bits(self, component_id):
        if component_id in self._cipher.inputs:
            return [0] * self._input_bit_size(component_id)
        return [0] * self._get_component_by_id(component_id).output_bit_size

    def _fixed_bits_lookup(self, fixed_values):
        fixed_lookup = {}
        for fixed_value in fixed_values:
            component_id = fixed_value["component_id"]
            bits = self._default_component_bits(component_id)
            for bit_position, bit_value in zip(fixed_value["bit_positions"], fixed_value["bit_values"]):
                bits[bit_position] = bit_value
            fixed_lookup[component_id] = bits
        return fixed_lookup

    def _build_fallback_components_values(self, fixed_values):
        components_values = {}
        fixed_lookup = self._fixed_bits_lookup(fixed_values)

        all_component_ids = [*self._cipher.inputs, *self._cipher.get_all_components_ids()]
        for component_id in all_component_ids:
            bits = fixed_lookup.get(component_id, self._default_component_bits(component_id))
            if component_id in self.middle_part_component_ids:
                value = "".join(str(bit) for bit in bits)
            elif any(bit == 2 for bit in bits):
                value = "".join("2" if bit == 2 else str(bit) for bit in bits)
            else:
                value = self._bits_to_hex_string(bits)
            components_values[component_id] = {"value": value, "weight": 0}

        return components_values

    def _normalize_middle_part_components_values(self, solution):
        if not isinstance(solution, dict):
            return

        components_values = solution.get("components_values", {})
        if not isinstance(components_values, dict):
            return

        for component_id in self.middle_part_component_ids:
            component_solution = components_values.get(component_id)
            if not isinstance(component_solution, dict):
                continue

            value = component_solution.get("value")
            if not isinstance(value, str):
                continue

            if value.startswith("0x"):
                bit_size = self._get_component_by_id(component_id).output_bit_size
                component_solution["value"] = bin(int(value, 16))[2:].zfill(bit_size)
            else:
                component_solution["value"] = value.replace("?", "2")

    @staticmethod
    def _base_component_id(component_id):
        if component_id.endswith("_i") or component_id.endswith("_o"):
            return component_id[:-2]
        return component_id

    def _differential_linear_total_weight_from_components(self, components_values):
        p_weight = 0.0
        middle_sum = 0.0
        q_weight = 0.0
        seen_middle = set()
        seen_bottom = set()

        for component_id, component_solution in components_values.items():
            if not isinstance(component_solution, dict):
                continue

            weight = float(component_solution.get("weight", 0))
            base_component_id = self._base_component_id(component_id)

            if base_component_id in self.top_part_component_ids:
                p_weight += weight
            elif base_component_id in self.middle_part_component_ids:
                if base_component_id not in seen_middle:
                    middle_sum += weight
                    seen_middle.add(base_component_id)
            elif base_component_id in self.bottom_part_component_ids:
                if base_component_id not in seen_bottom:
                    q_weight += weight
                    seen_bottom.add(base_component_id)
        import math
        r_weight = math.log(2 * (2**middle_sum) - 1, 2) if seen_middle else 0.0
        return round(p_weight + r_weight + (2 * q_weight), 10)

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
        parsed = super()._parse_solver_output(
            output_to_parse,
            model_type,
            truncated=truncated,
            solve_external=solve_external,
            solver_name=solver_name,
        )

        if model_type not in (
            XOR_DIFFERENTIAL_LINEAR_ONE_SOLUTION,
            XOR_DIFFERENTIAL_LINEAR_OPTIMAL_SOLUTION,
        ):
            return parsed

        if not solve_external:
            if isinstance(parsed, list):
                for solution in parsed:
                    self._set_differential_linear_total_weight(solution)
                return parsed

            self._set_differential_linear_total_weight(parsed)
            return parsed

        if solve_external:
            solver_time, memory, components_values, _ = parsed
            total_weight = []
            solution_keys = sorted(
                components_values.keys(),
                key=lambda key: int(key.replace("solution", "")) if key.startswith("solution") else 0,
            )
            for solution_key in solution_keys:
                solution_components_values = components_values.get(solution_key, {})
                total_weight.append(str(self._differential_linear_total_weight_from_components(solution_components_values)))
            return solver_time, memory, components_values, total_weight

        return parsed

    def _ensure_components_values(self, solution, fixed_values):
        if not isinstance(solution, dict):
            return
        if solution.get("status") != "SATISFIABLE":
            return
        components_values = solution.get("components_values", {})
        if not components_values:
            solution["components_values"] = self._build_fallback_components_values(fixed_values)

        self._normalize_middle_part_components_values(solution)


    def build_xor_differential_linear_model(self, weight=-1, fixed_variables=None):
        if fixed_variables is None:
            fixed_variables = []

        self.initialise_model()
        model_entries = self._component_model_entries()
        fixed_constraints = self._partition_fixed_value_constraints(fixed_variables)

        self.build_generic_cp_model_from_dictionary(model_entries)
        self._model_constraints = fixed_constraints + self._model_constraints

        probability_array_declaration = self._probability_array_declaration_from_component_map()

        middle_bottom_constraints = self._middle_to_bottom_connecting_constraints()
        branch_constraints = self._branch_xor_linear_constraints_for_bottom_part()

        weight_declarations, weight_constraints = self._build_weight_constraints(weight)

        declarations = self._state_declarations() + self._variables_list
        if probability_array_declaration is not None:
            declarations.append(probability_array_declaration)
        declarations.extend(weight_declarations)

        self._variables_list = declarations

        self._model_constraints.extend(middle_bottom_constraints)
        self._model_constraints.extend(branch_constraints)
        self._model_constraints.extend(weight_constraints)
        self._model_constraints.extend(self._build_output_block(weight))

        self._model_constraints = self._model_prefix + self._model_constraints

    def find_one_differential_linear_trail_with_fixed_weight(
        self,
        weight,
        fixed_values=None,
        solver_name=SOLVER_DEFAULT,
        num_of_processors=None,
        timelimit=None,
        solve_external=False,
    ):
        if fixed_values is None:
            fixed_values = []

        start = tm.time()
        self.build_xor_differential_linear_model(weight=weight, fixed_variables=fixed_values)
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
                self._ensure_components_values(partial_solution, fixed_values)
                partial_solution["building_time_seconds"] = build_time
                partial_solution["test_name"] = "find_one_differential_linear_trail_with_fixed_weight"
            if len(solution) == 1:
                return solution[0]
            return solution

        solution["model_type"] = XOR_DIFFERENTIAL_LINEAR_ONE_SOLUTION
        self._normalize_total_weight(solution)
        self._ensure_components_values(solution, fixed_values)
        solution["building_time_seconds"] = build_time
        solution["test_name"] = "find_one_differential_linear_trail_with_fixed_weight"

        return solution

    def find_lowest_weight_xor_differential_linear_trail(
        self,
        fixed_values=None,
        solver_name=SOLVER_DEFAULT,
        num_of_processors=None,
        timelimit=None,
        solve_external=False,
    ):
        if fixed_values is None:
            fixed_values = []

        start = tm.time()
        self.build_xor_differential_linear_model(weight=-1, fixed_variables=fixed_values)
        build_time = tm.time() - start

        solution = self.solve(
            XOR_DIFFERENTIAL_LINEAR_OPTIMAL_SOLUTION,
            solver_name=solver_name,
            timeout_in_seconds_=timelimit,
            processes_=num_of_processors,
            solve_external=solve_external,
        )
        if isinstance(solution, list):
            for partial_solution in solution:
                partial_solution["model_type"] = XOR_DIFFERENTIAL_LINEAR_OPTIMAL_SOLUTION
                self._normalize_total_weight(partial_solution)
                self._ensure_components_values(partial_solution, fixed_values)
                partial_solution["building_time_seconds"] = build_time
                partial_solution["test_name"] = "find_lowest_weight_xor_differential_linear_trail"
            if len(solution) == 1:
                return solution[0]
            return solution

        solution["model_type"] = XOR_DIFFERENTIAL_LINEAR_OPTIMAL_SOLUTION
        self._normalize_total_weight(solution)
        self._ensure_components_values(solution, fixed_values)
        solution["building_time_seconds"] = build_time
        solution["test_name"] = "find_lowest_weight_xor_differential_linear_trail"

        return solution

    def fix_variables_value_xor_linear_constraints(self, fixed_variables=None):
        if fixed_variables is None:
            fixed_variables = []

        return MznXorLinearModel.fix_variables_value_xor_linear_constraints(self, fixed_variables)
