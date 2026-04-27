from datetime import timedelta
import math
import time
from minizinc import Instance, Model, Solver, Status
from claasp.cipher_modules.models.cp.mzn_model import MznModel
from claasp.cipher_modules.models.cp.minizinc_utils.predicate_registry import CONTINUOUS_DIFFERENTIAL_LINEAR
from claasp.name_mappings import CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, WORD_OPERATION

class MznDifferentialLinearContinuousModel(MznModel):
    def __init__(self, cipher):
        super().__init__(cipher)
        self.added_component_ids = set()

    def fix_variables_value_constraints(self, fixed_variables=[]):
        constraints = []
        for entry in fixed_variables:
            component_id = entry.get("component_id")
            positions = entry.get("bit_positions", [])
            values = entry.get("bit_values") if "bit_values" in entry else entry.get("value")

            array_name = component_id if component_id in self._cipher.inputs else f"x1_{component_id}"
            constraints.extend([
                f"constraint {array_name}[{pos}] = {val};" 
                for pos, val in zip(positions, values)
            ])
        return constraints

    def build_differential_linear_continuous_trail_model(self, fixed_values=[]):
        component_and_model_types = []
        self.added_component_ids = set() 
        operation_types = ["MODADD", "ROTATE", "XOR"]
        component_types = [CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, WORD_OPERATION]

        fixed_constraints = []
        if fixed_values:
            if hasattr(self, "fix_variables_value_xor_linear_constraints"):
                fixed_constraints = self.fix_variables_value_xor_linear_constraints(fixed_values)
            elif any(
                entry["model_type"] == "minizinc_xor_differential_propagation_constraints"
                for entry in component_and_model_types
            ) and hasattr(self, "solve_for_ARX"):
                fixed_constraints = self.fix_variables_value_constraints_for_ARX(fixed_values)
            else:
                fixed_constraints = self.fix_variables_value_constraints(fixed_values)
        
        for component in self._cipher.get_all_components():
            operation = component.description[0]
            if component.type not in component_types or (
                WORD_OPERATION == component.type and operation not in operation_types
            ):
                print(f"{component.id} not yet implemented")
            else:
                component_and_model_types.append({
                    "component_object": component,
                    "model_type": "cp_continuous_differential_propagation_constraints"
                })
                self.added_component_ids.add(component.id)

        self.build_generic_cp_model_from_dictionary(
            component_and_model_types, 
            fixed_variables=fixed_values
        )

        # Ensure fixed-value constraints are explicitly included even when
        # generic model builder does not prepend them.
        self._model_constraints = fixed_constraints + self._model_constraints

        self.init_input_declarations()

        self._model_constraints.extend(self.connect_components())
        self.add_linear_mask_variables()
        self.finalize_model(model_contexts=(CONTINUOUS_DIFFERENTIAL_LINEAR,))
        self._variables_list = self._model_prefix + self._variables_list
        
    def add_linear_mask_variables(self):
        block_size = self._cipher.output_bit_size
        output_mask = (
            f"array[0..{block_size - 1}] of var 0..1: output_mask;"
        )
        self._variables_list.append(output_mask)

    def init_input_declarations(self):
        input_declarations = [
            f"array[0..{size - 1}] of var -1.0..1.0: {name};"
            for name, size in zip(self._cipher.inputs, self._cipher.inputs_bit_size)
        ]
        self._variables_list.extend(input_declarations)

    def connect_components(self):
        constraints = []
        for component in self._cipher.get_all_components():
            for idx, link_id in enumerate(component.input_id_links):
                input_array = f"x{idx+1}_{component.id}"
                
                if link_id in self._cipher.inputs:
                    source_positions = component.input_bit_positions[idx]
                    for bit_idx, source_bit_pos in enumerate(source_positions):
                        constraints.append(
                            f"constraint {input_array}[{bit_idx}] = {link_id}[{source_bit_pos}];"
                        )
                elif link_id in self.added_component_ids:
                    constraints.append(f"constraint {input_array} = {link_id};")
        return constraints

    def find_one_continuous_correlations(self, fixed_values=[], solver_name="scip"):
        self.build_differential_linear_continuous_trail_model(fixed_values=fixed_values)
        result = self.solve_for_ARX(solver_name=solver_name)
        return self._parse_result(result, solver_name)

    def _get_cipher_output_id(self):
        for component in self._cipher.get_all_components():
            if component.type == CIPHER_OUTPUT:
                return component.id
        raise ValueError("cipher_output component not found")
    
    def _build_linear_mask_correlation_constraints(self):
        block_size = self._cipher.output_bit_size
        cipher_output_id = self._get_cipher_output_id()

        active_bit_correlations_entries = ", ".join([
            f"if output_mask[{i}] = 0 then 1.0 "
            f"else output_mask[{i}] * abs({cipher_output_id}[{i}]) endif"
            for i in range(block_size)
        ])

        active_bit_correlations_decl = (
            f"array[0..{block_size - 1}] of var lower..upper: active_bit_correlations = "
            f"array1d(0..{block_size - 1}, [{active_bit_correlations_entries}]);"
        )
        self._variables_list.append(active_bit_correlations_decl)
    
    def _build_difflin_corr_constraints(self):
        self._variables_list.append("var lower..upper: differential_linear_correlation;")
        self._variables_list.append("var float: correlation_log2_approximation;")

        self._model_constraints.append(
            "constraint differential_linear_correlation = product(active_bit_correlations);"
        )
        self._model_constraints.append(
            "constraint differential_linear_correlation != 0.0;"
        )
        self._model_constraints.append(
            "constraint sum(array1d(output_mask)) >= 1;"
        )
        self._model_constraints.append("""
        constraint correlation_log2_approximation =
        if differential_linear_correlation <= 0.001021453702391378 then
        -19931.57001201849*differential_linear_correlation+29.89737278555626
        elseif differential_linear_correlation <= 0.004151650554233785 /\\ differential_linear_correlation > 0.001021453702391378 then
        -584.962260272084*differential_linear_correlation+10.13570866882117
        elseif differential_linear_correlation <= 0.01359667098324998 /\\ differential_linear_correlation > 0.004151650554233785 then
        -192.6450521799878*differential_linear_correlation+8.506944714410169
        elseif differential_linear_correlation <= 0.05399137458004444 /\\ differential_linear_correlation > 0.01359667098324998 then
        -50.62607129324977*differential_linear_correlation+6.575959357916722
        elseif differential_linear_correlation <= 0.1420480516058986 /\\ differential_linear_correlation > 0.05399137458004444 then
        -11.87410019056137*differential_linear_correlation+4.483687170396419
        elseif differential_linear_correlation <= 0.2463455066216964 /\\ differential_linear_correlation > 0.1420480516058986 then
        -8.613130253286352*differential_linear_correlation+4.020472744461092
        elseif differential_linear_correlation <= 0.595815289564374 /\\ differential_linear_correlation > 0.2463455066216964 then
        -3.761918786389538*differential_linear_correlation+2.825398597919413
        elseif differential_linear_correlation <= 0.998000001 /\\ differential_linear_correlation > 0.595815289564374 then
        -1.444862453710759*differential_linear_correlation+1.44486100812744
        else
        1=1
        endif;
        """)

    def find_lowest_continuous_correlation(self, fixed_values=[], solver_name="scip"):
        self.build_differential_linear_continuous_trail_model(fixed_values=fixed_values)
        self._build_linear_mask_correlation_constraints()
        self._build_difflin_corr_constraints()
        cipher_output_id = self._get_cipher_output_id()
        self._model_constraints.append(
            f"solve :: float_search({cipher_output_id}, 1e-12, smallest, indomain_min, complete) "
            "minimize correlation_log2_approximation;"
        )

        result = self.solve_for_ARX(solver_name=solver_name)
        return self._parse_result(result, solver_name)

    def _parse_result(self, result, solver_name):

        parsed = {
            "cipher": self.cipher_id,
            "model_type": "continuous_differential",
            "solver_name": solver_name,
            "solving_time_seconds": getattr(self, '_last_solve_time', -1),
            "memory_megabytes": str(self._last_result_stats.get('trailMem', '-1'))
                if hasattr(self, '_last_result_stats') else '-1',
            "components_values": {},
            "status": str(result.status)
        }

        if result.status not in [Status.SATISFIED, Status.OPTIMAL_SOLUTION]:
            return parsed

        for component_id in sorted(self.added_component_ids):
            try:
                if component_id in self._cipher.inputs:
                    val = result[component_id]
                    if val is not None:
                        parsed["components_values"][component_id] = {
                            "value": self._format_continuous_value(val),
                            "weight": 0
                        }

                elif component_id.startswith(("intermediate_output_", "cipher_output_")):
                    output_val = result[component_id]
                    if output_val is not None:
                        if component_id.startswith("cipher_output_"):
                            parsed["components_values"][component_id] = {
                                "value": self._format_continuous_value(output_val),
                                "weight": 0
                            }
                        elif component_id.startswith("intermediate_output_") and self._cipher.number_of_rounds > 1:
                            formatted = self._format_continuous_value(output_val)
                            if len(formatted) == self._cipher.output_bit_size:
                                parsed["components_values"][component_id] = {
                                    "value": formatted,
                                    "weight": 0
                                }

                elif component_id.startswith(("rot_", "modadd_", "xor_")):
                    input_vars = []
                    for prefix in ["x1_", "x2_"]:
                        try:
                            input_vars.extend(result[f"{prefix}{component_id}"])
                        except (KeyError, AttributeError):
                            pass

                    if input_vars:
                        parsed["components_values"][f"{component_id}_i"] = {
                            "value": self._format_continuous_value(input_vars),
                            "weight": 0
                        }

                    output_val = result[component_id]
                    if output_val is not None:
                        parsed["components_values"][f"{component_id}_o"] = {
                            "value": self._format_continuous_value(output_val),
                            "weight": 0
                        }

            except (KeyError, AttributeError):
                continue

        self._parse_difflin_fields(result, parsed)

        return parsed

    def _parse_difflin_fields(self, result, parsed):

        for field in ["differential_linear_correlation", "correlation_log2_approximation"]:
            try:
                parsed[field] = float(result[field])
            except (KeyError, AttributeError, TypeError):
                pass

        try:
            corr = float(result["differential_linear_correlation"])
            if not math.isclose(corr, 0.0, abs_tol=1e-9):
                parsed["correlation_log2_absolute_value"] = -math.log2(abs(corr))
        except (KeyError, AttributeError, TypeError, ValueError):
            pass

        try:
            parsed["output_mask"] = list(result["output_mask"])
        except (KeyError, AttributeError, TypeError):
            pass
        
    def _format_continuous_value(self, val):
        if isinstance(val, list):
            return [round(v, 6) for v in val]
        return val

    def solve_for_ARX(self, solver_name="scip", timeout_in_seconds_=30, processes_=4):
        constraints = self._model_constraints
        variables = self._variables_list
        mzn_model_string =  "\n".join(variables) + "\n".join(constraints) 
        solver_name_mzn = Solver.lookup(solver_name)
        bit_mzn_model = Model()
        bit_mzn_model.add_string(mzn_model_string)
        instance = Instance(solver_name_mzn, bit_mzn_model)
        
        start = time.time()
        result = instance.solve(
            processes=processes_,
            timeout=timedelta(seconds=int(timeout_in_seconds_))
        )
        end = time.time()
        
        self._last_solve_time = end - start
        self._last_result_stats = result.statistics if hasattr(result, 'statistics') else {}
        
        return result
