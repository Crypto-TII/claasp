from datetime import timedelta
import time
from minizinc import Instance, Model, Solver, Status
from claasp.cipher_modules.models.cp.mzn_model import MznModel
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_continuous_predicates import get_continuous_operations
from claasp.name_mappings import CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, WORD_OPERATION

class MznDifferentialLinearContinuousModel(MznModel):
    def __init__(self, cipher):
        super().__init__(cipher)
        self.added_component_ids = set()

    def fix_variables_value_constraints(self, fixed_variables=[]):
        constraints = []
        for entry in fixed_variables:
            comp_id = entry.get("component_id")
            positions = entry.get("bit_positions", [])
            values = entry.get("bit_values") if "bit_values" in entry else entry.get("value")
            
            if not comp_id or values is None:
                continue

            array_name = comp_id if comp_id in self._cipher.inputs else f"x1_{comp_id}"
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

        self.init_input_declarations()

        self._model_constraints.extend(self.connect_components())
        self._variables_list.extend([get_continuous_operations()])

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

    def find_continuous_correlations(self, fixed_values=[], solver_name="scip"):
        self.build_differential_linear_continuous_trail_model(fixed_values=fixed_values)
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
        
        for comp_id in sorted(self.added_component_ids):
            try:
                if comp_id in self._cipher.inputs:
                    val = result[comp_id]
                    if val is not None:
                        parsed["components_values"][comp_id] = {
                            "value": self._format_continuous_value(val),
                            "weight": 0
                        }
                
                elif comp_id.startswith(("intermediate_output_", "cipher_output_")):
                    output_val = result[comp_id]
                    if output_val is not None:
                        if comp_id.startswith("cipher_output_"):
                            parsed["components_values"][comp_id] = {
                                "value": self._format_continuous_value(output_val),
                                "weight": 0
                            }
                        elif comp_id.startswith("intermediate_output_") and self._cipher.number_of_rounds > 1:
                            formatted = self._format_continuous_value(output_val)
                            if len(formatted) == self._cipher.output_bit_size:
                                parsed["components_values"][comp_id] = {
                                    "value": formatted,
                                    "weight": 0
                                }
                
                elif comp_id.startswith(("rot_", "modadd_", "xor_")):
                    input_vars = []
                    for prefix in ["x1_", "x2_"]:
                        try:
                            input_vars.extend(result[f"{prefix}{comp_id}"])
                        except (KeyError, AttributeError):
                            pass
                    
                    if input_vars:
                        parsed["components_values"][f"{comp_id}_i"] = {
                            "value": self._format_continuous_value(input_vars),
                            "weight": 0
                        }
                    
                    output_val = result[comp_id]
                    if output_val is not None:
                        parsed["components_values"][f"{comp_id}_o"] = {
                            "value": self._format_continuous_value(output_val),
                            "weight": 0
                        }
                        
            except (KeyError, AttributeError):
                continue
        
        return parsed
        
    def _format_continuous_value(self, val):
        if isinstance(val, list):
            return [round(v, 6) for v in val]
        return val

    def solve_for_ARX(self, solver_name="scip", timeout_in_seconds_=30, processes_=4):
        constraints = self._model_constraints
        variables = self._variables_list
        mzn_model_string = "\n".join(constraints) + "\n".join(variables)
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