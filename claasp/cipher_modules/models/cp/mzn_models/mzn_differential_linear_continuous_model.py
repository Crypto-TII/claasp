from minizinc import Instance, Model, Solver, Status
from claasp.cipher_modules.models.cp.mzn_model import MznModel
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_continuous_predicates import get_continuous_operations
    
class MznDifferentialLinearContinuousModel(MznModel):
    def __init__(self, cipher):
        super().__init__(cipher)
        self.added_component_ids = set()
        self.excluded_component_ids = set()

    def fix_variables_value_constraints(self, fixed_variables=[]):
        constraints = []
        for entry in fixed_variables:
            comp_id = entry.get("component_id")
            positions = entry.get("bit_positions", [])
            values = entry.get("bit_values") if "bit_values" in entry else entry.get("value")
            
            if not comp_id or values is None: continue

            input_array_name = f"x1_{comp_id}"
            for pos, val in zip(positions, values):
                constraints.append(f"constraint {input_array_name}[{pos}] = {val};")
        return constraints

    def build_differential_linear_continuous_trail_model(self, fixed_values=[], exclude_components=[], custom_connections={}):
        component_and_model_types = []
        self.added_component_ids = set() 
        self.excluded_component_ids = set(exclude_components)
        
        supported = ["xor", "modadd", "rotate"]

        for component in self._cipher.get_all_components():
            if component.id in self.excluded_component_ids: continue
            if not hasattr(component, "description") or not component.description: continue

            desc = str(component.description[0]).lower()
            if any(op in desc for op in supported):
                component_and_model_types.append({
                    "component_object": component,
                    "model_type": "cp_continuous_differential_propagation_constraints"
                })
                self.added_component_ids.add(component.id)
        
        self.build_generic_cp_model_from_dictionary(
            component_and_model_types, 
            fixed_variables=fixed_values
        )
        
        self._model_constraints.extend(self.connect_components(custom_connections))

        self._variables_list.insert(0, get_continuous_operations())

    def connect_components(self, custom_connections={}):
        constraints = []
        for component in self._cipher.get_all_components():
            if component.id not in self.added_component_ids: continue

            for idx, link_id in enumerate(component.input_id_links):
                input_array = f"x{idx+1}_{component.id}"
                
                if input_array in custom_connections:
                    constraints.append(f"constraint {input_array} = {custom_connections[input_array]};")
                    continue 

                source_id = link_id
                while source_id in self.excluded_component_ids:
                    skipped_comp = self._cipher.get_component_from_id(source_id)
                    if not skipped_comp or not skipped_comp.input_id_links:
                        source_id = None; break
                    source_id = skipped_comp.input_id_links[0]
                
                if not source_id or source_id not in self.added_component_ids:
                    continue 
                
                constraints.append(f"constraint {input_array} = {source_id};")

        return constraints

    def find_continuous_correlations(self, fixed_values=[], exclude_components=[], custom_connections={}, solver_name="scip"):
        self.build_differential_linear_continuous_trail_model(
            fixed_values=fixed_values,
            exclude_components=exclude_components, 
            custom_connections=custom_connections
        )

        result = self.solve_for_ARX(solver_name=solver_name)

        return self._parse_result(result, solver_name)

    def _parse_result(self, result, solver_name):
        parsed = {"status": str(result.status), "solver": solver_name, "component_values": {}}
        
        if result.status in [Status.SATISFIED, Status.OPTIMAL_SOLUTION]:
            for comp_id in self.added_component_ids:
                try:
                    val = result[comp_id]
                    if isinstance(val, list):
                        parsed["component_values"][comp_id] = {"value": val, "type": "continuous_output"}
                except KeyError: pass
        return parsed