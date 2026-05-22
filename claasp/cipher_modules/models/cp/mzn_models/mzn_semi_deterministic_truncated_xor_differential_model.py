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

from minizinc import Status

from claasp.cipher_modules.models.cp.mzn_model import SOLVE_SATISFY, MznModel
from claasp.cipher_modules.models.cp.solvers import SOLVER_DEFAULT
from claasp.cipher_modules.models.utils import convert_solver_solution_to_dictionary
from claasp.name_mappings import (
    CIPHER_OUTPUT,
    CONSTANT,
    INTERMEDIATE_OUTPUT,
    PERMUTATION_COMPONENT,
    SEMI_DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_ONE_SOLUTION,
    SEMI_DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_OPTIMAL_SOLUTION,
    WORD_OPERATION,
)


class MznSemiDeterministicTruncatedXorDifferentialModel(MznModel):
    def __init__(self, cipher):
        super().__init__(cipher)

    def input_deterministic_truncated_xor_differential_constraints(self):
        cp_constraints = []
        cp_declarations = [
            f"array[0..{bit_size - 1}] of var 0..2: {input_};"
            for input_, bit_size in zip(self._cipher.inputs, self._cipher.inputs_bit_size)
        ]
        cipher = self._cipher
        for component in cipher.get_all_components():
            output_id_link = component.id
            output_size = int(component.output_bit_size)
            if CIPHER_OUTPUT in component.type:
                cp_declarations.append(f"array[0..{output_size - 1}] of var 0..2: {output_id_link};")
                cp_constraints.append(f"constraint count({output_id_link},2) < {output_size};")
            elif CONSTANT not in component.type:
                cp_declarations.append(f"array[0..{output_size - 1}] of var 0..2: {output_id_link};")

        return cp_declarations, cp_constraints

    @staticmethod
    def _allowed_component_and_operations():
        allowed_component_types = (CIPHER_OUTPUT, INTERMEDIATE_OUTPUT, WORD_OPERATION, CONSTANT, PERMUTATION_COMPONENT)
        allowed_operations = ("MODADD", "MODSUB", "XOR", "ROTATE", "SHIFT", "NOT")
        return allowed_component_types, allowed_operations

    def _build_component_and_model_types(self):
        component_and_model_types = []
        allowed_component_types, allowed_operations = self._allowed_component_and_operations()

        for component in self._cipher.get_all_components():
            operation = component.description[0]
            is_supported_word_op = component.type != WORD_OPERATION or operation in allowed_operations
            if component.type in allowed_component_types and is_supported_word_op:
                component_and_model_types.append(
                    {
                        "component_object": component,
                        "model_type": "cp_semi_deterministic_truncated_xor_differential_constraints",
                    }
                )
                continue

            raise NotImplementedError(
                f"Component {component.id} does not support CP semi-deterministic truncated XOR differential model"
            )

        return component_and_model_types

    def _build_fixed_constraints(self, fixed_variables, component_and_model_types):
        if not fixed_variables:
            return []

        if hasattr(self, "fix_variables_value_xor_linear_constraints"):
            return self.fix_variables_value_xor_linear_constraints(fixed_variables)

        uses_arx = any(
            entry["model_type"] == "minizinc_xor_differential_propagation_constraints"
            for entry in component_and_model_types
        )
        if uses_arx and hasattr(self, "solve_for_ARX"):
            return self.fix_variables_value_constraints_for_ARX(fixed_variables)

        return self.fix_variables_value_constraints(fixed_variables)

    def build_cp_semi_deterministic_truncated_xor_differential_trail(
        self, fixed_variables=None, number_of_rounds=None, minimize=False
    ):
        if fixed_variables is None:
            fixed_variables = []
        if number_of_rounds is None:
            number_of_rounds = self._cipher.number_of_rounds
        if number_of_rounds != self._cipher.number_of_rounds:
            raise ValueError("number_of_rounds must match the cipher instance number_of_rounds")

        self.initialise_model()
        input_declarations, input_constraints = self.input_deterministic_truncated_xor_differential_constraints()

        component_and_model_types = self._build_component_and_model_types()
        fixed_constraints = self._build_fixed_constraints(fixed_variables, component_and_model_types)

        self.build_generic_cp_model_from_dictionary(component_and_model_types, fixed_variables=fixed_variables)

        weight_var = "var int: weight;"
        if self.probability_vars:
            weight_constraint = f"constraint weight = sum([{', '.join(self.probability_vars)}]);"
        else:
            weight_constraint = "constraint weight = 0;"

        self._variables_declarations = input_declarations + self._variables_declarations + [weight_var]
        self._model_constraints = input_constraints + fixed_constraints + self._model_constraints

        self._model_constraints.append(weight_constraint)
        self.output_probability_per_round()
        self._model_constraints.extend(self._build_final_output_block(minimize))

    def _build_final_output_block(self, minimize):
        cipher_inputs = self._cipher.inputs
        cipher = self._cipher
        cp_constraints = []

        for component_id in cipher.get_all_components_ids():
            #at least one of the outputs bit difference should be active for the output cipher
            if "cipher_output" in component_id:
                cp_constraints.append(f"constraint count({component_id}, 1) > 0;")


        solve_directive = "solve minimize weight;" if (minimize and self.probability_vars) else SOLVE_SATISFY
        cp_constraints.append(solve_directive)

        new_constraint = "output["
        for element in cipher_inputs:
            new_constraint += f'"{element} = "++ show({element}) ++ "\\n" ++'
        for component_id in cipher.get_all_components_ids():
            new_constraint += f'"{component_id} = "++ show({component_id})++ "\\n" ++'
            probability_var = self.component_probability_var.get(component_id)
            if probability_var:
                new_constraint += f"show({probability_var}) ++ \"\\n\" ++"
            else:
                new_constraint += '"0" ++ "\\n" ++'
        new_constraint += '"Trail weight = " ++ show(weight)];'
        cp_constraints.append(new_constraint)

        cp_constraints.extend(self.mzn_output_directives)
        return cp_constraints

    def find_one_semi_deterministic_truncated_xor_differential_trail(
        self,
        fixed_values=None,
        solver_name=SOLVER_DEFAULT,
        num_of_processors=None,
        timelimit=None,
        random_seed=None,
        solve_external=False,
        intermediate_solutions=False,
    ):
        if fixed_values is None:
            fixed_values = []

        self.build_cp_semi_deterministic_truncated_xor_differential_trail(
            fixed_variables=fixed_values, minimize=False
        )
        return self.solve(
            SEMI_DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_ONE_SOLUTION,
            solver_name=solver_name,
            timeout_in_seconds_=timelimit,
            processes_=num_of_processors,
            random_seed_=random_seed,
            solve_external=solve_external,
            intermediate_solutions_=intermediate_solutions,
        )

    def find_optimal_cp_semi_deterministic_truncated_xor_differential_trail(
        self,
        fixed_values=None,
        solver_name=SOLVER_DEFAULT,
        num_of_processors=None,
        timelimit=None,
        random_seed=None,
        solve_external=False,
        include_non_optimal_solutions=False,
    ):
        if fixed_values is None:
            fixed_values = []

        self.build_cp_semi_deterministic_truncated_xor_differential_trail(
            fixed_variables=fixed_values, minimize=True
        )

        return self.solve(
            SEMI_DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_OPTIMAL_SOLUTION,
            solver_name=solver_name,
            timeout_in_seconds_=timelimit,
            processes_=num_of_processors,
            random_seed_=random_seed,
            solve_external=solve_external,
            intermediate_solutions_=include_non_optimal_solutions,
        )

    def add_solutions_from_components_values(
        self,
        components_values,
        memory,
        model_type,
        solutions,
        solve_time,
        solver_name,
        solver_output,
        _total_weight,
        solve_external=False,
    ):
        for solution_id, comp_values in components_values.items():
            computed_total_weight = sum(value.get("weight", 0) for value in comp_values.values())
            solution = convert_solver_solution_to_dictionary(
                self._cipher, model_type, solver_name, solve_time, memory, comp_values, str(computed_total_weight)
            )
            if solve_external:
                if "UNSATISFIABLE" in solver_output[0]:
                    solution["status"] = "UNSATISFIABLE"
                else:
                    solution["status"] = "SATISFIABLE"
            else:
                if solver_output.status not in [Status.SATISFIED, Status.ALL_SOLUTIONS, Status.OPTIMAL_SOLUTION]:
                    solution["status"] = "UNSATISFIABLE"
                else:
                    solution["status"] = "SATISFIABLE"
            solutions.append(solution)
