
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


"""Handler for MILP constraints of Cipher.

The target of this module is to find different kind of trails associated to a cryptanalysis technique by using MILP,
e.g. the search for XOR differential trails.

This module is able to use many different MILP solvers.
For any further information, refer to the file
:py:mod:`claasp.cipher_modules.models.milp.solvers.py` and to the section
:ref:`Available MILP solvers`.

The default choice is GLPK.

"""
import os
import subprocess
import time
import tracemalloc

from sage.numerical.mip import MixedIntegerLinearProgram, MIPSolverException

from claasp.cipher_modules.models.milp.solvers import SOLVER_DEFAULT, MODEL_DEFAULT_PATH, MILP_SOLVERS_EXTERNAL, \
    MILP_SOLVERS_INTERNAL
from claasp.cipher_modules.models.milp.utils.utils import _get_data, _parse_external_solver_output, _write_model_to_lp_file
from claasp.cipher_modules.models.utils import convert_solver_solution_to_dictionary

def get_independent_input_output_variables(component):
    """
    Return a list of 2 lists containing the name of each input/output bit.

    The bit in position 0 of those lists corresponds to the MSB.

    INPUT:

    - ``component`` -- **Component object**; component in cipher

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.cipher_modules.models.milp.milp_model import get_independent_input_output_variables
        sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
        sage: component = speck.get_component_from_id("xor_1_10")
        sage: l = get_independent_input_output_variables(component)
        sage: l[0]
         ['xor_1_10_0_i',
         'xor_1_10_1_i',
         ...
         'xor_1_10_30_i',
         'xor_1_10_31_i']
        sage: l[1]
        ['xor_1_10_0_o',
         'xor_1_10_1_o',
         ...
         'xor_1_10_14_o',
         'xor_1_10_15_o']
    """
    input_vars = [f"{component.id}_{i}_i" for i in range(component.input_bit_size)]
    output_vars = [f"{component.id}_{i}_o" for i in range(component.output_bit_size)]

    return input_vars, output_vars


def get_input_output_variables(component):
    """
    Return a list of 2 lists containing the name of each input/output bit.

    The bit in position 0 of those lists corresponds to the MSB.

    INPUT:

    - ``component`` -- **Component object**; component in cipher

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.cipher_modules.models.milp.milp_model import get_input_output_variables
        sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
        sage: component = speck.get_component_from_id("rot_0_0")
        sage: l = get_input_output_variables(component)
        sage: l[0]
        ['plaintext_0',
        'plaintext_1',
        'plaintext_2',
        ...
        'plaintext_13',
        'plaintext_14',
        'plaintext_15']
        sage: l[1]
        ['rot_0_0_0',
        'rot_0_0_1',
        'rot_0_0_2',
        ...
        'rot_0_0_13',
        'rot_0_0_14',
        'rot_0_0_15']
    """
    output_vars = [f"{component.id}_{i}" for i in range(component.output_bit_size)]
    input_vars = []
    for index, link in enumerate(component.input_id_links):
        input_vars.extend([f"{link}_{pos}" for pos in component.input_bit_positions[index]])

    return input_vars, output_vars


class MilpModel:
    """Build MILP models for ciphers using Cipher."""

    def __init__(self, cipher, n_window_heuristic=None, verbose=False):
        self._cipher = cipher
        self._variables_list = []
        self._model_constraints = []
        self._model = None
        self._binary_variable = None
        self._integer_variable = None
        self.n_window_heuristic = n_window_heuristic
        self._non_linear_component_id = []
        self._intermediate_output_names = []
        self._number_of_trails_found = 0
        self._verbose_print = print if verbose else lambda *a, **k: None

    def fix_variables_value_constraints(self, fixed_variables=[]):
        """
        Return a list of constraints that fix the input variables to a specific value.

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in standard
          format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: simon = SimonBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpModel(simon)
            sage: milp.init_model_in_sage_milp_class()
            sage: fixed_variables = [{
            ....:    'component_id': 'plaintext',
            ....:    'constraint_type': 'equal',
            ....:    'bit_positions': [0, 1, 2, 3],
            ....:    'bit_values': [1, 0, 1, 1]
            ....: }, {
            ....:    'component_id': 'cipher_output_1_8',
            ....:    'constraint_type': 'not_equal',
            ....:    'bit_positions': [0, 1, 2, 3],
            ....:    'bit_values': [1, 1, 1, 0]
            ....: }]
            sage: constraints = milp.fix_variables_value_constraints(fixed_variables)
            sage: constraints
            [x_0 == 1,
             x_1 == 0,
             x_2 == 1,
             x_3 == 1,
             x_4 == 1 - x_5,
             x_6 == 1 - x_7,
             x_8 == 1 - x_9,
             x_10 == x_11,
             1 <= x_4 + x_6 + x_8 + x_10]
        """
        x = self._binary_variable
        constraints = []
        for fixed_variable in fixed_variables:
            component_id = fixed_variable["component_id"]
            if fixed_variable["constraint_type"] == "equal":
                for index, bit_position in enumerate(fixed_variable["bit_positions"]):
                    constraints.append(x[f"{component_id}_{bit_position}"] == fixed_variable["bit_values"][index])
            else:
                for index, bit_position in enumerate(fixed_variable["bit_positions"]):
                    if fixed_variable["bit_values"][index]:
                        constraints.append(x[f"{component_id}{bit_position}_not_equal_{self._number_of_trails_found}"]
                                           == 1 - x[f"{component_id}_{bit_position}"])
                    else:
                        constraints.append(x[f"{component_id}{bit_position}_not_equal_{self._number_of_trails_found}"]
                                           == x[f"{component_id}_{bit_position}"])
                constraints.append(sum(x[f"{component_id}{i}_not_equal_{self._number_of_trails_found}"]
                                       for i in fixed_variable["bit_positions"]) >= 1)

        return constraints

    def weight_constraints(self, weight):
        """
        Return a list of variables and a list of constraints that fix the total weight to a specific value.

        INPUT:

        - ``weight`` -- **integer**; the total weight. If negative, no constraints on the weight is added

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: simon = SimonBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpModel(simon)
            sage: milp.init_model_in_sage_milp_class()
            sage: variables, constraints = milp.weight_constraints(10)
            sage: variables
            [('p[probability]', x_0)]
            sage: constraints
            [x_0 == 100]
        """
        p = self._integer_variable
        variables = []
        constraints = []

        if weight >= 0:
            constraints.append(p["probability"] == 10 * weight)
            variables = [("p[probability]", p["probability"])]
        elif weight != -1:
            self._model.set_max(p["probability"], - 10 * weight)
            variables = [("p[probability]", p["probability"])]

        return variables, constraints

    def init_model_in_sage_milp_class(self, solver_name=SOLVER_DEFAULT):
        """
        Initialize a MILP instance from the build-in sage class.

        INPUT:

        - ``solver_name`` -- **string**; the solver to call

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp._model
            Mixed Integer Program (no objective, 0 variables, 0 constraints)
        """
        if solver_name.upper().endswith("_EXT"):
            solver_name = SOLVER_DEFAULT
        self._model = MixedIntegerLinearProgram(maximization=False, solver=solver_name)
        self._binary_variable = self._model.new_variable(binary=True)
        self._integer_variable = self._model.new_variable(integer=True)
        self._non_linear_component_id = []

    def _solve_with_external_solver(self, model_type, model_path, solver_name=SOLVER_DEFAULT):


        solver_specs = [specs for specs in MILP_SOLVERS_EXTERNAL if specs["solver_name"] == solver_name.upper()][0]
        solution_file_path = f'{MODEL_DEFAULT_PATH}/{model_path[:-3]}.sol'

        command = ""
        for key in solver_specs['keywords']['command']['format']:
            parameter = solver_specs['keywords']['command'][key]
            if key == "input_file":
                parameter += " " + model_path
            elif key == "output_file":
                parameter = parameter + solution_file_path if parameter.endswith('=') else parameter + " " + solution_file_path
            elif key == "options":
                parameter = " ".join(parameter)
            command += " " + parameter
        tracemalloc.start()
        solver_process = subprocess.run(command, capture_output=True, shell=True, text=True)
        milp_memory = tracemalloc.get_traced_memory()[1] / 10 ** 6
        tracemalloc.stop()

        if solver_process.stderr:
            raise MIPSolverException("Make sure that the solver is correctly installed.")

        if 'memory' in solver_specs:
            milp_memory = _get_data(solver_specs['keywords']['memory'], str(solver_process))

        return _parse_external_solver_output(self, solver_specs, model_type, solution_file_path, solver_process.stdout) + (milp_memory,)

    def _solve_with_internal_solver(self):

        mip = self._model
        status = 'UNSATISFIABLE'
        self._verbose_print("Solving model in progress ...")
        time_start = time.time()
        tracemalloc.start()
        try:
            mip.solve()
            status = 'SATISFIABLE'

        except MIPSolverException as milp_exception:
            print(milp_exception)
        finally:
            milp_memory = tracemalloc.get_traced_memory()[1] / 10 ** 6
            tracemalloc.stop()
            time_end = time.time()
            milp_time = time_end - time_start
            self._verbose_print(f"Time for solving the model = {milp_time}")

        return status, milp_time, milp_memory

    def solve(self, model_type, solver_name=SOLVER_DEFAULT, external_solver_name=None):
        """
        Return the solution of the model.

        INPUT:

        - ``model_type`` -- **string**; the model to solve
        - ``solver_name`` -- **string** (default: `GLPK`); the solver to call when building the internal Sagemath MILP model. If no external solver is specified, ``solver_name`` will also be used to solve the model.
        - ``external_solver_name`` -- **string** (default: None); if specified, the library will write the internal Sagemath MILP model as a .lp file and solve it outside of Sagemath, using the external solver.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=4)
            sage: milp = MilpXorDifferentialModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp.add_constraints_to_build_in_sage_milp_class()
            ...
            sage: solution = milp.solve("xor_differential") # random
        """
        if external_solver_name or (solver_name.upper().endswith("_EXT")):
            solver_choice = external_solver_name or solver_name
            if solver_choice.upper() not in [specs["solver_name"] for specs in MILP_SOLVERS_EXTERNAL]:
                raise ValueError(f"Invalid solver name: {solver_choice}.\n"
                                 f"Please select a solver in the following list: {[specs['solver_name'] for specs in MILP_SOLVERS_EXTERNAL]}.")

            solver_name_in_solution = solver_choice
            model_path = _write_model_to_lp_file(self, model_type)
            solution_file_path, status, objective_value, components_values, milp_time, milp_memory = self._solve_with_external_solver(
                model_type, model_path, solver_choice)
            os.remove(model_path)
            os.remove(f"{solution_file_path}")
        else:
            objective_value = None
            components_values = None
            solver_name_in_solution = solver_name
            status, milp_time, milp_memory = self._solve_with_internal_solver()
            if status == 'SATISFIABLE':
                objective_value, components_values = self._parse_solver_output()

        solution = convert_solver_solution_to_dictionary(self._cipher, model_type, solver_name_in_solution, milp_time,
                                                         milp_memory, components_values, objective_value)
        solution['status'] = status
        return solution

    def solver_names(self, verbose=False):
        solver_names = []

        keys = ['solver_brand_name', 'solver_name']
        for solver in MILP_SOLVERS_INTERNAL:
            solver_names.append({key: solver[key] for key in keys})
        if verbose:
            keys = ['solver_brand_name', 'solver_name', 'keywords']

        for solver in MILP_SOLVERS_EXTERNAL:
            solver_names.append({key: solver[key] for key in keys})
        return solver_names

    @property
    def binary_variable(self):
        return self._binary_variable

    @property
    def cipher(self):
        return self._cipher

    @property
    def cipher_id(self):
        return self._cipher.id

    @property
    def integer_variable(self):
        return self._integer_variable

    @property
    def intermediate_output_names(self):
        return self._intermediate_output_names

    @property
    def model(self):
        return self._model

    @property
    def model_constraints(self):
        """
        Return the model specified by ``model_type``.

        INPUT:

        - ``model_type`` -- **string**; the model to retrieve

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: speck = SpeckBlockCipher(number_of_rounds=4)
            sage: milp = MilpModel(speck)
            sage: milp.model_constraints
            Traceback (most recent call last):
            ...
            ValueError: No model generated
        """
        if not self._model_constraints:
            raise ValueError('No model generated')
        return self._model_constraints

    @property
    def non_linear_component_id(self):
        return self._non_linear_component_id
