
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

import re, os

from claasp.cipher_modules.models.milp.utils.config import EXTERNAL_MILP_SOLVERS, MODEL_DEFAULT_PATH, \
    SOLUTION_FILE_DEFAULT_NAME
from sage.numerical.mip import MIPSolverException


def _write_model_to_lp_file(model, model_type):
    mip = model._model
    model_file_path = os.path.join(MODEL_DEFAULT_PATH, f"{model.cipher_id}_{model_type}.lp")
    mip.write_lp(model_file_path)

    return model_file_path

def _get_data(data_keywords, lines):
    data_line = re.search(data_keywords, lines, re.DOTALL)
    if data_line is None:
        raise MIPSolverException("Solver seems installed but license file might be missing.")
    data = float(re.findall(data_keywords, data_line.group(0))[0])
    return data

def _get_variables_value(internal_variables, read_file):
    variables_value = {}
    for key in internal_variables.keys():
        index = int(re.search(r'\d+', str(internal_variables[key])).group()) + 1
        match = re.search(r'[xyz]_%s[\s]+[\*]?[\s]*([0-9]*[.]?[0-9]+)' % index, read_file)
        variables_value[key] = float(match.group(1)) if match else 0.0
    return variables_value

def _parse_external_solver_output(model, solver_name, solver_process):
    solver_specs = EXTERNAL_MILP_SOLVERS[solver_name]

    solve_time = _get_data(solver_specs['time'], str(solver_process))

    probability_variables = {}
    components_variables = {}
    status = 'UNSATISFIABLE'
    total_weight = None

    if solver_specs['unsat_condition'] not in str(solver_process):
        status = 'SATISFIABLE'

        solution_file_path = os.path.join(MODEL_DEFAULT_PATH, SOLUTION_FILE_DEFAULT_NAME)

        with open(solution_file_path, 'r') as lp_file:
            read_file = lp_file.read()

        components_variables = _get_variables_value(model.binary_variable, read_file)
        probability_variables = _get_variables_value(model.integer_variable, read_file)

        total_weight = probability_variables["probability"] / 10.

    return status, total_weight, probability_variables, components_variables, solve_time