import os

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


SOLVER_DEFAULT = "GLPK"
MODEL_DEFAULT_PATH = os.getcwd()
SOLUTION_FILE_DEFAULT_NAME = "milp_model.sol"

def get_external_milp_solver_configuration(solution_name=SOLUTION_FILE_DEFAULT_NAME):

    external_milp_solvers_configuration = {
        'Gurobi': {
            'command': f'gurobi_cl ResultFile={MODEL_DEFAULT_PATH}/{solution_name} ',
            'options': "",
            'time': r"Explored \d+ nodes \(\d+ simplex iterations\) in ([0-9]*[.]?[0-9]+) seconds",
            'unsat_condition': "Model is infeasible"
        },
        'scip': {
            'file_path': [],
            'command': 'scip -c \"read ',
            'options': f' opt write solution {MODEL_DEFAULT_PATH}/{solution_name} quit\"',
            'time': r"Solving Time \(sec\)[\s]+:[\s]+([0-9]*[.]?[0-9]+)",
            'unsat_condition': "problem is solved [infeasible]"
        },
        'glpk': {
            'command': 'glpsol --lp ',
            'options': f' --output {MODEL_DEFAULT_PATH}/{solution_name}',
            'time': r"Time used:[\s]+([0-9]*[.]?[0-9]+) secs",
            'memory': r"Memory used:[\s]+([0-9]*[.]?[0-9]+) Mb",
            'unsat_condition': 'PROBLEM HAS NO PRIMAL FEASIBLE SOLUTION'
        },
        'cplex': {
            'command': 'cplex -c \"read ',
            'options': f'\" \"optimize\" \"display solution variables *\" | tee {MODEL_DEFAULT_PATH}/{solution_name}',
            'time': r"Solution time =[\s]+([0-9]*[.]?[0-9]+) sec.",
            'unsat_condition': "MIP - Integer infeasible."
        }
    }

    for solver in external_milp_solvers_configuration:
        external_milp_solvers_configuration[solver]['solution_path'] = f'{MODEL_DEFAULT_PATH}/{solution_name}'

    return external_milp_solvers_configuration
