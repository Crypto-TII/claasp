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



MILP_SOLVERS_INTERNAL = [
    {"solver_brand_name": "GLPK (GNU Linear Programming Kit) (using Sage backend)", "solver_name": "GLPK"},
    {"solver_brand_name": "GLPK (GNU Linear Programming Kit) with simplex method based on exact arithmetic (using Sage backend)", "solver_name": "GLPK/exact"},
    {"solver_brand_name": "COIN-BC (COIN Branch and Cut) (using Sage backend)", "solver_name": "Coin"},
    {"solver_brand_name": "CVXOPT (Python Software for Convex Optimization) (using Sage backend)", "solver_name": "CVXOPT"},
    {"solver_brand_name": "Gurobi Optimizer (using Sage backend)", "solver_name": "Gurobi"},
    {"solver_brand_name": "PPL (Parma Polyhedra Library) (using Sage backend)", "solver_name": "PPL"},
    {"solver_brand_name": "InteractiveLP (using Sage backend)", "solver_name": "InteractiveLP"},
]

MILP_SOLVERS_EXTERNAL = [
    {
        "solver_brand_name": "Gurobi Optimizer (external)",
        "solver_name": "GUROBI_EXT",
        "keywords": {
            "command": {
                "executable": "gurobi_cl",
                "options": [],
                "input_file": "",
                "solve": "",
                "output_file": "ResultFile=",
                "end": "",
                "format": ["executable", "output_file", "input_file"],
            },
            "time": r"Explored \d+ nodes \(\d+ simplex iterations\) in ([0-9]*[.]?[0-9]+) seconds",
            "unsat_condition": "Model is infeasible",
        },
    },
    {
        "solver_brand_name": "GLPK (GNU Linear Programming Kit) (external)",
        "solver_name": "GLPK_EXT",
        "keywords": {
            "command": {
                "executable": "glpsol",
                "options": ["--lp"],
                "input_file": "",
                "solve": "",
                "output_file": "--output ",
                "end": "",
                "format": ["executable", "options", "input_file", "output_file"],
            },
            "time": r"Time used:[\s]+([0-9]*[.]?[0-9]+) secs",
            "memory": r"Memory used:[\s]+([0-9]*[.]?[0-9]+) Mb",
            "unsat_condition": r"PROBLEM HAS NO (\w+) FEASIBLE SOLUTION",
        },
    },
    {
        "solver_brand_name": "SCIP (Solving Constraint Integer Programs) (external)",
        "solver_name": "SCIP_EXT",
        "keywords": {
            "command": {
                "executable": "scip",
                "options": ["-c", '"'],
                "input_file": "read",
                "solve": "optimize",
                "output_file": "write solution",
                "end": '"quit',
                "format": [
                    "executable",
                    "options",
                    "input_file",
                    "solve",
                    "output_file",
                    "end",
                ],
            },
            "time": r"Solving Time \(sec\)[\s]+:[\s]+([0-9]*[.]?[0-9]+)",
            "unsat_condition": r"problem is solved \[infeasible\]",
        },
    },
    {
        "solver_brand_name": "IBM ILOG CPLEX Optimizer (external)",
        "solver_name": "CPLEX_EXT",
        "keywords": {
            "command": {
                "executable": "cplex",
                "options": ["-c"],
                "input_file": "read",
                "solve": "optimize",
                "output_file": "set logfile",
                "end": "display solution variables -",
                "format": [
                    "executable",
                    "options",
                    "input_file",
                    "solve",
                    "output_file",
                    "end",
                ],
            },
            "time": r"Solution time =[\s]+([0-9]*[.]?[0-9]+) sec.",
            "unsat_condition": "MIP - Integer infeasible.",
        },
    },
    {
        "solver_brand_name": "HiGHS (external)",
        "solver_name": "HIGHS_EXT",
        "keywords": {
            "command": {
                "executable": "highs",
                "options": [],
                "input_file": "--model_file",
                "solve": "",
                "output_file": "--solution_file",
                "end": "",
                "format": ["executable", "output_file", "input_file"],
            },
            "time": r"[\s]+Timing [\s]+([0-9]*[.]?[0-9]+) \(total\)",
            "unsat_condition": "[\s]+Status[\s]+Infeasible",
        },
    },
]
