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

# solvers definition
CHOCO = "choco"
CHUFFED = "chuffed"
COIN_BC = "coin-bc"
CPLEX = "cplex"
FINDMUS = "findmus"
GLOBALIZER = "globalizer"
GUROBI = "gurobi"
SCIP = "scip"
CPSAT = "cp-sat"
XPRESS = "xpress"


SOLVER_DEFAULT = CHUFFED


CP_SOLVERS_INTERNAL = [
    {"solver_brand_name": "Choco", "solver_name": CHOCO},
    {"solver_brand_name": "Chuffed", "solver_name": CHUFFED},
    {"solver_brand_name": "COIN-BC", "solver_name": COIN_BC},
    {"solver_brand_name": "IBM ILOG CPLEX", "solver_name": CPLEX},
    {"solver_brand_name": "MiniZinc findMUS", "solver_name": FINDMUS},
    {"solver_brand_name": "MiniZinc Globalizer", "solver_name": GLOBALIZER},
    {"solver_brand_name": "Gurobi Optimizer", "solver_name": GUROBI},
    {"solver_brand_name": "SCIP", "solver_name": SCIP},
    {"solver_brand_name": "OR Tools", "solver_name": CPSAT},
    {"solver_brand_name": "FICO Xpress", "solver_name": XPRESS},
]


CP_SOLVERS_EXTERNAL = [
    {
        "solver_brand_name": "Chuffed",
        "solver_name": CHUFFED,  # keyword to call the solver
        "keywords": {
            "command": {
                "executable": ["minizinc"],
                "options": ["--input-from-stdin", "--solver-statistics"],
                "input_file": [],
                "output_file": [],
                "solver": ["--solver", CHUFFED],
                "format": ["executable", "options", "solver"],
            },
        },
    },
    {
        "solver_brand_name": "OR Tools",
        "solver_name": CPSAT,  # keyword to call the solver
        "keywords": {
            "command": {
                "executable": ["minizinc"],
                "options": ["--input-from-stdin", "--solver-statistics"],
                "input_file": [],
                "output_file": [],
                "solver": ["--solver", CPSAT],
                "format": ["executable", "options", "solver"],
            },
        },
    },
    {
        "solver_brand_name": "COIN-BC",
        "solver_name": COIN_BC,  # keyword to call the solver
        "keywords": {
            "command": {
                "executable": ["minizinc"],
                "options": ["--input-from-stdin", "--solver-statistics"],
                "input_file": [],
                "output_file": [],
                "solver": ["--solver", COIN_BC],
                "format": ["executable", "options", "solver"],
            },
        },
    },
    {
        "solver_brand_name": "Choco",
        "solver_name": CHOCO,  # keyword to call the solver
        "keywords": {
            "command": {
                "executable": ["--input-from-stdin", "minizinc"],
                "options": ["--solver-statistics"],
                "input_file": [],
                "output_file": [],
                "solver": ["--solver", CHOCO],
                "format": ["executable", "options", "solver"],
            },
        },
    },
]
