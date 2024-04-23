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
"""SAT solvers

.. _Available SAT solvers:

Available SAT solvers
---------------------

In this file, all the available SAT solvers are listed. They can be divided in
two categories: internal and external.

Internal SAT solvers should be installed by default and no further action is
needed. For any other information on internal SAT solvers, visit `Abstract SAT
solver <https://doc.sagemath.org/html/en/reference/sat/sage/sat/solvers/satsolver.html>`_.

External SAT solvers need to be installed in the system as long as you want a
bare metal installation since they are called using a subprocess. If you use a
Docker container running the default image for the library no further action is
needed.
"""


SOLVER_DEFAULT = "CRYPTOMINISAT_EXT"


SAT_SOLVERS_INTERNAL = [
    {
        "solver_brand_name": "CryptoMiniSat SAT solver (using Sage backend)",
        "solver_name": "cryptominisat",
    },
    {
        "solver_brand_name": "PicoSAT (using Sage backend)",
        "solver_name": "picosat",
    },
    {
        "solver_brand_name": "Glucose SAT solver (using Sage backend)",
        "solver_name": "glucose",
    },
    {
        "solver_brand_name": "Glucose (Syrup) SAT solver (using Sage backend)",
        "solver_name": "glucose-syrup",
    },
]


SAT_SOLVERS_EXTERNAL = [
    {
        "solver_brand_name": "CaDiCal Simplified Satisfiability Solver",
        "solver_name": "CADICAL_EXT",
        "keywords": {
            "command": {
                "executable": "cadical",
                "options": [],
                "input_file": "",
                "solve": "",
                "output_file": "",
                "end": "",
                "format": ["executable", "options", "input_file"],
            },
            "time": "real time",
            "memory": "size of process",
            "is_dimacs_compliant": True,
            "unsat_condition": "s UNSATISFIABLE",
        },
    },
    {
        "solver_brand_name": "CryptoMiniSat SAT solver",
        "solver_name": "CRYPTOMINISAT_EXT",
        "keywords": {
            "command": {
                "executable": "cryptominisat5",
                "options": ["--verb=1"],
                "input_file": "",
                "solve": "",
                "output_file": "",
                "end": "",
                "format": ["executable", "options", "input_file"],
            },
            "time": "c Total time (this thread)",
            "memory": "c Max Memory (rss)",
            "is_dimacs_compliant": True,
            "unsat_condition": "s UNSATISFIABLE",
        },
    },
    {
        "solver_brand_name": "Glucose SAT solver",
        "solver_name": "GLUCOSE_EXT",
        "keywords": {
            "command": {
                "executable": "glucose",
                "options": ["-model"],
                "input_file": "",
                "solve": "",
                "output_file": "",
                "end": "",
                "format": ["executable", "options", "input_file"],
            },
            "time": "CPU time",
            "memory": None,
            "is_dimacs_compliant": True,
            "unsat_condition": "s UNSATISFIABLE",
        },
    },
    {
        "solver_brand_name": "Glucose (Syrup) SAT solver",
        "solver_name": "GLUCOSE_SYRUP_EXT",
        "keywords": {
            "command": {
                "executable": "glucose-syrup",
                "options": ["-model"],
                "input_file": "",
                "solve": "",
                "output_file": "",
                "end": "",
                "format": ["executable", "options", "input_file"],
            },
            "time": "cpu time",
            "memory": "Total Memory",
            "is_dimacs_compliant": True,
            "unsat_condition": "s UNSATISFIABLE",
        },
    },
    {
        "solver_brand_name": "The Kissat SAT solver",
        "solver_name": "KISSAT_EXT",
        "keywords": {
            "command": {
                "executable": "kissat",
                "options": [],
                "input_file": "",
                "solve": "",
                "output_file": "",
                "end": "",
                "format": ["executable", "options", "input_file"],
            },
            "time": "process-time",
            "memory": "maximum-resident-set-size",
            "is_dimacs_compliant": True,
            "unsat_condition": "s UNSATISFIABLE",
        },
    },
    {
        "solver_brand_name": "ParKissat-RS",
        "solver_name": "PARKISSAT_EXT",
        "keywords": {
            "command": {
                "executable": "parkissat",
                "options": ["-shr-sleep=500000", "-shr-lit=1500", "-initshuffle"],
                "input_file": "",
                "solve": "",
                "output_file": "",
                "end": "",
                "format": ["executable", "options", "input_file"],
            },
            "time": None,
            "memory": None,
            "is_dimacs_compliant": False,
            "unsat_condition": "s UNSATISFIABLE",
        },
    },
    {
        "solver_brand_name": "MathSAT",
        "solver_name": "MATHSAT_EXT",
        "keywords": {
            "command": {
                "executable": "mathsat",
                "options": ["-stats", "-model", "-input=dimacs"],
                "input_file": "",
                "solve": "",
                "output_file": "",
                "end": "",
                "format": ["executable", "options", "input_file"],
            },
            "time": "CPU Time",
            "memory": "Memory used",
            "is_dimacs_compliant": True,
            "unsat_condition": "s UNSATISFIABLE",
        },
    },
    {
        "solver_brand_name": "MiniSat",
        "solver_name": "MINISAT_EXT",
        "keywords": {
            "command": {
                "executable": "minisat",
                "options": [],
                "input_file": "",
                "solve": "",
                "output_file": "",
                "end": "",
                "format": ["executable", "options", "input_file", "output_file"],
            },
            "time": "CPU time",
            "memory": "Memory used",
            "is_dimacs_compliant": False,
            "unsat_condition": "UNSATISFIABLE",
        },
    },
    {
        "solver_brand_name": "Yices2",
        "solver_name": "YICES_SAT_EXT",
        "keywords": {
            "command": {
                "executable": "yices-sat",
                "options": ["--stats", "--model"],
                "input_file": "",
                "solve": "",
                "output_file": "",
                "end": "",
                "format": ["executable", "options", "input_file"],
            },
            "time": "Search time",
            "memory": "Memory used",
            "is_dimacs_compliant": False,
            "unsat_condition": "unsat",
        },
    },
]
