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
"""SMT solvers

.. _Available SMT solvers:

Available SMT solvers
---------------------

In this file, all the available SMT solvers are listed. They are only external.

External SMT solvers need to be installed in the system as long as you want a
bare metal installation since they are called using a subprocess. If you use a
Docker container running the default image for the library no further action is
needed.
"""

# external solvers definition
MATHSAT_EXT = "MATHSAT_EXT"
YICES_EXT = "YICES_EXT"
Z3_EXT = "Z3_EXT"

SOLVER_DEFAULT = Z3_EXT


SMT_SOLVERS_INTERNAL = []


SMT_SOLVERS_EXTERNAL = [
    {
        "solver_brand_name": "MathSAT 5",
        "solver_name": MATHSAT_EXT,
        "keywords": {
            "command": {
                "executable": "mathsat",
                "options": ["-model", "-stats"],
                "input_file": "",
                "solve": "",
                "output_file": "",
                "end": "",
                "format": ["executable", "options", "input_file"],
            },
            "time": "time-seconds",
            "memory": "memory-mb",
            "unsat_condition": "unsat",
        },
    },
    {
        "solver_brand_name": "Yices2",
        "solver_name": YICES_EXT,
        "keywords": {
            "command": {
                "executable": "yices-smt2",
                "options": ["--stats"],
                "input_file": "",
                "solve": "",
                "output_file": "",
                "end": "",
                "format": ["executable", "options", "input_file"],
            },
            "time": "total-run-time",
            "memory": "mem-usage",
            "unsat_condition": "unsat",
        },
    },
    {
        "solver_brand_name": "Z3 Theorem Prover",
        "solver_name": Z3_EXT,
        "keywords": {
            "command": {
                "executable": "z3",
                "options": ["-st", "-in"],
                "input_file": "",
                "solve": "",
                "output_file": "",
                "end": "",
                "format": ["executable", "options", "input_file"],
            },
            "time": "total-time",
            "memory": "memory",
            "unsat_condition": "unsat",
        },
    },
]
