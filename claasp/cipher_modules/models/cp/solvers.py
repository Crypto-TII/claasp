
# ****************************************************************************

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

import os

SOLVER_DEFAULT = 'Chuffed'
MODEL_DEFAULT_PATH = os.getcwd()

CP_SOLVERS_INTERNAL = []

CP_SOLVERS_EXTERNAL = [
    {
        'solver_brand_name': 'Chuffed',
        'solver_name': 'Chuffed', # keyword to call the solver  
        'keywords': {
            'command': {
                'executable': ['minizinc'],
                'options': ['--solver-statistics'],
                'input_file': [],
                'output_file': [],
                'solver': ['--solver', 'Chuffed'],
                'format': ['executable', 'options', 'solver', 'input_file', 'output_file'],
            },
        },
    },
    {
        'solver_brand_name': 'Gecode',
        'solver_name': 'Gecode', # keyword to call the solver  
        'keywords': {
            'command': {
                'executable': ['minizinc'],
                'options': ['--solver-statistics'],
                'input_file': [],
                'output_file': [],
                'solver': ['--solver', 'Gecode'],
                'format': ['executable', 'options', 'solver', 'input_file', 'output_file'],
            },
        },    
    },
    {
        'solver_brand_name': 'OR Tools',
        'solver_name': 'Xor', # keyword to call the solver   
        'keywords': {
            'command': {
                'executable': ['minizinc'],
                'options': ['--solver-statistics'],
                'input_file': [],
                'output_file': [],
                'solver': ['--solver', 'Xor'],
                'format': ['executable', 'options', 'solver', 'input_file', 'output_file'],
            },
        },   
    },
    {
        'solver_brand_name': 'COIN-BC',
        'solver_name': 'COIN-BC', # keyword to call the solver   
        'keywords': {
            'command': {
                'executable': ['minizinc'],
                'options': ['--solver-statistics'],
                'input_file': [],
                'output_file': [],
                'solver': ['--solver', 'COIN-BC'],
                'format': ['executable', 'options', 'solver', 'input_file', 'output_file'],
            },
        },   
    },
    {
        'solver_brand_name': 'Choco',
        'solver_name': 'choco', # keyword to call the solver    
        'keywords': {
            'command': {
                'executable': ['minizinc'],
                'options': ['--solver-statistics'],
                'input_file': [],
                'output_file': [],
                'solver': ['--solver', 'choco'],
                'format': ['executable', 'options', 'solver', 'input_file', 'output_file'],
            },
        },   
    },
]
