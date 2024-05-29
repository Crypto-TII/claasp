
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


import pickle
from sympy import symbols, And, Not, to_cnf, Equivalent, Xor
from joblib import Parallel, delayed
import os

def save_list(data, filename):
    """Save a list to a file using pickle."""
    try:
        with open(filename, 'wb') as file:
            pickle.dump(data, file, protocol=pickle.HIGHEST_PROTOCOL)
        print(f"List successfully saved to {filename}")
    except Exception as e:
        print(f"Error saving list: {e}")

def load_list(filename):
    """Load a list from a file using pickle."""
    try:
        with open(filename, 'rb') as file:
            return pickle.load(file)
    except Exception as e:
        print(f"Error loading list: {e}")
        return None

def generating_n_window_clauses(window_size_plus_one):
    def compute_ex(i):
        return Xor(first_diff_addend_vars[i], second_diff_addend_vars[i], output_diff_vars[i])



    filename = f"{window_size_plus_one-1}-window_size_list_of_clauses.pkl"
    if os.path.exists(filename):
        return load_list(filename)


    # Define your variables
    first_diff_addend_vars = symbols('a[:{}]'.format(window_size_plus_one))
    second_diff_addend_vars = symbols('b[:{}]'.format(window_size_plus_one))
    output_diff_vars = symbols('c[:{}]'.format(window_size_plus_one))
    temp_var = symbols('aux')

    if window_size_plus_one == 1:
        ex = Not(
            Xor(
                first_diff_addend_vars[window_size_plus_one - 1],
                second_diff_addend_vars[window_size_plus_one - 1],
                output_diff_vars[window_size_plus_one - 1]
            )
        )
    else:
        results = Parallel(n_jobs=-1)(delayed(compute_ex)(i) for i in range(window_size_plus_one - 1))
        ex2 = Equivalent(And(*results), temp_var)
        ex1 = And(
            temp_var, Xor(
                first_diff_addend_vars[window_size_plus_one - 1],
                second_diff_addend_vars[window_size_plus_one - 1],
                output_diff_vars[window_size_plus_one - 1]
            )
        )
        ex = And(Not(ex1), ex2)

    final_cnf = to_cnf(ex, simplify=True, force=True)
    clauses = convert_clauses(str(final_cnf))
    save_list(clauses, filename)
    return clauses


def convert_clauses(clauses):
    import re

    clean_clauses = re.sub(r'[{}()\s]', '', clauses)

    clause_list = clean_clauses.split('&')

    formatted_clauses = []

    for clause in clause_list:
        literals = clause.split('|')
        pos_vars = []
        neg_vars = []

        for literal in literals:
            if literal.startswith('~'):
                neg_vars.append(literal[1:])
            else:
                pos_vars.append(literal)

        pos_vars.sort()
        neg_vars.sort()

        formatted_clause = f"f'"
        formatted_clause += f"   ".join(f"{{{var}}}" for var in pos_vars)
        formatted_clause += f"   " if pos_vars and neg_vars else ""
        formatted_clause += "   ".join(f"-{{{var}}}" for var in neg_vars)
        formatted_clause += f"'"

        formatted_clauses.append(formatted_clause)

    return formatted_clauses

def generate_window_size_clauses(first_input_difference, second_input_difference, output_difference, aux_var):
    """
    Returns a set of clauses representing a simplified CNF (Conjunctive Normal Form) expression 
    for the n-window size heuristic applied to a + b = c. Specifically, these clauses ensure that no more than n variables
    are true (i.e., there are no sequences of n+1 ones in the carry differences of a + b = c). These clauses were obtained after simplifying
    the formula below (in sympy notation):
    formula_temp = Equivalent(And(*[Xor(A[i], B[i], C[i]) for i in range(n - 1)]), aux);
    formula = And(Not(And(aux, Xor(A[n - 1], B[n - 1], C[n - 1]))), formula_temp).
    The variable aux is used to store the conjunctions of the carries of the addition of the n - 1 bits of A and B.
    aux will serve as a variable to allow users to perform a global count on the number of full n-window sequences.

    INPUT:

    - ``a`` -- **list**: List of binary variables representing the input differences a
    - ``b`` -- **list**: List of binary variables representing the input differences b
    - ``c`` -- **list**: List of binary variables representing the input differences c
    - ``aux`` -- **integer**: Auxiliary variable used to store the conjunctions of the carry differences from the addition of the first n - 1 bit differences of a and b

    EXAMPLES:
    ::
        sage: a = [1, 2, 3, 4]
        sage: b = [5, 6, 7, 8]
        sage: c = [9, 10, 11, 12]
        sage: aux = 10
        sage: cnf = window_size_3_cnf(a, b, c, aux)
        sage: cnf
        ['4   -4   -10', '8   -10   -8']
    """
    window_size_plus_one = len(first_input_difference)

    context = {
        'a': first_input_difference,
        'b': second_input_difference,
        'c': output_difference,
        'aux': aux_var
    }

    new_clauses = []
    string_generated_clauses = generating_n_window_clauses(window_size_plus_one)
    for clause in string_generated_clauses:
        new_clauses.append(eval(clause, context))
    return new_clauses
