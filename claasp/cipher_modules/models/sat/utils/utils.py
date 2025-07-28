
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


"""
Utilities for SAT model.

General
-------



Direct building of CNFs representing boolean equalities
-------------------------------------------------------

Building a CNF representing a generic boolean equality can be time consuming.
This module offers functions to directly build the CNF of basic boolean
equalities. It also offers function to directly build CNFs for the
Lipmaa-Moriai algorithm which is a cornerstone when searching XOR differential
trails.

Every function returns a list of strings representing clauses whose
satisfiability is equivalent to the equality they represent.

Running SAT solver
------------------

:py:class:`Sat Model <cipher_modules.models.sat.sat_model>` allows to use many SAT solvers like CryptoMiniSat,
Glucose, Minisat and others. Unfortunately, some of them do not take input from
stdin and need an input file. Functions of this section supply the best running
method for SAT solvers in :py:class:`Sat Model <cipher_modules.models.sat.sat_model>`.

"""
import itertools
import os
import re
import subprocess
import time

from claasp.cipher_modules.models.sat import solvers


# ----------------- #
#    - General -    #
# ----------------- #


def cms_add_clauses_to_solver(numerical_cnf, solver):
    """
    Add clauses to the (internal) SAT solver.

    It needs to be overwritten in this class because it must handle the XOR clauses.
    """
    for clause in numerical_cnf:
        if clause.startswith('x '):
            rhs = bool(1 ^ (clause.count('-') % 2))
            literals = clause.replace('-', '').split()[1:]
            solver.add_xor_clause([int(literal) for literal in literals], rhs)
        else:
            solver.add_clause([int(literal) for literal in clause.split()])


def create_numerical_cnf(cnf: list[str]) -> tuple[list[str], list[str]]:
    # creating dictionary (variable -> string, numeric_id -> int)
    variables = ' '.join(cnf).replace('-', '').replace('x ', ' ')
    variables = sorted(set(variables.split()))
    variable_to_number = {variable: i + 1 for i, variable in enumerate(variables)}
    # creating numerical CNF
    numerical_cnf = []
    for clause in cnf:
        literals = clause.split()
        numerical_literals = []
        if literals[0] == 'x':
            literals = literals[1:]
            numerical_literals = ['x']
        signs = (literal[0] == '-' for literal in literals)
        numerical_literals.extend(
            [f'{"-" * sign}{variable_to_number[literal[sign:]]}' for sign, literal in zip(signs, literals)]
        )
        numerical_cnf.append(' '.join(numerical_literals))

    return variables, numerical_cnf


def numerical_cnf_to_dimacs(variables: list[str], numerical_cnf: list[str]) -> str:
    dimacs = [f'p cnf {len(variables)} {len(numerical_cnf)}']
    dimacs.extend(f'{numerical_clause} 0' for numerical_clause in numerical_cnf)
    dimacs = "\n".join(dimacs)

    return dimacs


def cnf_n_window_heuristic_on_w_vars(hw_bit_ids):
    cnf_constraint_lst = [f'-{hw_bit}' for hw_bit in hw_bit_ids]

    return [' '.join(cnf_constraint_lst)]


# ----------------------------------------------------------------- #
#    - Direct building of CNFs representing boolean equalities -    #
# ----------------------------------------------------------------- #


def cnf_equivalent(variables):
    """
    Return a list of strings.

    Representing the CNF of the equivalence of Boolean variables ``variable_0 = variable_1 = ... = variable_2``.

    INPUT:

    - ``variables`` -- **list**; the variables that must be equivalent

    EXAMPLES::

        sage: from claasp.cipher_modules.models.sat.utils.utils import cnf_equivalent
        sage: cnf_equivalent(['a', 'b'])
        ['a -b', 'b -a']
    """
    variables_shifted = [variables[-1]] + variables[:-1]

    return [f'{variables[i]} -{variables_shifted[i]}' for i in range(len(variables))]


def cnf_inequality(left_var, right_var):
    """
    Return a list of strings representing the CNF of the Boolean equality ``left_var = Not(right_var)``.

    INPUT:

    - ``left_var`` -- **string**; the left side variable
    - ``right_var`` -- **string**; the right side variable

    EXAMPLES::

        sage: from claasp.cipher_modules.models.sat.utils.utils import cnf_inequality
        sage: cnf_inequality('a', 'b')
        ('a b', '-a -b')
    """
    return (f'{left_var} {right_var}', f'-{left_var} -{right_var}')


def cnf_and(result, variables):
    """
    Return a list of strings.

    Representing the CNF of the Boolean equality ``result = And(variable_0, variable_1, ..., variable_{n-1})``.

    INPUT:

    - ``result`` -- **string**; the variable for the result
    - ``variables`` -- **list**; the list of variables which are operands

    EXAMPLES::

        sage: from claasp.cipher_modules.models.sat.utils.utils import cnf_and
        sage: cnf_and('r', ['a', 'b', 'c'])
        ['-r a', '-r b', '-r c', 'r -a -b -c']
    """
    cnf = [f'-{result} {variable}' for variable in variables]
    cnf.append(f'{result} -{" -".join(variables)}')

    return cnf


def cnf_and_seq(out_ids, in_ids):
    cnf = cnf_and(out_ids[0], (in_ids[0], in_ids[1]))
    for i in range(1, len(out_ids)):
        cnf.extend(cnf_and(out_ids[i], (out_ids[i - 1], in_ids[i + 1])))

    return cnf


def cnf_or(result, variables):
    """
    Return a list of strings.

    Representing the CNF of the Boolean equality ``result = Or(variable_0, variable_1, ..., variable_{n-1})``.

    INPUT:

    - ``result`` -- **string**; the variable for the result
    - ``variables`` -- **list**; the list of variables which are operands

    EXAMPLES::

        sage: from claasp.cipher_modules.models.sat.utils.utils import cnf_or
        sage: cnf_or('r', ['a', 'b', 'c'])
        ['r -a', 'r -b', 'r -c', '-r a b c']
    """
    model = [f'{result} -{variable}' for variable in variables]
    model.append(f'-{result} {" ".join(variables)}')

    return model


def cnf_or_seq(out_ids, in_ids):
    cnf = cnf_or(out_ids[0], (in_ids[0], in_ids[1]))
    for i in range(1, len(out_ids)):
        cnf.extend(cnf_or(out_ids[i], (out_ids[i - 1], in_ids[i + 1])))

    return cnf


def cnf_xor(result, variables):
    """
    Return a list of strings.

    Representing the CNF of the Boolean equality ``result = Xor(variable_0, variable_1, ..., variable_{n-1})``.

    INPUT:

    - ``result`` -- **string**; the variable for the result
    - ``variables`` -- **list**; the variables

    EXAMPLES::

        sage: from claasp.cipher_modules.models.sat.utils.utils import cnf_xor
        sage: cnf_xor('r', ['a', 'b', 'c'])
        ['-r a b c',
         'r -a b c',
         'r a -b c',
         'r a b -c',
         '-r -a -b c',
         '-r -a b -c',
         '-r a -b -c',
         'r -a -b -c']
    """
    model = []
    operands = [result] + variables
    num_of_operands = len(operands)
    for i in range(1, num_of_operands + 1, 2):
        subsets = tuple(itertools.combinations(range(num_of_operands), i))
        for s in subsets:
            literals = ['-' * (j in s) + f'{operands[j]}' for j in range(num_of_operands)]
            model.append(' '.join(literals))

    return model


def cnf_xor_seq(results, variables):
    """
    Return a list of strings.

    Representing the CNF of the Boolean equality ``result = Xor(variable_0, variable_1, ..., variables_n)`` with ``n``
    at least 3. Note that ``results[:-1]`` are intermediate results and ``results[-1]`` must be the string identifying
    the whole ``result``.

    INPUT:

    - ``results`` -- **list**; the results
    - ``variables`` -- **list**; the variables

    EXAMPLES::

        sage: from claasp.cipher_modules.models.sat.utils.utils import cnf_xor_seq
        sage: cnf_xor_seq(['i_0', 'i_1', 'r_7'], ['a_7', 'b_7', 'c_7', 'd_7'])
        ['-i_0 a_7 b_7',
         'i_0 -a_7 b_7',
         'i_0 a_7 -b_7',
         ...
         'r_7 -i_1 d_7',
         'r_7 i_1 -d_7',
         '-r_7 -i_1 -d_7']
    """
    model = cnf_xor(results[0], [variables[0], variables[1]])
    for i in range(1, len(results)):
        model.extend(cnf_xor(results[i], [results[i - 1], variables[i + 1]]))

    return model


def cnf_carry(carry, x, y, previous_carry):
    """
    Return a tuple of strings.

    Representing the CNF of the Boolean equality ``carry = Or(And(x, y), And(x, previous_carry),
    And(y, previous_carry))``. It represents the general form of a carry when performing modular addition between two
    bitvectors.

    INPUT:

    - ``carry`` -- **string**; the carry to be comuted (current carry)
    - ``x`` -- **string**; the bit of the first addendum
    - ``y`` -- **string**; the bit of the second addendum
    - ``previous_carry`` -- **string**; the previous carry

    EXAMPLES::

        sage: from claasp.cipher_modules.models.sat.utils.utils import cnf_carry
        sage: cnf_carry('c_3', 'x_3', 'y_3', 'c_2')
        ('x_3 y_3 -c_3',
         '-x_3 -y_3 c_3',
         'x_3 c_2 -c_3',
         '-x_3 -c_2 c_3',
         'y_3 c_2 -c_3',
         '-y_3 -c_2 c_3')
    """
    return (f'{x} {y} -{carry}',
            f'-{x} -{y} {carry}',
            f'{x} {previous_carry} -{carry}',
            f'-{x} -{previous_carry} {carry}',
            f'{y} {previous_carry} -{carry}',
            f'-{y} -{previous_carry} {carry}')


def cnf_carry_comp2(carry, x, previous_carry):
    """
    Return a tuple of strings.

    Representing the CNF of the Boolean equality ``carry = And(Not(x), previous_carry)``. It represents the general
    form of a carry when performing modular addition between the notwise of a vector and 1.

    INPUT:

    - ``carry`` -- **string**; the carry to be comuted (current carry)
    - ``x`` -- **string**; the bit of the input addendum
    - ``previous_carry`` -- **string**; the previous carry

    EXAMPLES::

        sage: from claasp.cipher_modules.models.sat.utils.utils import cnf_carry_comp2
        sage: cnf_carry_comp2('c_3', 'x_2', 'c_2')
        ('-c_3 c_2', '-c_3 -x_2', 'c_3 -c_2 x_2')
    """
    return (f'-{carry} {previous_carry}',
            f'-{carry} -{x}',
            f'{carry} -{previous_carry} {x}')


def cnf_result_comp2(result, x, carry):
    """
    Return a tuple of strings representing the CNF of the Boolean equality ``result = Xor(Not(x), carry)``.

    It represents the general form of a result when performing modular addition between the notwise of a vector and 1.

    INPUT:

    - ``result`` -- **string**; the result to be comuted
    - ``x`` -- **string**; the bit of the input addendum
    - ``carry`` -- **string**; the carry

    EXAMPLES::

        sage: from claasp.cipher_modules.models.sat.utils.utils import cnf_result_comp2
        sage: cnf_result_comp2('r_3', 'x_3', 'c_3')
        ('c_3 -r_3 -x_3', '-c_3 r_3 -x_3', '-c_3 -r_3 x_3', 'c_3 r_3 x_3')
    """
    return (f'{carry} -{result} -{x}',
            f'-{carry} {result} -{x}',
            f'-{carry} -{result} {x}',
            f'{carry} {result} {x}')


def cnf_vshift_id(out_id, in_id, in_shifted, shift_id):
    """
    Return a tuple of strings.

    Representing the CNF of the Boolean branch when shifting by variable amount and having to decide between two bits.

    INPUT:

    - ``out_id`` -- **string**; the bit of the new state
    - ``in_id`` -- **string**; the bit to be assigned to ``out_id`` if not shifted
    - ``in_shifted`` -- **string**; the bit to be assigned to ``out_id`` if shifted
    - ``shift_id`` -- **string**; the bit determining the shift

    EXAMPLES::

        sage: from claasp.cipher_modules.models.sat.utils.utils import cnf_vshift_id
        sage: cnf_vshift_id('s_3', 'i_3', 'i_4', 'k_7')
        ('-s_3 i_3 k_7', 's_3 -i_3 k_7', '-s_3 i_4 -k_7', 's_3 -i_4 -k_7')
    """
    return (f'-{out_id} {in_id} {shift_id}',
            f'{out_id} -{in_id} {shift_id}',
            f'-{out_id} {in_shifted} -{shift_id}',
            f'{out_id} -{in_shifted} -{shift_id}')


def cnf_vshift_false(out_id, in_id, shift_id):
    """
    Return a tuple of strings.

    Representing the CNF of the Boolean branch when shifting by variable amount and having to decide between a bit
    and false.

    INPUT:

    - ``out_id`` -- **string**; the bit of the new state
    - ``in_id`` -- **string**; the bit to be assigned to ``out_id`` if not shifted
    - ``shift_id`` -- **string**; the bit determining the shift

    EXAMPLES::

        sage: from claasp.cipher_modules.models.sat.utils.utils import cnf_vshift_false
        sage: cnf_vshift_false('s_1', 'i_1', 'k_7')
        ('-s_1 i_1', '-s_1 -k_7', 's_1 -i_1 k_7')
    """
    return (f'-{out_id} {in_id}',
            f'-{out_id} -{shift_id}',
            f'{out_id} -{in_id} {shift_id}')


def cnf_hw_lipmaa(hw, alpha, beta, gamma):
    """
    Return a tuple of strings representing the CNF of the Boolean equality.

    ``Not(hw_i) = And(Xor(Not(alpha_{i+1}), beta_{i+1}), Xor(Not(alpha_{i+1}), gamma_{i+1}))``
    (Lipmaa-Moriai algorithm).

    INPUT:

    - ``hw`` -- **string**; the variable for the Hamming weight
    - ``alpha`` -- **string**; the bit in the first mask
    - ``beta`` -- **string**; the bit in the second mask
    - ``gamma`` -- **string**; the bit in the result mask

    EXAMPLES::

        sage: from claasp.cipher_modules.models.sat.utils.utils import cnf_hw_lipmaa
        sage: cnf_hw_lipmaa('hw_6', 'alpha_7', 'beta_7', 'gamma_7')
        ('alpha_7 -gamma_7 hw_6',
         'beta_7 -alpha_7 hw_6',
         'gamma_7 -beta_7 hw_6',
         'alpha_7 beta_7 gamma_7 -hw_6',
         '-alpha_7 -beta_7 -gamma_7 -hw_6')
    """
    return (f'{alpha} -{gamma} {hw}',
            f'{beta} -{alpha} {hw}',
            f'{gamma} -{beta} {hw}',
            f'{alpha} {beta} {gamma} -{hw}',
            f'-{alpha} -{beta} -{gamma} -{hw}')


def cnf_lipmaa(hw, dummy, beta_1, alpha, beta, gamma):
    """
    Return a tuple of strings representing the CNF of the Boolean equalities.

    ``And(Not(hw_i), Xor(dummy_i, beta_{i-1})) = 0`` and ``dummy_i = Xor(alpha_i, beta_i, gamma_i)``
    (Lipmaa-Moriai algorithm).

    INPUT:

    - ``hw`` -- **string**; the variable for the Hamming weight bit
    - ``dummy`` -- **string**; the variable for the XOR of the three masks
    - ``beta_1`` -- **string**; the next bit in the second mask
    - ``alpha`` -- **string**; the bit in the first mask
    - ``beta`` -- **string**; the bit in the second mask
    - ``gamma`` -- **string**; the bit in the result mask

    EXAMPLES::

        sage: from claasp.cipher_modules.models.sat.utils.utils import cnf_lipmaa
        sage: cnf_lipmaa('hw_10', 'dummy_10', 'beta_11', 'alpha_10', 'beta_10', 'gamma_10')
        ('beta_11 -dummy_10 hw_10',
         '-beta_11 dummy_10 hw_10',
         'alpha_10 beta_10 dummy_10 -gamma_10',
         'alpha_10 beta_10 -dummy_10 gamma_10',
         'alpha_10 -beta_10 dummy_10 gamma_10',
         '-alpha_10 beta_10 dummy_10 gamma_10',
         'alpha_10 -beta_10 -dummy_10 -gamma_10',
         '-alpha_10 beta_10 -dummy_10 -gamma_10',
         '-alpha_10 -beta_10 dummy_10 -gamma_10',
         '-alpha_10 -beta_10 -dummy_10 gamma_10')
    """
    return (f'{beta_1} -{dummy} {hw}',
            f'-{beta_1} {dummy} {hw}',
            f'{alpha} {beta} {dummy} -{gamma}',
            f'{alpha} {beta} -{dummy} {gamma}',
            f'{alpha} -{beta} {dummy} {gamma}',
            f'-{alpha} {beta} {dummy} {gamma}',
            f'{alpha} -{beta} -{dummy} -{gamma}',
            f'-{alpha} {beta} -{dummy} -{gamma}',
            f'-{alpha} -{beta} {dummy} -{gamma}',
            f'-{alpha} -{beta} -{dummy} {gamma}')


def cnf_modadd_inequality(z, u, v):
    """
    Return a tuple of strings representing the CNF of the Boolean inequality ``z >= Xor(u, v)``.

    It is needed for the XOR linear constraints of modular addition (see formula (1) in `Automatic Search of Linear
    Trails in ARX with Applications to SPECK and Chaskey
    <https://link.springer.com/content/pdf/10.1007%2F978-3-319-39555-5_26.pdf>`_.

    INPUT:

    - ``z`` -- **string**; the bit of the hamming weight
    - ``u`` -- **string**; the bit of the result
    - ``v`` -- **string**; the bit of an addendum

    EXAMPLES::

        sage: from claasp.cipher_modules.models.sat.utils.utils import cnf_modadd_inequality
        sage: cnf_modadd_inequality('z', 'u', 'v')
        ('z u -v', 'z -u v')
    """
    return (f'{z} {u} -{v}',
            f'{z} -{u} {v}')


def cnf_and_differential(diff_in_0, diff_in_1, diff_out, hw):
    """
    Return a tuple of strings representing the CNF of the probability of the differential relation.

    INPUT:

    - ``diff_in_0`` -- **string**; the difference for the bit of the first input
    - ``diff_in_1`` -- **string**; the difference for the bit of the second input
    - ``diff_out`` -- **string**; the difference for the bit of the output
    - ``hw`` -- **string**; the bit for the hamming weight

    EXAMPLES::

        sage: from claasp.cipher_modules.models.sat.utils.utils import cnf_and_differential
        sage: cnf_and_differential('and_0', 'and_1', 'and_out', 'hw')
        ('-and_out hw', 'and_0 and_1 -hw', '-and_0 hw', '-and_1 hw')
    """
    return (f'-{diff_out} {hw}',
            f'{diff_in_0} {diff_in_1} -{hw}',
            f'-{diff_in_0} {hw}',
            f'-{diff_in_1} {hw}')


def cnf_and_linear(mask_in_0, mask_in_1, mask_out, hw):
    """
    Return a tuple of strings representing the CNF of the probability of the linear relation.

    ``(mask_in_0 & in_0) ^ (mask_in_1 & in_1) = (mask_out & out)``, being ``out = in_0 & in_1``.

    INPUT:

    - ``mask_in_0`` -- **string**; the mask for the bit of the first input
    - ``mask_in_1`` -- **string**; the mask for the bit of the second input
    - ``mask_out`` -- **string**; the mask for the bit of the output
    - ``hw`` -- **string**; the bit for the hamming weight

    EXAMPLES::

        sage: from claasp.cipher_modules.models.sat.utils.utils import cnf_and_linear
        sage: cnf_and_linear('and_0', 'and_1', 'and_out', 'hw')
        ('-and_0 hw', '-and_1 hw', '-and_out hw', 'and_out -hw')
    """
    return (f'-{mask_in_0} {hw}',
            f'-{mask_in_1} {hw}',
            f'-{mask_out} {hw}',
            f'{mask_out} -{hw}')


def cnf_xor_truncated(result, variable_0, variable_1):
    """
    Return a list of strings representing the CNF of the Boolean XOR when
    searching for DETERMINISTIC TRUNCATED XOR DIFFERENTIAL. I.e., an XOR
    behaving as in the following table:

    ==========  ==========  ==========
    variable_0  variable_1  result
    ==========  ==========  ==========
    0           0           0
    ----------  ----------  ----------
    0           1           1
    ----------  ----------  ----------
    0           2           2
    ----------  ----------  ----------
    1           0           1
    ----------  ----------  ----------
    1           1           0
    ----------  ----------  ----------
    1           2           2
    ----------  ----------  ----------
    2           0           2
    ----------  ----------  ----------
    2           1           2
    ----------  ----------  ----------
    2           2           2
    ==========  ==========  ==========

    INPUT:

    - ``result`` -- **tuple of two strings**; the result variable
    - ``variable_0`` -- **tuple of two string**; the first variable
    - ``variable_1`` -- **tuple of two string**; the second variable

    EXAMPLES::

        sage: from claasp.cipher_modules.models.sat.utils.utils import cnf_xor_truncated
        sage: cnf_xor_truncated(('r0', 'r1'), ('a0', 'a1'), ('b0', 'b1'))
        ['r0 -a0',
         'r0 -b0',
         'a0 b0 -r0',
         'a1 b1 r0 -r1',
         'a1 r0 r1 -b1',
         'b1 r0 r1 -a1',
         'r0 -a1 -b1 -r1']
    """
    return [f'{result[0]} -{variable_0[0]}',
            f'{result[0]} -{variable_1[0]}',
            f'{variable_0[0]} {variable_1[0]} -{result[0]}',
            f'{variable_0[1]} {variable_1[1]} {result[0]} -{result[1]}',
            f'{variable_0[1]} {result[0]} {result[1]} -{variable_1[1]}',
            f'{variable_1[1]} {result[0]} {result[1]} -{variable_0[1]}',
            f'{result[0]} -{variable_0[1]} -{variable_1[1]} -{result[1]}']


def cnf_xor_truncated_seq(results, variables):
    """
    Return a list of strings representing the CNF of the Boolean XOR performed
    between more than 2 inputs when searching for DETERMINISTIC TRUNCATED XOR
    DIFFERENTIAL.

    .. SEEALSO::

        :py:meth:`~cipher_modules.models.sat.utils.cnf_xor_truncated`

    INPUT:

    - ``results`` -- **list**; intermediate results + final result
    - ``variables`` -- **list**; the variables

    EXAMPLES::

        sage: from claasp.cipher_modules.models.sat.utils.utils import cnf_xor_truncated_seq
        sage: cnf_xor_truncated_seq([('i0', 'i1'), ('r0', 'r1')], [('a0', 'a1'), ('b0', 'b1'), ('c0', 'c1')])
        ['i0 -a0',
         'i0 -b0',
         'a0 b0 -i0',
         ...
         'i1 r0 r1 -c1',
         'c1 r0 r1 -i1',
         'r0 -i1 -c1 -r1']
    """
    model = cnf_xor_truncated(results[0], variables[0], variables[1])
    for i in range(1, len(results)):
        model.extend(cnf_xor_truncated(results[i], results[i - 1], variables[i + 1]))

    return model


def get_cnf_bitwise_truncate_constraints(a, a_0, a_1):
    return [
        f'-{a_0}', f'{a_1}   -{a}', f'{a}   -{a_1}'
    ]


def get_cnf_truncated_linear_constraints(a, a_0):
    return [
        f'-{a}   -{a_0}'
    ]


def modadd_truncated_lsb(result, variable_0, variable_1, next_carry):
    return [f'{next_carry[0]} -{next_carry[1]}',
            f'{next_carry[0]} -{variable_1[1]}',
            f'{next_carry[0]} -{result[0]}',
            f'{next_carry[0]} -{result[1]}',
            f'{result[0]} -{variable_0[0]}',
            f'{result[0]} -{variable_1[0]}',
            f'{variable_0[0]} {variable_1[0]} -{result[0]}',
            f'{variable_0[1]} {variable_1[1]} {result[0]} -{next_carry[0]}',
            f'{variable_0[1]} {result[0]} {result[1]} -{variable_1[1]}',
            f'{variable_1[1]} {result[0]} {result[1]} -{variable_0[1]}',
            f'{result[0]} -{variable_0[1]} -{variable_1[1]} -{result[1]}']


def modadd_truncated(result, variable_0, variable_1, carry, next_carry):
    return [f'{next_carry[0]} -{next_carry[1]}',
            f'{next_carry[0]} -{variable_1[1]}',
            f'{next_carry[0]} -{result[0]}',
            f'{next_carry[0]} -{result[1]}',
            f'{result[0]} -{carry[0]}',
            f'{result[0]} -{carry[1]}',
            f'{result[0]} -{variable_0[0]}',
            f'{result[0]} -{variable_1[0]}',
            f'{variable_0[1]} {variable_1[1]} {result[0]} -{next_carry[0]}',
            f'{variable_0[1]} {result[0]} {result[1]} -{variable_1[1]}',
            f'{variable_1[1]} {result[0]} {result[1]} -{variable_0[1]}',
            f'{carry[0]} {carry[1]} {variable_0[0]} {variable_1[0]} -{result[0]}',
            f'{result[0]} -{variable_0[1]} -{variable_1[1]} -{result[1]}']


def modadd_truncated_msb(result, variable_0, variable_1, carry):
    return [f'{result[0]} -{carry[0]}',
            f'{result[0]} -{carry[1]}',
            f'{result[0]} -{variable_0[0]}',
            f'{result[0]} -{variable_1[0]}',
            f'{variable_0[1]} {variable_1[1]} {result[0]} -{result[1]}',
            f'{variable_0[1]} {result[0]} {result[1]} -{variable_1[1]}',
            f'{variable_1[1]} {result[0]} {result[1]} -{variable_0[1]}',
            f'{carry[0]} {carry[1]} {variable_0[0]} {variable_1[0]} -{result[0]}',
            f'{result[0]} -{variable_0[1]} -{variable_1[1]} -{result[1]}']


# ---------------------------- #
#    - Running SAT solver -    #
# ---------------------------- #

def _get_data(data_keywords, lines):
    data_line = [line for line in lines if data_keywords in line][0]
    data = float(re.findall(r'[0-9]+\.?[0-9]*', data_line)[0])

    return data


def run_sat_solver(solver_specs, options, dimacs_input, host=None, env_vars_string=""):
    """Call the SAT solver specified in `solver_specs`, using input and output pipes."""
    solver_name = solver_specs['solver_name']
    command = [solver_specs['keywords']['command']['executable']] + solver_specs['keywords']['command']['options'] + options
    if host:
        command = ['ssh', f'{host}'] + [env_vars_string] + command
    solver_process = subprocess.run(command, input=dimacs_input, capture_output=True, text=True)
    solver_output = solver_process.stdout.splitlines()
    status = [line for line in solver_output if line.startswith('s')][0].split()[1]
    values = []
    if status == 'SATISFIABLE':
        for line in solver_output:
            if line.startswith('v'):
                values.extend(line.split()[1:])
        values = values[:-1]
    if solver_name == solvers.KISSAT_EXT:
        data_keywords = solver_specs['keywords']['time']
        lines = solver_output
        data_line = [line for line in lines if data_keywords in line][0]
        seconds_str_index = data_line.find("seconds") - 2
        output_str = ""
        while data_line[seconds_str_index] != " ":
            output_str += data_line[seconds_str_index]
            seconds_str_index -= 1
        solver_time = float(output_str[::-1])
    else:
        solver_time = _get_data(solver_specs['keywords']['time'], solver_output)
    solver_memory = float('inf')
    memory_keywords = solver_specs['keywords']['memory']
    if memory_keywords:
        if not (solver_name == solvers.GLUCOSE_SYRUP_EXT and status != 'SATISFIABLE'):
            solver_memory = _get_data(memory_keywords, solver_output)
    if solver_name == solvers.KISSAT_EXT:
        solver_memory = solver_memory / 10**6
    if solver_name == solvers.CRYPTOMINISAT_EXT:
        solver_memory = solver_memory / 10**3

    return status, solver_time, solver_memory, values


def run_minisat(solver_specs, options, dimacs_input, input_file_name, output_file_name):
    """Call the MiniSat solver specified in `solver_specs`, using input and output files."""
    with open(input_file_name, 'wt') as input_file:
        input_file.write(dimacs_input)
    command = [solver_specs['keywords']['command']['executable']] + solver_specs['keywords']['command']['options'] + options
    command.append(input_file_name)
    command.append(output_file_name)
    solver_process = subprocess.run(command, capture_output=True, text=True)
    solver_output = solver_process.stdout.splitlines()
    solver_time = _get_data(solver_specs['keywords']['time'], solver_output)
    solver_memory = _get_data(solver_specs['keywords']['memory'], solver_output)
    status = solver_output[-1]
    values = []
    if status == 'SATISFIABLE':
        with open(output_file_name, 'rt') as output_file:
            values = output_file.read().splitlines()[1].split()[:-1]
    os.remove(input_file_name)
    os.remove(output_file_name)

    return status, solver_time, solver_memory, values


def run_parkissat(solver_specs, options, dimacs_input, input_file_name):
    """Call the Parkissat solver specified in `solver_specs`, using input and output files."""
    with open(input_file_name, 'wt') as input_file:
        input_file.write(dimacs_input)
    command = [solver_specs['keywords']['command']['executable']] + solver_specs['keywords']['command']['options'] + options
    command.append(input_file_name)
    start = time.time()
    solver_process = subprocess.run(command, capture_output=True, text=True)
    end = time.time()
    solver_output = solver_process.stdout.splitlines()
    solver_time = end - start
    solver_memory = 0
    status = solver_output[0].split()[1]
    values = ""
    if status == 'SATISFIABLE':
        solver_output = solver_output[1:]
        solver_output = list(map(lambda s: s.replace('v ', ''), solver_output))
        values = []
        for element in solver_output:
            substrings = element.split()
            values.extend(substrings)
    os.remove(input_file_name)

    return status, solver_time, solver_memory, values


def run_yices(solver_specs, options, dimacs_input, input_file_name):
    """Call the Yices SAT solver specified in `solver_specs`, using input file."""
    with open(input_file_name, 'wt') as input_file:
        input_file.write(dimacs_input)
    command = [solver_specs['keywords']['command']['executable']] + solver_specs['keywords']['command']['options'] + options
    command.append(input_file_name)
    solver_process = subprocess.run(command, capture_output=True, text=True)
    solver_stats = solver_process.stderr.splitlines()
    solver_output = solver_process.stdout.splitlines()
    solver_time = _get_data(solver_specs['keywords']['time'], solver_stats)
    solver_memory = _get_data(solver_specs['keywords']['memory'], solver_stats)
    status = 'SATISFIABLE' if solver_output[0] == 'sat' else 'UNSATISFIABLE'
    values = []
    if status == 'SATISFIABLE':
        values = solver_output[1].split()[:-1]
    os.remove(input_file_name)

    return status, solver_time, solver_memory, values


def _generate_component_model_types(speck_cipher):
    """Generates the component model types for a given Speck cipher."""
    component_model_types = []
    for component in speck_cipher.get_all_components():
        component_model_types.append({
            "component_id": component.id,
            "component_object": component,
            "model_type": "sat_xor_differential_propagation_constraints"
        })
    return component_model_types


def _update_component_model_types_for_truncated_components(
        component_model_types,
        truncated_components,
        truncated_model_type="sat_bitwise_deterministic_truncated_xor_differential_constraints"
):
    """Updates the component model types for truncated components."""
    for component_model_type in component_model_types:
        if component_model_type["component_id"] in truncated_components:
            component_model_type["model_type"] = truncated_model_type


def _update_component_model_types_for_linear_components(component_model_types, linear_components):
    """Updates the component model types for linear components."""
    for component_model_type in component_model_types:
        if component_model_type["component_id"] in linear_components:
            component_model_type["model_type"] = "sat_xor_linear_mask_propagation_constraints"


def get_semi_deterministic_cnf_window_0(
        A_t0, A_t1, A_v0, A_v1,
        B_t0, B_t1, B_v0, B_v1,
        C_t0, C_t1, C_v0, C_v1,
        p0, q0, r0
):
    return [
        f'{C_v1} {B_t1} {C_t0} {B_v0} {A_v0} {A_t0} {A_t1} {B_v1} -{C_v0} {A_v1} {B_t0}',
        f'{C_v1} {B_t1} {C_t0} {B_v0} -{A_v0} {A_t0} {A_t1} {B_v1} {C_v0} {A_v1} {B_t0}',
        f'{C_v1} {B_t1} {C_t0} -{B_v0} {A_v0} {A_t0} {A_t1} {B_v1} {C_v0} {A_v1} {B_t0}',
        f'{C_v1} {B_t1} {C_t0} -{B_v0} -{A_v0} {A_t0} {A_t1} {B_v1} -{C_v0} {A_v1} {B_t0}',
        f'{C_v1} {B_t1} -{C_t0} {A_t1} {B_v1} {A_v1} {C_t1}',
        f'{C_v1} {B_t1} -{p0} {A_t1} {B_v1} {A_v1}',
        f'{C_v1} {B_t1} {B_v0} {A_v0} {A_t1} {B_v1} -{C_v0} {A_v1} {C_t1}',
        f'{C_v1} {B_t1} {B_v0} -{A_v0} {A_t1} {B_v1} {C_v0} {A_v1} {C_t1}',
        f'{C_v1} {B_t1} -{B_v0} {A_v0} {A_t1} {B_v1} {C_v0} {A_v1} {C_t1}',
        f'{C_v1} {B_t1} -{B_v0} -{A_v0} {A_t1} {B_v1} -{C_v0} {A_v1} {C_t1}',
        f'{C_v1} {B_t1} -{r0} {A_t1} {B_v1} {A_v1}',
        f'{C_v1} {B_t1} -{A_t0} {A_t1} {B_v1} {A_v1} {C_t1}',
        f'{C_v1} {B_t1} {A_t1} {B_v1} {A_v1} -{B_t0} {C_t1}',
        f'{C_v1} {C_t0} {p0} {B_v0} {A_v0} {A_t0} -{C_v0} {B_t0}',
        f'{C_v1} {C_t0} {p0} {B_v0} -{A_v0} {A_t0} {C_v0} {B_t0}',
        f'{C_v1} {C_t0} {p0} -{B_v0} {A_v0} {A_t0} {C_v0} {B_t0}',
        f'{C_v1} {C_t0} {p0} -{B_v0} -{A_v0} {A_t0} -{C_v0} {B_t0}',
        f'{C_v1} {C_t0} {p0} {A_t0} -{B_v1} {B_t0}',
        f'{C_v1} {C_t0} {p0} {A_t0} -{A_v1} {B_t0}',
        f'{C_v1} {C_t0} {B_v0} {r0} {A_v0} {A_t0} -{C_v0} {B_t0}',
        f'{C_v1} {C_t0} {B_v0} {r0} -{A_v0} {A_t0} {C_v0} {B_t0}',
        f'{C_v1} {C_t0} -{B_v0} {r0} {A_v0} {A_t0} {C_v0} {B_t0}',
        f'{C_v1} {C_t0} -{B_v0} {r0} -{A_v0} {A_t0} -{C_v0} {B_t0}',
        f'{C_v1} {C_t0} {r0} {A_t0} -{B_v1} {B_t0}',
        f'{C_v1} {C_t0} {r0} {A_t0} -{A_v1} {B_t0}',
        f'-{C_v1} {B_t1} -{C_t0} {A_t1} -{B_v1} -{A_v1} {C_t1}',
        f'-{C_v1} {B_t1} -{p0} {A_t1} -{B_v1} -{A_v1} {C_t1}',
        f'-{C_v1} {B_t1} {B_v0} {A_v0} {A_t1} -{B_v1} {C_v0} -{A_v1} {C_t1}',
        f'-{C_v1} {B_t1} {B_v0} -{A_v0} {A_t1} -{B_v1} -{C_v0} -{A_v1} {C_t1}',
        f'-{C_v1} {B_t1} -{B_v0} {A_v0} {A_t1} -{B_v1} -{C_v0} -{A_v1} {C_t1}',
        f'-{C_v1} {B_t1} -{B_v0} -{A_v0} {A_t1} -{B_v1} {C_v0} -{A_v1} {C_t1}',
        f'-{C_v1} {B_t1} -{r0} {A_t1} -{B_v1} -{A_v1} {C_t1}',
        f'-{C_v1} {B_t1} -{A_t0} {A_t1} -{B_v1} -{A_v1} {C_t1}',
        f'-{C_v1} {B_t1} {A_t1} -{B_v1} -{A_v1} -{B_t0} {C_t1}',
        f'-{C_v1} {C_t0} {p0} {B_v0} {A_v0} {A_t0} {C_v0} {B_t0}',
        f'-{C_v1} {C_t0} {p0} {B_v0} -{A_v0} {A_t0} -{C_v0} {B_t0}',
        f'-{C_v1} {C_t0} {p0} -{B_v0} {A_v0} {A_t0} -{C_v0} {B_t0}',
        f'-{C_v1} {C_t0} {p0} -{B_v0} -{A_v0} {A_t0} {C_v0} {B_t0}',
        f'-{C_v1} {C_t0} {p0} {A_t0} {B_v1} {B_t0}',
        f'-{C_v1} {C_t0} {p0} {A_t0} {A_v1} {B_t0}',
        f'-{C_v1} {C_t0} {B_v0} {r0} {A_v0} {A_t0} {C_v0} {B_t0}',
        f'-{C_v1} {C_t0} {B_v0} {r0} -{A_v0} {A_t0} -{C_v0} {B_t0}',
        f'-{C_v1} {C_t0} -{B_v0} {r0} {A_v0} {A_t0} -{C_v0} {B_t0}',
        f'-{C_v1} {C_t0} -{B_v0} {r0} -{A_v0} {A_t0} {C_v0} {B_t0}',
        f'-{C_v1} {C_t0} {r0} {A_t0} {B_v1} {B_t0}',
        f'-{C_v1} {C_t0} {r0} {A_t0} {A_v1} {B_t0}',
        f'{B_t1} {C_t0} {A_t0} {A_t1} {B_v1} {A_v1} {B_t0} -{C_t1}',
        f'{B_t1} -{p0} {A_t1} {B_v1} {A_v1} -{C_t1}',
        f'{B_t1} -{r0} {A_t1} {B_v1} {A_v1} -{C_t1}',
        f'-{B_t1} {C_t0} {p0} {A_t0} {B_t0}',
        f'-{B_t1} {C_t0} {r0} {A_t0} {B_t0}',
        f'{C_t0} {p0} {B_v0} {A_v0} {A_t0} {B_v1} -{C_v0} {B_t0}',
        f'{C_t0} {p0} {B_v0} {A_v0} {A_t0} -{B_v1} {C_v0} {B_t0}',
        f'{C_t0} {p0} {B_v0} {A_v0} {A_t0} {C_v0} -{A_v1} {B_t0}',
        f'{C_t0} {p0} {B_v0} {A_v0} {A_t0} -{C_v0} {A_v1} {B_t0}',
        f'{C_t0} {p0} {B_v0} -{A_v0} {A_t0} {B_v1} {C_v0} {B_t0}',
        f'{C_t0} {p0} {B_v0} -{A_v0} {A_t0} -{B_v1} -{C_v0} {B_t0}',
        f'{C_t0} {p0} {B_v0} -{A_v0} {A_t0} {C_v0} {A_v1} {B_t0}',
        f'{C_t0} {p0} {B_v0} -{A_v0} {A_t0} -{C_v0} -{A_v1} {B_t0}',
        f'{C_t0} {p0} -{B_v0} {A_v0} {A_t0} {B_v1} {C_v0} {B_t0}',
        f'{C_t0} {p0} -{B_v0} {A_v0} {A_t0} -{B_v1} -{C_v0} {B_t0}',
        f'{C_t0} {p0} -{B_v0} {A_v0} {A_t0} {C_v0} {A_v1} {B_t0}',
        f'{C_t0} {p0} -{B_v0} {A_v0} {A_t0} -{C_v0} -{A_v1} {B_t0}',
        f'{C_t0} {p0} -{B_v0} -{A_v0} {A_t0} {B_v1} -{C_v0} {B_t0}',
        f'{C_t0} {p0} -{B_v0} -{A_v0} {A_t0} -{B_v1} {C_v0} {B_t0}',
        f'{C_t0} {p0} -{B_v0} -{A_v0} {A_t0} {C_v0} -{A_v1} {B_t0}',
        f'{C_t0} {p0} -{B_v0} -{A_v0} {A_t0} -{C_v0} {A_v1} {B_t0}',
        f'{C_t0} {p0} {A_t0} -{A_t1} {B_t0}',
        f'{C_t0} {p0} {A_t0} {B_v1} -{A_v1} {B_t0}',
        f'{C_t0} {p0} {A_t0} -{B_v1} {A_v1} {B_t0}',
        f'{C_t0} {p0} {A_t0} {B_t0} -{C_t1}',
        f'{C_t0} {B_v0} {r0} {A_v0} {A_t0} {B_v1} -{C_v0} {B_t0}',
        f'{C_t0} {B_v0} {r0} {A_v0} {A_t0} -{B_v1} {C_v0} {B_t0}',
        f'{C_t0} {B_v0} {r0} {A_v0} {A_t0} {C_v0} -{A_v1} {B_t0}',
        f'{C_t0} {B_v0} {r0} {A_v0} {A_t0} -{C_v0} {A_v1} {B_t0}',
        f'{C_t0} {B_v0} {r0} -{A_v0} {A_t0} {B_v1} {C_v0} {B_t0}',
        f'{C_t0} {B_v0} {r0} -{A_v0} {A_t0} -{B_v1} -{C_v0} {B_t0}',
        f'{C_t0} {B_v0} {r0} -{A_v0} {A_t0} {C_v0} {A_v1} {B_t0}',
        f'{C_t0} {B_v0} {r0} -{A_v0} {A_t0} -{C_v0} -{A_v1} {B_t0}',
        f'{C_t0} -{B_v0} {r0} {A_v0} {A_t0} {B_v1} {C_v0} {B_t0}',
        f'{C_t0} -{B_v0} {r0} {A_v0} {A_t0} -{B_v1} -{C_v0} {B_t0}',
        f'{C_t0} -{B_v0} {r0} {A_v0} {A_t0} {C_v0} {A_v1} {B_t0}',
        f'{C_t0} -{B_v0} {r0} {A_v0} {A_t0} -{C_v0} -{A_v1} {B_t0}',
        f'{C_t0} -{B_v0} {r0} -{A_v0} {A_t0} {B_v1} -{C_v0} {B_t0}',
        f'{C_t0} -{B_v0} {r0} -{A_v0} {A_t0} -{B_v1} {C_v0} {B_t0}',
        f'{C_t0} -{B_v0} {r0} -{A_v0} {A_t0} {C_v0} -{A_v1} {B_t0}',
        f'{C_t0} -{B_v0} {r0} -{A_v0} {A_t0} -{C_v0} {A_v1} {B_t0}',
        f'{C_t0} {r0} {A_t0} -{A_t1} {B_t0}',
        f'{C_t0} {r0} {A_t0} {B_v1} -{A_v1} {B_t0}',
        f'{C_t0} {r0} {A_t0} -{B_v1} {A_v1} {B_t0}',
        f'{C_t0} {r0} {A_t0} {B_t0} -{C_t1}',
        f'-{C_t0} -{p0}',
        f'-{C_t0} -{r0}',
        f'-{q0}',
        f'{p0} -{r0}',
        f'-{p0} {r0}',
        f'-{p0} -{A_t0}',
        f'-{p0} -{B_t0}',
        f'-{r0} -{A_t0}',
        f'-{r0} -{B_t0}'
    ]


def get_cnf_semi_deterministic_window_1(
        A_t0, A_t1, A_t2, A_v0, A_v1, A_v2,
        B_t0, B_t1, B_t2, B_v0, B_v1, B_v2,
        C_t0, C_t1, C_t2, C_v0, C_v1,
        p0, q0, r0
):
    return [
        f'{C_v1} {A_t1} {A_v1} {A_t0} {B_t1} {C_t0} {B_t0} {A_v0} {B_v1} {B_v0} -{C_v0}',
        f'{C_v1} {A_t1} {A_v1} {A_t0} {B_t1} {C_t0} {B_t0} {A_v0} {B_v1} -{B_v0} {C_v0}',
        f'{C_v1} {A_t1} {A_v1} {A_t0} {B_t1} {C_t0} {B_t0} -{A_v0} {B_v1} {B_v0} {C_v0}',
        f'{C_v1} {A_t1} {A_v1} {A_t0} {B_t1} {C_t0} {B_t0} -{A_v0} {B_v1} -{B_v0} -{C_v0}',
        f'{C_v1} {A_t1} {A_v1} -{A_t0} {C_t1} {B_t1} {B_v1}',
        f'{C_v1} {A_t1} {A_v1} {C_t1} {B_t1} -{C_t0} {B_v1}',
        f'{C_v1} {A_t1} {A_v1} {C_t1} {B_t1} -{B_t0} {B_v1}',
        f'{C_v1} {A_t1} {A_v1} {C_t1} {B_t1} {A_v0} {B_v1} {B_v0} -{C_v0}',
        f'{C_v1} {A_t1} {A_v1} {C_t1} {B_t1} {A_v0} {B_v1} -{B_v0} {C_v0}',
        f'{C_v1} {A_t1} {A_v1} {C_t1} {B_t1} -{A_v0} {B_v1} {B_v0} {C_v0}',
        f'{C_v1} {A_t1} {A_v1} {C_t1} {B_t1} -{A_v0} {B_v1} -{B_v0} -{C_v0}',
        f'{C_v1} {A_t1} {A_v1} {C_t1} {B_t1} -{p0} {B_v1}',
        f'{C_v1} {A_t1} {A_v1} -{r0} {B_t1} {B_v1}',
        f'{C_v1} {A_t1} {A_v1} {A_v2} {B_t1} -{C_t2} {A_t2} {B_t2} {B_v2} -{p0} {B_v1}',
        f'{C_v1} {A_t1} {A_v1} {B_t1} {A_v0} -{p0} {B_v1} {B_v0} -{C_v0}',
        f'{C_v1} {A_t1} {A_v1} {B_t1} {A_v0} -{p0} {B_v1} -{B_v0} {C_v0}',
        f'{C_v1} {A_t1} {A_v1} {B_t1} -{A_v0} -{p0} {B_v1} {B_v0} {C_v0}',
        f'{C_v1} {A_t1} {A_v1} {B_t1} -{A_v0} -{p0} {B_v1} -{B_v0} -{C_v0}',
        f'{C_v1} -{A_v1} {A_t0} {r0} {C_t0} {B_t0}',
        f'{C_v1} -{A_v1} {A_t0} {C_t0} {B_t0} {p0}',
        f'{C_v1} {A_t0} {r0} {C_t0} {B_t0} {A_v0} {B_v0} -{C_v0}',
        f'{C_v1} {A_t0} {r0} {C_t0} {B_t0} {A_v0} -{B_v0} {C_v0}',
        f'{C_v1} {A_t0} {r0} {C_t0} {B_t0} -{A_v0} {B_v0} {C_v0}',
        f'{C_v1} {A_t0} {r0} {C_t0} {B_t0} -{A_v0} -{B_v0} -{C_v0}',
        f'{C_v1} {A_t0} {r0} {C_t0} {B_t0} -{B_v1}',
        f'{C_v1} {A_t0} {C_t0} {B_t0} {A_v0} {p0} {B_v0} -{C_v0}',
        f'{C_v1} {A_t0} {C_t0} {B_t0} {A_v0} {p0} -{B_v0} {C_v0}',
        f'{C_v1} {A_t0} {C_t0} {B_t0} -{A_v0} {p0} {B_v0} {C_v0}',
        f'{C_v1} {A_t0} {C_t0} {B_t0} -{A_v0} {p0} -{B_v0} -{C_v0}',
        f'{C_v1} {A_t0} {C_t0} {B_t0} {p0} -{B_v1}',
        f'-{C_v1} {A_t1} -{A_v1} -{A_t0} {C_t1} {B_t1} -{B_v1}',
        f'-{C_v1} {A_t1} -{A_v1} {C_t1} -{r0} {B_t1} -{B_v1}',
        f'-{C_v1} {A_t1} -{A_v1} {C_t1} {B_t1} -{C_t0} -{B_v1}',
        f'-{C_v1} {A_t1} -{A_v1} {C_t1} {B_t1} -{B_t0} -{B_v1}',
        f'-{C_v1} {A_t1} -{A_v1} {C_t1} {B_t1} {A_v0} -{B_v1} {B_v0} {C_v0}',
        f'-{C_v1} {A_t1} -{A_v1} {C_t1} {B_t1} {A_v0} -{B_v1} -{B_v0} -{C_v0}',
        f'-{C_v1} {A_t1} -{A_v1} {C_t1} {B_t1} -{A_v0} -{B_v1} {B_v0} -{C_v0}',
        f'-{C_v1} {A_t1} -{A_v1} {C_t1} {B_t1} -{A_v0} -{B_v1} -{B_v0} {C_v0}',
        f'-{C_v1} {A_t1} -{A_v1} {C_t1} {B_t1} -{p0} -{B_v1}',
        f'-{C_v1} {A_v1} {A_t0} {C_t1} {r0} {C_t0} {B_t0}',
        f'-{C_v1} {A_v1} {A_t0} {r0} {A_v2} {C_t0} {B_t0} -{C_t2} {A_t2} {B_t2} {B_v2}',
        f'-{C_v1} {A_v1} {A_t0} {C_t0} {B_t0} {p0}',
        f'-{C_v1} {A_t0} {C_t1} {r0} {C_t0} {B_t0} {A_v0} {B_v0} {C_v0}',
        f'-{C_v1} {A_t0} {C_t1} {r0} {C_t0} {B_t0} {A_v0} -{B_v0} -{C_v0}',
        f'-{C_v1} {A_t0} {C_t1} {r0} {C_t0} {B_t0} -{A_v0} {B_v0} -{C_v0}',
        f'-{C_v1} {A_t0} {C_t1} {r0} {C_t0} {B_t0} -{A_v0} -{B_v0} {C_v0}',
        f'-{C_v1} {A_t0} {C_t1} {r0} {C_t0} {B_t0} {B_v1}',
        f'-{C_v1} {A_t0} {r0} {A_v2} {C_t0} {B_t0} {A_v0} -{C_t2} {A_t2} {B_t2} {B_v2} {B_v0} {C_v0}',
        f'-{C_v1} {A_t0} {r0} {A_v2} {C_t0} {B_t0} {A_v0} -{C_t2} {A_t2} {B_t2} {B_v2} -{B_v0} -{C_v0}',
        f'-{C_v1} {A_t0} {r0} {A_v2} {C_t0} {B_t0} -{A_v0} -{C_t2} {A_t2} {B_t2} {B_v2} {B_v0} -{C_v0}',
        f'-{C_v1} {A_t0} {r0} {A_v2} {C_t0} {B_t0} -{A_v0} -{C_t2} {A_t2} {B_t2} {B_v2} -{B_v0} {C_v0}',
        f'-{C_v1} {A_t0} {r0} {A_v2} {C_t0} {B_t0} -{C_t2} {A_t2} {B_t2} {B_v2} {B_v1}',
        f'-{C_v1} {A_t0} {C_t0} {B_t0} {A_v0} {p0} {B_v0} {C_v0}',
        f'-{C_v1} {A_t0} {C_t0} {B_t0} {A_v0} {p0} -{B_v0} -{C_v0}',
        f'-{C_v1} {A_t0} {C_t0} {B_t0} -{A_v0} {p0} {B_v0} -{C_v0}',
        f'-{C_v1} {A_t0} {C_t0} {B_t0} -{A_v0} {p0} -{B_v0} {C_v0}',
        f'-{C_v1} {A_t0} {C_t0} {B_t0} {p0} {B_v1}',
        f'{A_t1} {A_v1} {A_t0} -{C_t1} {A_v2} {B_t1} {C_t0} {B_t0} -{C_t2} {A_t2} {B_t2} {B_v2} {B_v1}',
        f'{A_t1} {A_v1} {A_t0} -{C_t1} {B_t1} {C_t0} {B_t0} {A_v0} {B_v1} {B_v0} -{C_v0}',
        f'{A_t1} {A_v1} {A_t0} -{C_t1} {B_t1} {C_t0} {B_t0} {A_v0} {B_v1} -{B_v0} {C_v0}',
        f'{A_t1} {A_v1} {A_t0} -{C_t1} {B_t1} {C_t0} {B_t0} -{A_v0} {B_v1} {B_v0} {C_v0}',
        f'{A_t1} {A_v1} {A_t0} -{C_t1} {B_t1} {C_t0} {B_t0} -{A_v0} {B_v1} -{B_v0} -{C_v0}',
        f'{A_t1} {A_v1} -{C_t1} -{r0} {B_t1} {B_v1}',
        f'{A_t1} {A_v1} -{C_t1} {A_v2} {B_t1} -{C_t2} {A_t2} {B_t2} {B_v2} -{p0} {B_v1}',
        f'{A_t1} {A_v1} -{C_t1} {B_t1} {A_v0} -{p0} {B_v1} {B_v0} -{C_v0}',
        f'{A_t1} {A_v1} -{C_t1} {B_t1} {A_v0} -{p0} {B_v1} -{B_v0} {C_v0}',
        f'{A_t1} {A_v1} -{C_t1} {B_t1} -{A_v0} -{p0} {B_v1} {B_v0} {C_v0}',
        f'{A_t1} {A_v1} -{C_t1} {B_t1} -{A_v0} -{p0} {B_v1} -{B_v0} -{C_v0}',
        f'-{A_t1} {A_t0} {r0} {C_t0} {B_t0}',
        f'-{A_t1} {A_t0} {C_t0} {B_t0} {p0}',
        f'-{A_t1} {r0} -{p0}',
        f'{A_v1} {A_t0} {r0} {C_t0} {B_t0} {A_v0} {B_v0} -{C_v0}',
        f'{A_v1} {A_t0} {r0} {C_t0} {B_t0} {A_v0} -{B_v0} {C_v0}',
        f'{A_v1} {A_t0} {r0} {C_t0} {B_t0} -{A_v0} {B_v0} {C_v0}',
        f'{A_v1} {A_t0} {r0} {C_t0} {B_t0} -{A_v0} -{B_v0} -{C_v0}',
        f'{A_v1} {A_t0} {r0} {C_t0} {B_t0} -{B_v1}',
        f'{A_v1} {A_t0} {C_t0} {B_t0} {A_v0} {p0} {B_v0} -{C_v0}',
        f'{A_v1} {A_t0} {C_t0} {B_t0} {A_v0} {p0} -{B_v0} {C_v0}',
        f'{A_v1} {A_t0} {C_t0} {B_t0} -{A_v0} {p0} {B_v0} {C_v0}',
        f'{A_v1} {A_t0} {C_t0} {B_t0} -{A_v0} {p0} -{B_v0} -{C_v0}',
        f'{A_v1} {A_t0} {C_t0} {B_t0} {p0} -{B_v1}',
        f'-{A_v1} {A_t0} -{C_t1} {r0} {C_t0} {B_t0}',
        f'-{A_v1} {A_t0} {r0} {C_t0} {B_t0} {A_v0} {B_v0} {C_v0}',
        f'-{A_v1} {A_t0} {r0} {C_t0} {B_t0} {A_v0} -{B_v0} -{C_v0}',
        f'-{A_v1} {A_t0} {r0} {C_t0} {B_t0} -{A_v0} {B_v0} -{C_v0}',
        f'-{A_v1} {A_t0} {r0} {C_t0} {B_t0} -{A_v0} -{B_v0} {C_v0}',
        f'-{A_v1} {A_t0} {r0} {C_t0} {B_t0} {B_v1}',
        f'-{A_v1} {A_t0} {C_t0} {B_t0} {A_v0} {p0} {B_v0} {C_v0}',
        f'-{A_v1} {A_t0} {C_t0} {B_t0} {A_v0} {p0} -{B_v0} -{C_v0}',
        f'-{A_v1} {A_t0} {C_t0} {B_t0} -{A_v0} {p0} {B_v0} -{C_v0}',
        f'-{A_v1} {A_t0} {C_t0} {B_t0} -{A_v0} {p0} -{B_v0} {C_v0}',
        f'-{A_v1} {A_t0} {C_t0} {B_t0} {p0} {B_v1}',
        f'-{A_v1} {r0} -{p0}',
        f'{A_t0} -{C_t1} {r0} {A_v2} {C_t0} {B_t0} -{C_t2} {A_t2} {B_t2} {B_v2}',
        f'{A_t0} -{C_t1} {r0} {C_t0} {B_t0} {A_v0} {B_v0} -{C_v0}',
        f'{A_t0} -{C_t1} {r0} {C_t0} {B_t0} {A_v0} -{B_v0} {C_v0}',
        f'{A_t0} -{C_t1} {r0} {C_t0} {B_t0} -{A_v0} {B_v0} {C_v0}',
        f'{A_t0} -{C_t1} {r0} {C_t0} {B_t0} -{A_v0} -{B_v0} -{C_v0}',
        f'{A_t0} -{C_t1} {r0} {C_t0} {B_t0} -{B_v1}',
        f'{A_t0} -{C_t1} {C_t0} {B_t0} {p0}',
        f'{A_t0} {r0} -{B_t1} {C_t0} {B_t0}',
        f'{A_t0} {r0} {C_t0} {B_t0} {A_v0} {B_v1} {B_v0} -{C_v0}',
        f'{A_t0} {r0} {C_t0} {B_t0} {A_v0} {B_v1} -{B_v0} {C_v0}',
        f'{A_t0} {r0} {C_t0} {B_t0} {A_v0} -{B_v1} {B_v0} {C_v0}',
        f'{A_t0} {r0} {C_t0} {B_t0} {A_v0} -{B_v1} -{B_v0} -{C_v0}',
        f'{A_t0} {r0} {C_t0} {B_t0} -{A_v0} {B_v1} {B_v0} {C_v0}',
        f'{A_t0} {r0} {C_t0} {B_t0} -{A_v0} {B_v1} -{B_v0} -{C_v0}',
        f'{A_t0} {r0} {C_t0} {B_t0} -{A_v0} -{B_v1} {B_v0} -{C_v0}',
        f'{A_t0} {r0} {C_t0} {B_t0} -{A_v0} -{B_v1} -{B_v0} {C_v0}',
        f'{A_t0} -{B_t1} {C_t0} {B_t0} {p0}',
        f'{A_t0} {C_t0} {B_t0} {A_v0} {p0} {B_v1} {B_v0} -{C_v0}',
        f'{A_t0} {C_t0} {B_t0} {A_v0} {p0} {B_v1} -{B_v0} {C_v0}',
        f'{A_t0} {C_t0} {B_t0} {A_v0} {p0} -{B_v1} {B_v0} {C_v0}',
        f'{A_t0} {C_t0} {B_t0} {A_v0} {p0} -{B_v1} -{B_v0} -{C_v0}',
        f'{A_t0} {C_t0} {B_t0} -{A_v0} {p0} {B_v1} {B_v0} {C_v0}',
        f'{A_t0} {C_t0} {B_t0} -{A_v0} {p0} {B_v1} -{B_v0} -{C_v0}',
        f'{A_t0} {C_t0} {B_t0} -{A_v0} {p0} -{B_v1} {B_v0} -{C_v0}',
        f'{A_t0} {C_t0} {B_t0} -{A_v0} {p0} -{B_v1} -{B_v0} {C_v0}',
        f'-{A_t0} -{r0}',
        f'-{A_t0} -{p0}',
        f'{C_t1} {r0} -{p0}',
        f'{r0} {A_v2} -{C_t2} {A_t2} {B_t2} {B_v2} -{p0}',
        f'{r0} -{B_t1} -{p0}',
        f'{r0} {A_v0} -{p0} {B_v0} -{C_v0}',
        f'{r0} {A_v0} -{p0} -{B_v0} {C_v0}',
        f'{r0} -{A_v0} -{p0} {B_v0} {C_v0}',
        f'{r0} -{A_v0} -{p0} -{B_v0} -{C_v0}',
        f'{r0} -{p0} -{B_v1}',
        f'-{r0} -{C_t0}',
        f'-{r0} -{B_t0}',
        f'-{r0} {p0}',
        f'-{C_t0} -{p0}',
        f'-{B_t0} -{p0}',
        f'-{q0}'
    ]


def get_cnf_semi_deterministic_window_2(
        A_t0, A_t1, A_t2, A_t3,
        A_v0, A_v1, A_v2, A_v3,
        B_t0, B_t1, B_t2, B_t3,
        B_v0, B_v1, B_v2, B_v3,
        C_t0, C_t1, C_t2, C_t3,
        C_v0, C_v1,
        p0, q0, r0
):
    return [
        f'{A_t3} {A_v3} {B_t3} {B_v3} -{C_t3} -{q0}',
        f'-{A_t1} -{q0}',
        f'{A_t2} {A_v2} {B_t2} {B_v2} -{C_t2} -{p0} {r0}',
        f'{A_t1} {A_v0} -{A_v1} {B_t1} {B_v0} -{B_v1} {C_t1} {C_v0} -{C_v1}',
        f'{A_t1} -{A_v0} -{A_v1} {B_t1} -{B_v0} -{B_v1} {C_t1} {C_v0} -{C_v1}',
        f'{A_t1} -{A_v0} -{A_v1} {B_t1} {B_v0} -{B_v1} {C_t1} -{C_v0} -{C_v1}',
        f'{A_t1} {A_v0} -{A_v1} {B_t1} -{B_v0} -{B_v1} {C_t1} -{C_v0} -{C_v1}',
        f'-{A_t2} -{q0}',
        f'-{A_v1} -{q0}',
        f'-{A_v2} -{q0}',
        f'-{B_t1} -{q0}',
        f'{A_t1} -{A_v1} {B_t1} -{B_v1} {C_t1} -{C_v1} -{r0}',
        f'{A_t0} {A_t1} -{A_v0} {A_v1} {B_t0} {B_t1} {B_v0} {B_v1} {C_t0} -{C_t1} {C_v0}',
        f'{A_t0} {A_t1} {A_v0} {A_v1} {B_t0} {B_t1} -{B_v0} {B_v1} {C_t0} -{C_t1} {C_v0}',
        f'{A_t0} {A_t1} {A_v0} {A_v1} {B_t0} {B_t1} {B_v0} {B_v1} {C_t0} -{C_t1} -{C_v0}',
        f'{A_t0} {A_t1} -{A_v0} {A_v1} {B_t0} {B_t1} -{B_v0} {B_v1} {C_t0} -{C_t1} -{C_v0}',
        f'{A_t0} {A_t1} -{A_v0} {A_v1} {B_t0} {B_t1} {B_v0} {B_v1} {C_t0} {C_v0} {C_v1}',
        f'{A_t0} {A_t1} {A_v0} {A_v1} {B_t0} {B_t1} -{B_v0} {B_v1} {C_t0} {C_v0} {C_v1}',
        f'{A_t0} {A_t1} {A_v0} {A_v1} {B_t0} {B_t1} {B_v0} {B_v1} {C_t0} -{C_v0} {C_v1}',
        f'{A_t0} {A_t1} -{A_v0} {A_v1} {B_t0} {B_t1} -{B_v0} {B_v1} {C_t0} -{C_v0} {C_v1}',
        f'-{B_t2} -{q0}',
        f'{A_t1} {A_v1} {B_t1} {B_v1} -{C_t1} {q0} -{r0}',
        f'-{A_v1} -{p0} {r0}',
        f'{A_t1} {A_v1} {B_t1} {B_v1} {C_v1} {q0} -{r0}',
        f'{A_t0} {B_t0} {B_v1} {C_t0} -{C_v1} {p0} {r0}',
        f'-{B_v1} -{q0}',
        f'-{B_v2} -{q0}',
        f'{A_t0} -{A_v1} {B_t0} {C_t0} {C_v1} {r0}',
        f'{C_t1} -{p0} {r0}',
        f'{A_t0} {A_v1} {B_t0} -{B_v1} {C_t0} {r0}',
        f'{C_t2} -{q0}',
        f'{A_t0} -{A_t1} {B_t0} {C_t0} {r0}',
        f'-{A_t0} -{r0}',
        f'-{B_t0} -{r0}',
        f'{A_t0} {B_t0} -{B_t1} {C_t0} {r0}',
        f'-{C_t0} -{r0}',
        f'-{p0} -{q0}',
        f'{A_t0} {B_t0} {C_t0} -{C_t1} {p0} {q0}',
        f'{C_t1} {p0} -{r0}',
        f'-{q0} {r0}',
        f'{A_t1} -{A_v1} {B_t1} -{B_v1} -{C_t0} {C_t1} -{C_v1}',
        f'{A_t1} -{A_v1} -{B_t0} {B_t1} -{B_v1} {C_t1} -{C_v1}',
        f'-{A_t0} {A_t1} -{A_v1} {B_t1} -{B_v1} {C_t1} -{C_v1}',
        f'{A_t1} {A_v1} {B_t1} {B_v1} -{C_t0} {C_t1} {C_v1}',
        f'{A_t1} {A_v1} -{B_t0} {B_t1} {B_v1} {C_t1} {C_v1}',
        f'-{A_t0} {A_t1} {A_v1} {B_t1} {B_v1} {C_t1} {C_v1}',
        f'-{C_t0} -{p0}',
        f'-{B_t0} -{p0}',
        f'-{A_t0} -{p0}',
    ]


def get_cnf_semi_deterministic_window_3(
        A_t0, A_t1, A_t2, A_t3, A_t4,
        A_v0, A_v1, A_v2, A_v3, A_v4,
        B_t0, B_t1, B_t2, B_t3, B_t4,
        B_v0, B_v1, B_v2, B_v3, B_v4,
        C_t0, C_t1, C_t2, C_t3, C_t4,
        C_v0, C_v1, p0, q0, r0):
    return [
        f'{A_t4} {A_v4} {B_t4} {B_v4} -{C_t4} -{q0} {r0}',
        f'{A_t3} {A_v3} {B_t3} {B_v3} -{C_t3} -{q0} -{r0}',
        f'-{A_t3} -{q0} {r0}',
        f'-{A_v3} -{q0} {r0}',
        f'-{B_t3} -{q0} {r0}',
        f'-{B_v3} -{q0} {r0}',
        f'{C_t3} -{q0} {r0}',
        f'{A_t1} {A_v0} -{A_v1} {B_t1} {B_v0} -{B_v1} {C_t1} {C_v0} -{C_v1}',
        f'{A_t1} -{A_v0} -{A_v1} {B_t1} -{B_v0} -{B_v1} {C_t1} {C_v0} -{C_v1}',
        f'{A_t1} -{A_v0} -{A_v1} {B_t1} {B_v0} -{B_v1} {C_t1} -{C_v0} -{C_v1}',
        f'{A_t1} {A_v0} -{A_v1} {B_t1} -{B_v0} -{B_v1} {C_t1} -{C_v0} -{C_v1}',
        f'-{A_v1} -{q0}',
        f'-{B_v1} -{q0}',
        f'{A_t0} {A_t2} {A_v2} {B_t0} {B_t2} {B_v2} {C_t0} -{C_t1} -{C_t2} {q0} {r0}',
        f'{A_t1} -{A_v1} {B_t1} -{B_v1} {C_t1} -{C_v1} -{r0}',
        f'{A_t0} {A_t1} -{A_v0} {A_v1} {B_t0} {B_t1} {B_v0} {B_v1} {C_t0} -{C_t1} {C_v0}',
        f'{A_t0} {A_t1} {A_v0} {A_v1} {B_t0} {B_t1} -{B_v0} {B_v1} {C_t0} -{C_t1} {C_v0}',
        f'{A_t0} {A_t1} {A_v0} {A_v1} {B_t0} {B_t1} {B_v0} {B_v1} {C_t0} -{C_t1} -{C_v0}',
        f'{A_t0} {A_t1} -{A_v0} {A_v1} {B_t0} {B_t1} -{B_v0} {B_v1} {C_t0} -{C_t1} -{C_v0}',
        f'{A_t0} -{A_t2} {B_t0} {C_t0} -{C_t1} {p0}',
        f'{A_t1} {A_v1} {B_t1} {B_v1} -{C_t1} {q0} -{r0}',
        f'{A_t0} {A_t1} -{A_v0} {A_v1} {B_t0} {B_t1} {B_v0} {B_v1} {C_t0} {C_v0} {C_v1}',
        f'{A_t0} {A_t1} {A_v0} {A_v1} {B_t0} {B_t1} -{B_v0} {B_v1} {C_t0} {C_v0} {C_v1}',
        f'{A_t0} {A_t1} {A_v0} {A_v1} {B_t0} {B_t1} {B_v0} {B_v1} {C_t0} -{C_v0} {C_v1}',
        f'{A_t0} {A_t1} -{A_v0} {A_v1} {B_t0} {B_t1} -{B_v0} {B_v1} {C_t0} -{C_v0} {C_v1}',
        f'{A_t1} {A_v1} {B_t1} {B_v1} {C_v1} {q0} -{r0}',
        f'{A_t0} -{A_v2} {B_t0} {C_t0} -{C_t1} {p0}',
        f'{A_t0} {B_t0} {B_v1} {C_t0} -{C_v1} {p0} {q0}',
        f'{A_t0} {B_t0} -{B_t2} {C_t0} -{C_t1} {p0}',
        f'{C_t1} -{p0} {r0}',
        f'{A_t0} {B_t0} -{B_v2} {C_t0} -{C_t1} {p0}',
        f'{A_t0} -{A_v1} {B_t0} {C_t0} -{C_t1} {r0}',
        f'{A_t0} -{A_v1} {B_t0} {C_t0} {C_v1} {r0}',
        f'{A_t0} {A_v1} {B_t0} -{B_v1} {C_t0} {r0}',
        f'-{p0} -{q0}',
        f'{A_t0} {B_t0} {C_t0} -{C_t1} {C_t2} {p0}',
        f'-{A_t1} {p0} -{r0}',
        f'-{B_t1} {p0} -{r0}',
        f'{p0} {q0} -{r0}',
        f'{A_t0} -{A_t1} {B_t0} {C_t0} {r0}',
        f'{A_t0} {B_t0} -{B_t1} {C_t0} {r0}',
        f'{A_t1} -{A_v1} {B_t1} -{B_v1} -{C_t0} {C_t1} -{C_v1}',
        f'{A_t1} -{A_v1} -{B_t0} {B_t1} -{B_v1} {C_t1} -{C_v1}',
        f'-{A_t0} {A_t1} -{A_v1} {B_t1} -{B_v1} {C_t1} -{C_v1}',
        f'{A_t1} {A_v1} {B_t1} {B_v1} -{C_t0} {C_t1} {C_v1}',
        f'{A_t1} {A_v1} -{B_t0} {B_t1} {B_v1} {C_t1} {C_v1}',
        f'-{A_t0} {A_t1} {A_v1} {B_t1} {B_v1} {C_t1} {C_v1}',
        f'-{C_t0} -{p0}',
        f'-{B_t0} -{p0}',
        f'-{A_t0} -{p0}',
        f'-{C_t0} -{q0}',
        f'-{B_t0} -{q0}',
        f'-{A_t0} -{q0}',
        f'{C_t1} -{q0}',
    ]
