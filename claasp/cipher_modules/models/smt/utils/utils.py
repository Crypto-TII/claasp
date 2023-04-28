
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


# ------------------------ #
#    - Build formulae -    #
# ------------------------ #

def smt_and(formulae):
    """
    Return a string representing the AND of formulae in SMT-LIB standard.

    INPUT:

    - ``formulae`` -- **list**; the formulae which are operands

    EXAMPLES::

        sage: from claasp.cipher_modules.models.smt.utils.utils import smt_and
        sage: smt_and(['a', 'c', 'e'])
        '(and a c e)'
    """
    return f'(and {" ".join(formulae)})'


def smt_assert(formula):
    """
    Return a string representing assert in SMT-LIB standard.

    INPUT:

    - ``formula`` -- **string**; the formula that must be asserted

    EXAMPLES::

        sage: from claasp.cipher_modules.models.smt.utils.utils import smt_assert
        sage: smt_assert('(= a b c)')
        '(assert (= a b c))'
    """
    return f'(assert {formula})'


def smt_distinct(variable_0, variable_1):
    """
    Return a string representing the Boolean inequality in SMT-LIB standard.

    INPUT:

    - ``variable_0`` -- **string**; the first variable
    - ``variable_1`` -- **string**; the second variable

    EXAMPLES::

        sage: from claasp.cipher_modules.models.smt.utils.utils import smt_distinct
        sage: smt_distinct('a', 'q')
        '(distinct a q)'
    """
    return f'(distinct {variable_0} {variable_1})'


def smt_equivalent(formulae):
    """
    Return a string representing the equivalence of formulae in SMT-LIB standard.

    INPUT:

    - ``formulae`` -- **list**; the formulae that must be equivalent

    EXAMPLES::

        sage: from claasp.cipher_modules.models.smt.utils.utils import smt_equivalent
        sage: smt_equivalent(['a', 'b', 'c', 'd'])
        '(= a b c d)'
    """
    return f'(= {" ".join(formulae)})'


def smt_implies(antecedent, consequent):
    """
    Return a string representing the implication in SMT-LIB standard.

    INPUT:

    - ``antecedent`` -- **string**; the formula that is the antecedent
    - ``consequent`` -- **string**; the formula that is the consequent

    EXAMPLES::

        sage: from claasp.cipher_modules.models.smt.utils.utils import smt_implies
        sage: smt_implies('(and a c)', '(or l f)')
        '(=> (and a c) (or l f))'
    """
    return f'(=> {antecedent} {consequent})'


def smt_ite(condition, consequent, alternative):
    """
    Return a string representing the if-then-else in SMT-LIB standard.

    INPUT:

    - ``condition`` -- **string**; the formula that is the condition
    - ``consequent`` -- **string**; the formula that is the consequent
    - ``antecedent`` -- **string**; the formula that is the antecedent

    EXAMPLES::

        sage: from claasp.cipher_modules.models.smt.utils.utils import smt_ite
        sage: smt_ite('t', '(and a b)', '(and a e)')
        '(ite t (and a b) (and a e))'
    """
    return f'(ite {condition} {consequent} {alternative})'


def smt_not(formula):
    """
    Return a string representing the negation of the formula in SMT-LIB standard.

    INPUT:

    - ``formula`` -- **string**; the formula that must be negated

    EXAMPLES::

        sage: from claasp.cipher_modules.models.smt.utils.utils import smt_not
        sage: smt_not('(xor a e)')
        '(not (xor a e))'
    """
    return f'(not {formula})'


def smt_or(formulae):
    """
    Return a string representing the OR of formulae in SMT-LIB standard.

    INPUT:

    - ``formulae`` -- **list of str**; the formulae which are operands

    EXAMPLES::

        sage: from claasp.cipher_modules.models.smt.utils.utils import smt_or
        sage: smt_or(['b', 'd', 'f'])
        '(or b d f)'
    """
    return f'(or {" ".join(formulae)})'


def smt_xor(formulae):
    """
    Return a string representing the XOR of formulae in SMT-LIB standard.

    INPUT:

    - ``formulae`` -- **list of str**; the formulae which are operands

    EXAMPLES::

        sage: from claasp.cipher_modules.models.smt.utils.utils import smt_xor
        sage: smt_xor(['b', 'd', 'f'])
        '(xor b d f)'
    """
    return f'(xor {" ".join(formulae)})'


def smt_carry(x, y, previous_carry):
    """
    Return a list of strings.

    The list represents the Boolean equality ``carry = Or(And(x, y), And(x, previous_carry), And(y, previous_carry))``
    in SMT-LIB standard. It represents the general form of a carry when performing modular addition between two
    bitvectors.

    INPUT:

    - ``x`` -- **string**; the bit of the first addendum
    - ``y`` -- **string**; the bit of the second addendum
    - ``previous_carry`` -- **string**; the previous carry

    EXAMPLES::

        sage: from claasp.cipher_modules.models.smt.utils.utils import smt_carry
        sage: smt_carry('x_3', 'y_3', 'c_2')
        '(or (and x_3 y_3) (and x_3 c_2) (and y_3 c_2))'
    """
    operand_0 = smt_and((x, y))
    operand_1 = smt_and((x, previous_carry))
    operand_2 = smt_and((y, previous_carry))

    return smt_or((operand_0, operand_1, operand_2))


def smt_lipmaa(hw, alpha, beta, gamma, beta_1):
    """
    Return a string representing the Lipmaa-Moriai algorithm in SMT-LIB standard.

    INPUT:

    - ``hw`` -- **string**; the variable for the Hamming weight bit
    - ``alpha`` -- **string**; the bit in the first mask
    - ``beta`` -- **string**; the bit in the second mask
    - ``gamma`` -- **string**; the bit in the result mask
    - ``beta_1`` -- **string**; the next bit in the second mask

    EXAMPLES::

        sage: from claasp.cipher_modules.models.smt.utils.utils import smt_lipmaa
        sage: smt_lipmaa('hw', 'alpha', 'beta', 'gamma', 'beta_1')
        '(or hw (not (xor alpha beta gamma beta_1)))'
    """
    return smt_or((hw, smt_not(smt_xor((alpha, beta, gamma, beta_1)))))

# ---------------------------- #
#    - Parsing SMT output -    #
# ---------------------------- #


def z3_parser(to_parse):
    tmp_dict = {}
    start = to_parse.index('sat') + 2
    stop = to_parse.index(')')
    to_parse = to_parse[start: stop]
    for i in range(0, len(to_parse), 2):
        var_name = to_parse[i].split()[1]
        var_value = 1 if to_parse[i + 1][4:-1] == 'true' else 0
        tmp_dict[var_name] = var_value

    return tmp_dict


def yices_parser(to_parse):
    tmp_dict = {}
    start = to_parse.index('sat') + 1
    stop = to_parse.index('(')
    to_parse = to_parse[start: stop]
    for line in to_parse:
        solution = line[3:-1].split(' ')
        var_name = solution[0]
        var_value = 1 if solution[1] == 'true' else 0
        tmp_dict[var_name] = var_value

    return tmp_dict


def mathsat_parser(to_parse):
    tmp_dict = {}
    start = to_parse.index('(model') + 1
    stop = to_parse.index(')')
    to_parse = to_parse[start: stop]
    for line in to_parse:
        solution = line[14:-1].split(' ')
        var_name = solution[0]
        var_value = 1 if solution[3] == 'true' else 0
        tmp_dict[var_name] = var_value

    return tmp_dict
