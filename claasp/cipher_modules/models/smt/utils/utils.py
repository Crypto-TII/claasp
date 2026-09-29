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
import numpy as np
import pickle

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
    return f"(and {' '.join(formulae)})"


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
    return f"(assert {formula})"


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
    return f"(distinct {variable_0} {variable_1})"


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
    return f"(= {' '.join(formulae)})"


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
    return f"(=> {antecedent} {consequent})"


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
    return f"(ite {condition} {consequent} {alternative})"


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
    return f"(not {formula})"


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
    return f"(or {' '.join(formulae)})"


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
    return f"(xor {' '.join(formulae)})"


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


def get_component_hex_value(component, out_suffix, variable2value):
    output_bit_size = component.output_bit_size
    value = 0
    for i in range(output_bit_size):
        value <<= 1
        if f"{component.id}_{i}{out_suffix}" in variable2value:
            value ^= variable2value[f"{component.id}_{i}{out_suffix}"]
        hex_digits = output_bit_size // 4 + (output_bit_size % 4 != 0)
        hex_value = f"{value:#0{hex_digits + 2}x}"

    return hex_value


def interleave_bits(x, y, n):
    """
    Interleave the bits of x and y.

    EXAMPLES::

        sage: from claasp.cipher_modules.models.smt.utils.utils import interleave_bits
        sage: interleave_bits(0b11, 0b00, 2), interleave_bits(0b00, 0b11, 2)
        (5, 10)

    The bits of ``x`` land on the even positions, those of ``y`` on the odd ones.
    """
    z = 0

    for i in range(n):
        z |= (x & (1 << i)) << i | (y & (1 << i)) << (i + 1)

    return z


def to_quasidifferential_basis(x):
    """
    Transform x into the quasidifferential basis.

    EXAMPLES::

        sage: import numpy as np
        sage: from claasp.cipher_modules.models.smt.utils.utils import to_quasidifferential_basis
        sage: to_quasidifferential_basis(np.array([1, 0, 0, 0], dtype=float)).tolist()
        [1.0, 0.0, 1.0, 0.0]
        sage: to_quasidifferential_basis(np.array([1, 0], dtype=float))
        Traceback (most recent call last):
        ...
        ValueError: Input length must be divisible by 4.
    """
    if len(x) == 1:
        return x

    if len(x) % 4 != 0:
        raise ValueError("Input length must be divisible by 4.")

    block_length = len(x) // 4

    x_00 = to_quasidifferential_basis(x[:block_length])
    x_01 = to_quasidifferential_basis(x[block_length : 2 * block_length])
    x_10 = to_quasidifferential_basis(x[2 * block_length : 3 * block_length])
    x_11 = to_quasidifferential_basis(x[3 * block_length :])

    return np.concatenate(
        [
            x_00 + x_11,
            x_01 + x_10,
            x_00 - x_11,
            x_01 - x_10,
        ]
    )


def interleaved_transition_matrix(sbox_function, n, m):
    """
    Build the interleaved transition matrix of ``sbox_function``.

    This is the NumPy equivalent of the Sage implementation.

    EXAMPLES::

        sage: from claasp.cipher_modules.models.smt.utils.utils import interleaved_transition_matrix
        sage: interleaved_transition_matrix(lambda x: x, 1, 1).tolist()
        [[1.0, 0.0, 0.0, 0.0], [0.0, 1.0, 0.0, 0.0], [0.0, 0.0, 1.0, 0.0], [0.0, 0.0, 0.0, 1.0]]
    """
    size_rows = 2 ** (2 * m)
    size_cols = 2 ** (2 * n)

    transition_matrix = np.zeros(
        (size_rows, size_cols),
        dtype=np.float64,
    )

    for x in range(2**n):
        for y in range(2**n):
            i = interleave_bits(x, y, n)
            j = interleave_bits(sbox_function(x), sbox_function(y), m)

            transition_matrix[j, i] = 1

    return transition_matrix


def quasidifferential_transition_matrix(
    sbox_function,
    n,
    m,
):
    """
    Compute the quasidifferential transition matrix of ``sbox_function``.

    EXAMPLES::

        sage: from claasp.cipher_modules.models.smt.utils.utils import quasidifferential_transition_matrix
        sage: quasidifferential_transition_matrix(lambda x: x ^^ 1, 1, 1).tolist()
        [[1.0, 0.0, 0.0, 0.0], [0.0, 1.0, 0.0, 0.0], [0.0, 0.0, -1.0, 0.0], [0.0, 0.0, 0.0, -1.0]]

    The one-bit NOT, still in the interleaved order.
    """
    quasidifferential_matrix = interleaved_transition_matrix(sbox_function, n, m)

    # Transform columns.
    for i in range(2 ** (2 * n)):
        quasidifferential_matrix[:, i] = to_quasidifferential_basis(quasidifferential_matrix[:, i])

    # Transform rows.
    for i in range(2 ** (2 * m)):
        quasidifferential_matrix[i, :] = to_quasidifferential_basis(quasidifferential_matrix[i, :])

    return quasidifferential_matrix / (2**n)


def _diff_target_indices(
    n,
    m,
    a,
    b,
    u,
    v,
):
    """
    Target position with the DIFFERENCE as the major index.

    EXAMPLES::

        sage: from claasp.cipher_modules.models.smt.utils.utils import _diff_target_indices
        sage: _diff_target_indices(2, 2, 1, 2, 3, 0)
        (8, 7)
    """
    return 2**m * b + v, 2**n * a + u


def _mask_target_indices(
    n,
    m,
    a,
    b,
    u,
    v,
):
    """
    Target position with the MASK as the major index.

    EXAMPLES::

        sage: from claasp.cipher_modules.models.smt.utils.utils import _mask_target_indices
        sage: _mask_target_indices(2, 2, 1, 2, 3, 0)
        (2, 13)
    """
    return 2**m * v + b, 2**n * u + a


def _fill_deinterleaved_block(
    deinterleaved_matrix,
    qdt_matrix,
    n,
    m,
    u,
    v,
    target_indices,
):
    """
    Copy into ``deinterleaved_matrix`` the block of ``qdt_matrix``
    selected by the input mask ``u`` and the output mask ``v``, placing
    each entry at the position given by ``target_indices``.

    EXAMPLES::

        sage: import numpy as np
        sage: from claasp.cipher_modules.models.smt.utils.utils import (
        ....:     _diff_target_indices, _fill_deinterleaved_block, quasidifferential_transition_matrix)
        sage: qdt = quasidifferential_transition_matrix(lambda x: x ^^ 1, 1, 1)
        sage: block = np.zeros((4, 4))
        sage: _fill_deinterleaved_block(block, qdt, 1, 1, 1, 1, _diff_target_indices)
        sage: block.tolist()
        [[0.0, 0.0, 0.0, 0.0], [0.0, -1.0, 0.0, 0.0], [0.0, 0.0, 0.0, 0.0], [0.0, 0.0, 0.0, -1.0]]
    """
    for a in range(2**n):
        source_col = interleave_bits(a, u, n)

        for b in range(2**m):
            source_row = interleave_bits(b, v, m)
            target_row, target_col = target_indices(n, m, a, b, u, v)

            deinterleaved_matrix[target_row, target_col] = qdt_matrix[
                source_row,
                source_col,
            ]


def deinterleave_qdt_matrix(
    qdt_matrix,
    n,
    m,
    primary: str = "diff",
):
    """
    Convert an interleaved QDT matrix to the requested ordering.

    ``primary`` selects which of the two quantities is used as the
    major index of the result: ``"diff"`` (the default, expected by the
    quasidifferential SMT model) or ``"mask"``.

    EXAMPLES::

        sage: from claasp.cipher_modules.models.smt.utils.utils import deinterleave_qdt_matrix, quasidifferential_transition_matrix
        sage: qdt = quasidifferential_transition_matrix(lambda x: x ^^ 1, 1, 1)
        sage: deinterleave_qdt_matrix(qdt, 1, 1).tolist()
        [[1.0, 0.0, 0.0, 0.0], [0.0, -1.0, 0.0, 0.0], [0.0, 0.0, 1.0, 0.0], [0.0, 0.0, 0.0, -1.0]]
        sage: deinterleave_qdt_matrix(qdt, 1, 1, primary='mask').tolist()
        [[1.0, 0.0, 0.0, 0.0], [0.0, 1.0, 0.0, 0.0], [0.0, 0.0, -1.0, 0.0], [0.0, 0.0, 0.0, -1.0]]
        sage: deinterleave_qdt_matrix(qdt, 1, 1, primary='other')
        Traceback (most recent call last):
        ...
        ValueError: primary must be either 'diff' or 'mask'.

    With the difference as the major index, the one-bit NOT has coefficient
    ``-1`` exactly where the output mask is 1: the sign factor ``(-1)^v``.
    """
    if primary == "diff":
        target_indices = _diff_target_indices
    elif primary == "mask":
        target_indices = _mask_target_indices
    else:
        raise ValueError("primary must be either 'diff' or 'mask'.")

    deinterleaved_matrix = np.zeros_like(qdt_matrix)

    for u in range(2**n):
        for v in range(2**m):
            _fill_deinterleaved_block(
                deinterleaved_matrix,
                qdt_matrix,
                n,
                m,
                u,
                v,
                target_indices,
            )

    return deinterleaved_matrix


def check_qdt_feasibility(qdt_matrix):
    """
    Check that every non-zero coefficient of a quasidifferential
    transition matrix is a power of two.

    The weight of a transition is ``-log2|coefficient|``, and the SMT
    model encodes it as a thermometer of Boolean indicators, so it must
    be an integer. A coefficient of 3/8 has weight 1.415 and would be
    recorded as 1 -- a silently optimistic weight, pooled with the
    genuine weight-1 transitions, and a correlation of 2^-1 instead of
    3/8 in the sum of Theorem 4.1.

    This mirrors ``claasp.components.sbox_component.check_table_feasibility``,
    which already refuses a DDT with a non-power-of-two entry for the
    SAT, SMT and MILP differential models. The two checks are NOT
    equivalent: a power-of-two DDT can still yield a non-power-of-two
    QDT, since a mask-carrying cell sums +-1 over a power-of-two number
    of terms and may land anywhere in between. Of 31 random 4-bit
    permutations whose DDT is all powers of two, 14 had a QDT cell that
    is not.

    INPUT:

    - ``qdt_matrix`` -- a NumPy array of quasidifferential coefficients

    OUTPUT:

    - None; raises ``ValueError`` when a non-zero coefficient is not a
      power of two

    EXAMPLES::

        sage: import numpy as np
        sage: from claasp.cipher_modules.models.smt.utils.utils import check_qdt_feasibility
        sage: check_qdt_feasibility(np.array([[1, 1/2], [0, 1/4]], dtype=float))
        sage: check_qdt_feasibility(np.array([[3/8]], dtype=float))
        Traceback (most recent call last):
        ...
        ValueError: The S-box QDT of the cipher contains 0.375 which is not a power of two. Currently, SMT cannot handle it.
    """
    magnitudes = np.unique(np.abs(qdt_matrix[qdt_matrix != 0]))
    exponents = np.log2(magnitudes)
    offending = magnitudes[np.abs(exponents - np.round(exponents)) > 1e-9]

    if offending.size:
        raise ValueError(
            f"The S-box QDT of the cipher contains {offending[0]} which is not a "
            f"power of two. Currently, SMT cannot handle it."
        )


def _weight_table_for_differential(
    qdt_matrix,
    n,
    m,
    b,
    a,
):
    """
    Return the weight table of a single differential transition
    (``a`` -> ``b``) of the quasidifferential transition matrix.

    The result maps each weight loss to the list of ``(v, u)`` mask
    pairs achieving it. An empty dictionary means the differential
    admits no valid quasidifferential transition.

    EXAMPLES::

        sage: from claasp.cipher_modules.models.smt.utils.utils import (
        ....:     _weight_table_for_differential, deinterleave_qdt_matrix, quasidifferential_transition_matrix)
        sage: qdt = deinterleave_qdt_matrix(quasidifferential_transition_matrix(lambda x: x ^^ 1, 1, 1), 1, 1)
        sage: _weight_table_for_differential(qdt, 1, 1, 0, 0)
        {0: [(0, 0), (1, 1)]}
        sage: _weight_table_for_differential(qdt, 1, 1, 1, 0)
        {}
    """
    table = {}

    for v in range(2**m):
        for u in range(2**n):
            coefficient = qdt_matrix[
                2**m * b + v,
                2**n * a + u,
            ]

            if coefficient == 0:
                continue

            w_loss = int(-np.log2(abs(coefficient)))
            table.setdefault(w_loss, []).append((v, u))

    return table


def generate_weight_tables(
    qdt_matrix,
    n,
    m,
):
    """
    Return the weight tables of the quasidifferential transition matrix,
    indexed by differential transition:

        {(b, a): {weight_loss: [(v, u), ...], ...}, ...}

    Every ``(b, a)`` pair is present, mapping to an empty dictionary
    when the differential admits no valid transition.

    EXAMPLES::

        sage: from claasp.cipher_modules.models.smt.utils.utils import (
        ....:     deinterleave_qdt_matrix, generate_weight_tables, quasidifferential_transition_matrix)
        sage: qdt = deinterleave_qdt_matrix(quasidifferential_transition_matrix(lambda x: x ^^ 1, 1, 1), 1, 1)
        sage: generate_weight_tables(qdt, 1, 1)
        {(0, 0): {0: [(0, 0), (1, 1)]}, (0, 1): {}, (1, 0): {}, (1, 1): {0: [(0, 0), (1, 1)]}}
    """
    check_qdt_feasibility(qdt_matrix)

    weights = {}

    for b in range(2**m):
        for a in range(2**n):
            weights[(b, a)] = _weight_table_for_differential(qdt_matrix, n, m, b, a)

    return weights
