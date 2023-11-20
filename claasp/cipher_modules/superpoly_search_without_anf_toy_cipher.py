import math

# from sage.all__sagemath_objects import Integer
from sage.rings.polynomial.pbori.pbori import BooleanPolynomialRing
from sage.rings.monomials import monomials
import numpy as np
from random import randint
import copy


def toyspn_chi(x0, x1, x2):
    y0 = x0 + (1 + x1) * x2
    y1 = x1 + (1 + x2) * x0
    y2 = x2 + (1 + x0) * x1
    return y0, y1, y2


def toyspn_round(x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5, verb=False):
    x0 = x0 + k0
    x1 = x1 + k1
    x2 = x2 + k2
    x3 = x3 + k3
    x4 = x4 + k4
    x5 = x5 + k5
    if verb:
        print(f'after xor: {x0}{x1}{x2}{x3}{x4}{x5}')
    y0, y1, y2 = toyspn_chi(x0, x1, x2)
    y3, y4, y5 = toyspn_chi(x3, x4, x5)
    if verb:
        print(f'after sbox: {y0}{y1}{y2}{y3}{y4}{y5}')
        print(f'after rotl: {y5}{y0}{y1}{y2}{y3}{y4}')
    return y5, y0, y1, y2, y3, y4


def toyspn_update_key(k0, k1, k2, k3, k4, k5):
    return k5, k0, k1, k2, k3, k4


def toyspn_rotr1(x0, x1, x2, x3, x4, x5):
    return x5, x0, x1, x2, x3, x4

def toyspn2_cipher(R, x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5, verb=False):
    """
    EXAMPLE:
        import numpy as np
        from algebraic_attack_on_toy_cipher import *
        R = BooleanPolynomialRing(12, names=('x0','x1','x2','x3','x4','x5', 'k0','k1','k2','k3','k4','k5')); (x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5) = R._first_ngens(12)
        component_functions = toyspn2_cipher(R, x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5)
    """
    if verb:
        print(f'input:      {x0}{x1}{x2}{x3}{x4}{x5}')
        print(f'key:        {k0}{k1}{k2}{k3}{k4}{k5}')
    k0, k1, k2, k3, k4, k5 = toyspn_update_key(k0, k1, k2, k3, k4, k5)
    x0, x1, x2, x3, x4, x5 = toyspn_round(x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5, verb=verb)
    k0, k1, k2, k3, k4, k5 = toyspn_update_key(k0, k1, k2, k3, k4, k5)
    x0, x1, x2, x3, x4, x5 = toyspn_round(x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5, verb=verb)

    return R(x0), R(x1), R(x2), R(x3), R(x4), R(x5)

def get_quo_rem(R, f, p):
    """
    EXAMPLE:
        import numpy as np
        from algebraic_attack_on_toy_cipher import *
        R = BooleanPolynomialRing(12, names=('x0','x1','x2','x3','x4','x5', 'k0','k1','k2','k3','k4','k5')); (x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5) = R._first_ngens(12)
        component_functions = toyspn2_cipher(R, x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5)
        q,r = get_quo_rem(R, component_functions[5], x2*x5)
    """
    Q = R.quotient(p)
    r = Q(f).lift()
    q = (f - r) / p
    return q, r

def find_all_maxterms_superpolies_of_each_coordinate_with_ANF(component_functions):
    """
    This method returns all the maxterms and superpolies of each coordinate of the cipher with knowledge of their ANF.

    EXAMPLE:
        import numpy as np
        from algebraic_attack_on_toy_cipher import *
        R = BooleanPolynomialRing(12, names=('x0','x1','x2','x3','x4','x5', 'k0','k1','k2','k3','k4','k5')); (x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5) = R._first_ngens(12)
        component_functions = toyspn2_cipher(R, x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5)
        all = find_all_maxterms_superpolies_of_each_coordinate_with_ANF(component_functions)

        all[0] =
        [ (x2*x5, x4 + k3 + 1),
          (x2*x4, x5 + k4),
          (x1*x4*x5, x0 + k5 + 1),
          (x1*x3, x0 + k5 + 1),
          (x0*x4*x5, x1 + k0),
          (x0*x3, x1 + k0),
          (x0*x1*x5, x4 + k3 + 1),
          (x0*x1*x4, x5 + k4)]
        For example, if we xor F in the cube variables x2, x5, we obtain x4 + k3 + 1.
        F(0,0,1,0,0,0) + F(0,0,0,0,0,1) + F(0,0,1,0,0,1) + F(0,0,0,0,0,0) = x4 + k3 + 1

    """
    R = BooleanPolynomialRing(12, names=('x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'k0', 'k1', 'k2', 'k3', 'k4', 'k5'))
    (x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5) = R._first_ngens(12)
    max_super = []
    for component_function in component_functions:
        max_super_for_fi = []
        l = [m for m in monomials([x0, x1, x2, x3, x4, x5], [2, 2, 2, 2, 2, 2]) if 0 < m.degree() <= component_function.degree()]
        for monomial in l:
            q, r = get_quo_rem(R, component_function, monomial)
            if q.degree() == 1:
                max_super_for_fi.append((monomial, q))
        max_super.append(max_super_for_fi)
    return max_super

def generate_cube_inputs(cube_index, inputs_size):
    """
    EXAMPLE:
        import numpy as np
        from algebraic_attack_on_toy_cipher import *
        A = generate_cube_inputs([1,0,0,0,0,1], 12)
    """
    number_of_1s = cube_index.count(1)
    specific_format = f"0{number_of_1s}b"
    binary_numbers = [format(i, specific_format) for i in range(2**number_of_1s)]
    columns = []
    for i in range(number_of_1s):
        columns.append([int(n[i]) for n in binary_numbers])

    A = np.zeros((2**number_of_1s, inputs_size), dtype=int)
    j = 0
    for index, value in enumerate(cube_index):
        if value == 1:
            A[:,index] = columns[j]
            j += 1
    return A

def evaluate_f_as_sum_with_cube_var_fixed(cube_index, key_vars, R):
    """
    EXAMPLE:
        import numpy as np
        from algebraic_attack_on_toy_cipher import *
        R = BooleanPolynomialRing(12, names=('x0','x1','x2','x3','x4','x5', 'k0','k1','k2','k3','k4','k5')); (x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5) = R._first_ngens(12)
        evaluate_f_as_sum_with_cube_var_fixed([1,0,0,0,0,1], [1,1,0,0,1,1], R) # this is an oracle, in practice we don't have access to the key
    """
    cube = generate_cube_inputs(cube_index, 12)
    print(cube)
    for index, var in enumerate(key_vars):
        cube[:,len(key_vars)+index] = [var for _ in range(2**cube_index.count(1))]
    print(cube)
    sum = 0
    for vector in cube:
        sum += np.array(toyspn2_cipher(R, *vector))
    return sum

def is_potential_superpoly_constant(cube_index, f_coordinate, R):
    """
    EXAMPLE:
        import numpy as np
        from algebraic_attack_on_toy_cipher import *
        R = BooleanPolynomialRing(12, names=('x0','x1','x2','x3','x4','x5', 'k0','k1','k2','k3','k4','k5')); (x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5) = R._first_ngens(12)
        is_potential_superpoly_constant([1,1,0,0,0,1], 0, R)
    """
    specific_format = f"06b"
    binary_numbers = [format(i, specific_format) for i in range(2 ** 6)]
    all_key_combinaisons = [[int(c) for c in str] for str in binary_numbers]
    constant = True
    bit_0 = evaluate_f_as_sum_with_cube_var_fixed(cube_index, all_key_combinaisons[0], R)[f_coordinate]
    i = 1
    while constant and i < len(all_key_combinaisons):
        bit_i = evaluate_f_as_sum_with_cube_var_fixed(cube_index, all_key_combinaisons[i], R)[f_coordinate]
        constant = (bit_0 == bit_i)
        i += 1
    return constant


def is_potential_superpoly_linear(cube_index, f_coordinate, R):
    """
    EXAMPLE:
        import numpy as np
        from algebraic_attack_on_toy_cipher import *
        R = BooleanPolynomialRing(12, names=('x0','x1','x2','x3','x4','x5', 'k0','k1','k2','k3','k4','k5')); (x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5) = R._first_ngens(12)
        is_potential_superpoly_linear([1,1,0,0,0,1], 0, R)
    """
    # chose randomly x and y
    left = 1
    right = 1
    count = 100
    p0 = evaluate_f_as_sum_with_cube_var_fixed(cube_index, [0, 0, 0, 0, 0, 0], R)
    while left == right and count > 0:
        x = randint(0, (2 ** 6) - 1)
        y = randint(0, (2 ** 6) - 1)
        specific_format = f"06b"
        x = format(x, specific_format)
        y = format(y, specific_format)
        x = [int(c) for c in x]
        y = [int(c) for c in y]
        x_xor_y = np.array(x) ^ np.array(y)

        p_x = evaluate_f_as_sum_with_cube_var_fixed(cube_index, x, R)
        p_y = evaluate_f_as_sum_with_cube_var_fixed(cube_index, y, R)
        p_x_xor_y = evaluate_f_as_sum_with_cube_var_fixed(cube_index, x_xor_y, R)
        left = p0 + p_x + p_y
        right = p_x_xor_y
        left = left[f_coordinate]
        right = right[f_coordinate]
        count -= 1

    return left == right


def which_cubes_give_superpoly(f_coordinate, R, component_functions):
    """
    EXAMPLE:
        import numpy as np
        from algebraic_attack_on_toy_cipher import *
        R = BooleanPolynomialRing(12, names=('x0','x1','x2','x3','x4','x5', 'k0','k1','k2','k3','k4','k5')); (x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5) = R._first_ngens(12)
        component_functions = toyspn2_cipher(R, x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5)
        g,b = which_cubes_give_superpoly(0, R, component_functions)
    """
    specific_format = f"06b"
    binary_numbers = [format(i, specific_format) for i in range(2 ** 6)]
    all_possible_cube_indexes = [[int(c) for c in str] for str in binary_numbers if 0 < sum([int(c) for c in str]) <= component_functions[f_coordinate].degree() - 1]
    good = []
    bad = []
    for cube_index in all_possible_cube_indexes:
        if (is_potential_superpoly_linear(cube_index, f_coordinate, R) == True) and (is_potential_superpoly_constant(cube_index, f_coordinate, R) == False):
            good.append(cube_index)
        else:
            bad.append(cube_index)
    return good, bad

def construction_of_superpoly(cube_index, R, f_coordinate):
    """
    EXAMPLE:
        import numpy as np
        from algebraic_attack_on_toy_cipher import *
        R = BooleanPolynomialRing(12, names=('x0','x1','x2','x3','x4','x5', 'k0','k1','k2','k3','k4','k5')); (x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5) = R._first_ngens(12)
        construction_of_superpoly([0,0,1,0,0,1], R, 0)
    """
    cube_with_key_vars_0 = generate_cube_inputs(cube_index, 12)
    superpoly = 0
    # check if there is a constant term:
    constant = 0
    for vector in cube_with_key_vars_0:
        constant += np.array(toyspn2_cipher(R, *vector))[f_coordinate]
    superpoly += constant
    # check if there is all other monomial:
    for i in range(6):
        cube = copy.deepcopy(cube_with_key_vars_0)
        cube[:, 6+i] = 1
        presence_of_xi = 0
        for vector in cube:
            presence_of_xi += np.array(toyspn2_cipher(R, *vector))[f_coordinate]
        if constant + presence_of_xi == 1 % 2:
            superpoly += R.variable(6+i)

    return superpoly

def find_all_maxterms_superpolies_of_each_coordinate_without_ANF(R, component_functions):
    """
    This method returns all the maxterms and superpolies of each coordinate of the cipher without knowledge of their ANF.

    EXAMPLE:
        import numpy as np
        from algebraic_attack_on_toy_cipher import *
        R = BooleanPolynomialRing(12, names=('x0','x1','x2','x3','x4','x5', 'k0','k1','k2','k3','k4','k5')); (x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5) = R._first_ngens(12)
        component_functions = toyspn2_cipher(R, x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5)
        all = find_all_maxterms_superpolies_of_each_coordinate_without_ANF(R, component_functions)
    """
    all_maxterms_superpolies = []
    for i in range(len(component_functions)):
        all_maxterms_superpolies_of_fi = []
        g,b = which_cubes_give_superpoly(i, R, component_functions)
        for maxterm in g:
            superpoly = construction_of_superpoly(maxterm, R, i)
            all_maxterms_superpolies_of_fi.append((maxterm, superpoly))
        all_maxterms_superpolies.append(all_maxterms_superpolies_of_fi)
    return all_maxterms_superpolies

