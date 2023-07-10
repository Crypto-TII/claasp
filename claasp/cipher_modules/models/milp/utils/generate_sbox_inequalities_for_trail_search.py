
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
The target of this module is to generate MILP inequalities for small sboxes (4 bits) by using the convex hull method.

Part of this code has been extracted from an external source available at :
https://gist.github.com/pfasante/3a2f087e74cd0f2a10853c8a5d036d85
Generate inequalities for 8-bit sboxes is infeasible with this module.
The module generate_inequalities_for_large_sboxes.py take care of both cases, small and large sboxes.
Hence, this module can be removed, but we decide to keep it for comparison purpose.
"""
import pickle, os, pathlib

from sage.rings.integer_ring import ZZ

from claasp.cipher_modules.models.milp.utils.config import SOLVER_DEFAULT

small_sbox_file_name = "dictionary_that_contains_inequalities_for_small_sboxes.obj"
small_sbox_xor_linear_file_name = "dictionary_that_contains_inequalities_for_small_sboxes_xor_linear.obj"

inequalities_for_small_sboxes_path = os.path.join(pathlib.Path(__file__).parent.resolve(), small_sbox_file_name)
inequalities_for_small_sboxes_xor_linear_path = os.path.join(pathlib.Path(__file__).parent.resolve(),
                                                             small_sbox_xor_linear_file_name)


def sbox_inequalities(sbox, analysis="differential", algorithm="milp", big_endian=False):
    """
    Compute inequalities for modeling the given S-box.

    INPUT:

    - ``sbox`` -- **SBox object**; the S-box to model
    - ``analysis`` -- **string** (default: `differential`); choosing between 'differential' and 'linear' cryptanalysis
    - ``algorithm`` -- **string** (default: `greedy`); choosing the algorithm for computing the S-box model, one of
      ['none', 'greedy', 'milp']
    - ``big_endian`` -- **boolean** (default: `False`); representation of transitions vectors

        EXAMPLES::

        sage: from sage.crypto.sbox import SBox
        sage: SBox_PRESENT = SBox([12,5,6,11,9,0,10,13,3,14,15,8,4,7,1,2])
        sage: from claasp.cipher_modules.models.milp.utils.generate_sbox_inequalities_for_trail_search import *
        sage: sbox_ineqs = sbox_inequalities(SBox_PRESENT) # long
        sage: sbox_ineqs[2][1]
        An inequality (0, 0, 0, 1, 1, 0, 1, 0) x - 1 >= 0
    """
    ch = convex_hull(sbox, analysis, big_endian)
    if algorithm == "greedy":
        return cutting_off_greedy(ch)
    elif algorithm == "milp":
        return cutting_off_milp(ch)
    elif algorithm == "none":
        return list(ch.inequalities())
    else:
        raise ValueError("algorithm (%s) has to be one of ['greedy', 'milp']" % (algorithm,))


def convex_hull(sbox, analysis="differential", big_endian=False):
    """
    Compute the convex hull of the differential or linear behaviour of the given S-box.

    INPUT:

    - ``sbox`` -- **SBox object**; the S-box for which the convex hull should be computed
    - ``analysis`` -- **string** (default: `differential`); choosing between differential and linear behaviour
    - ``big_endian`` -- **boolean** (default: `False`); representation of transitions vectors
    """
    from sage.geometry.polyhedron.constructor import Polyhedron

    if analysis == "differential":
        valid_transformations_matrix = sbox.difference_distribution_table()
    elif analysis == "linear":
        valid_transformations_matrix = sbox.linear_approximation_table()
    else:
        raise TypeError("analysis (%s) has to be one of ['differential', 'linear']" % (analysis,))

    n, m = sbox.input_size(), sbox.output_size()
    values_in_matrix = list(set(valid_transformations_matrix.coefficients()))
    dict_polyhedron = {}
    dict_points = {}

    for value in values_in_matrix:
        dict_points[value] = []
    for i in range(0, 1 << n):
        for o in range(0, 1 << m):
            if i+o > 0 and valid_transformations_matrix[i][o] != 0:
                dict_points[valid_transformations_matrix[i][o]].append(
                    to_bits(n, i, big_endian) + to_bits(n, o, big_endian))
    for value in values_in_matrix:
        if dict_points[value]:
            dict_polyhedron[value] = Polyhedron(vertices=dict_points[value])

    return dict_polyhedron


def to_bits(n, x, big_endian=False):
    if big_endian:
        return ZZ(x).digits(base=2, padto=n)
    return ZZ(x).digits(base=2, padto=n)[::-1]


def cutting_off_greedy(dict_polyhedron):
    """
    Compute a set of inequalities that is cutting-off equivalent to the H-representation of the given convex hull.

    INPUT:

    - ``dict_polyhedron`` -- **dictionary**; the polyhedron representing the convex hull
    """
    from sage.modules.free_module import VectorSpace
    from sage.rings.finite_rings.finite_field_constructor import GF
    from sage.modules.free_module_element import vector

    dict_chosen_inequalities = {}
    for proba in dict_polyhedron.keys():
        chosen_ineqs = []
        poly_points = dict_polyhedron[proba].integral_points()
        remaining_ineqs = list(dict_polyhedron[proba].inequalities())
        impossible = [vector(dict_polyhedron[proba].base_ring(), v)
                      for v in VectorSpace(GF(2), dict_polyhedron[proba].ambient_dim())
                      if v not in poly_points]
        while impossible != []:
            if len(remaining_ineqs) == 0:
                raise ValueError("no more inequalities to choose, but still "
                                 "%d impossible points left" % len(impossible))

            # find inequality in remaining_ineqs that cuts off the most
            # impossible points and add this to the chosen_ineqs
            ineqs = []
            for i in remaining_ineqs:
                cnt = sum(map(lambda x, value=i: not (value.contains(x)), impossible))
                ineqs.append((cnt, i))
            chosen_ineqs.append(sorted(ineqs, reverse=True)[0][1])

            # remove ineq from remaining_ineqs
            remaining_ineqs.remove(chosen_ineqs[-1])

            # remove all cut off impossible points
            impossible = [v
                          for v in impossible
                          if chosen_ineqs[-1].contains(v)
                          ]
        dict_chosen_inequalities[proba] = chosen_ineqs

    return dict_chosen_inequalities


def cutting_off_milp(dict_polyhedron, number_of_ineqs=None):
    """
    Compute a set of inequalities that is cutting-off equivalent to the H-representation of the given convex hull by solving a MILP.

    The representation can either be computed from the minimal number of necessary inequalities, or by a given number
    of inequalities. This second variant might be faster, because the MILP solver that later uses this representation
    can do some optimizations itself.

    INPUT:

    - ``dict_polyhedron`` -- **dictionary**; the polyhedron representing the convex hull
    - ``number_of_ineqs`` -- **integer** (default: `None`); either `None` or the number of inequalities that should be
      used for representing the S-box.

    .. [SasTod17]_ "New Algorithm for Modeling S-box in MILP Based Differential and Division Trail Search"
    """
    from sage.matrix.constructor import matrix
    from sage.modules.free_module import VectorSpace
    from sage.modules.free_module_element import vector
    from sage.numerical.mip import MixedIntegerLinearProgram
    from sage.rings.finite_rings.finite_field_constructor import GF

    dict_chosen_inequalities = {}
    for proba in dict_polyhedron.keys():
        ineqs = list(dict_polyhedron[proba].inequalities())
        poly_points = dict_polyhedron[proba].integral_points()
        impossible = [vector(dict_polyhedron[proba].base_ring(), v)
                      for v in VectorSpace(GF(2), dict_polyhedron[proba].ambient_dim())
                      if v not in poly_points]

        # precompute which inequality removes which impossible point
        precomputation = matrix(
            [[int(not (ineq.contains(p)))
              for p in impossible]
             for ineq in ineqs]
        )
        milp = MixedIntegerLinearProgram(maximization=False, solver=SOLVER_DEFAULT)
        var_ineqs = milp.new_variable(binary=True, name="ineqs")

        # either use the minimal number of inequalities for the representation
        if number_of_ineqs is None:
            milp.set_objective(sum([var_ineqs[i] for i in range(len(ineqs))]))
        # or the given number
        else:
            milp.add_constraint(sum(
                [var_ineqs[i]
                 for i in range(len(ineqs))]
            ) == number_of_ineqs)

        nrows, ncols = precomputation.dimensions()
        for c in range(ncols):
            lhs = sum([var_ineqs[r]
                       for r in range(nrows)
                       if precomputation[r][c] == 1])
            if (not isinstance(lhs, int)):
                milp.add_constraint(lhs >= 1)

        milp.solve()

        remaining_ineqs = [
            ineq
            for ineq, (var, val) in zip(ineqs, milp.get_values(var_ineqs).items())
            if val == 1
        ]
        dict_chosen_inequalities[proba] = remaining_ineqs

    return dict_chosen_inequalities


def get_dictionary_that_contains_inequalities_for_small_sboxes(analysis="differential"):
    """
    Compute a set of inequalities that is cutting-off equivalent to the H-representation of the given convex hull.

    INPUT:

    - ``analysis`` - **string** (default: `differential`);
    """
    file_path = inequalities_for_small_sboxes_path if analysis == "differential" else inequalities_for_small_sboxes_xor_linear_path
    read_file = open(file_path, 'rb')
    dictio = pickle.load(read_file)
    read_file.close()

    return dictio


def update_dictionary_that_contains_inequalities_for_small_sboxes(sbox, analysis="differential"):
    file_path = inequalities_for_small_sboxes_path if analysis == "differential" else inequalities_for_small_sboxes_xor_linear_path
    try:
        read_file = open(file_path, 'rb')
        dictio = pickle.load(read_file)
        read_file.close()
    except OSError:
        dictio = {}

    if str(sbox) not in dictio.keys():
        print("Adding sbox inequalities in pre-saved dictionary")
        dict_inequalities = sbox_inequalities(sbox, analysis)
        dictio[str(sbox)] = dict_inequalities
        write_file = open(file_path, 'wb')
        pickle.dump(dictio, write_file)
        write_file.close()


def delete_dictionary_that_contains_inequalities_for_small_sboxes(analysis="differential"):
    file_path = inequalities_for_small_sboxes_path if analysis == "differential" else inequalities_for_small_sboxes_xor_linear_path
    write_file = open(file_path, 'wb')
    pickle.dump({}, write_file)
    write_file.close()
