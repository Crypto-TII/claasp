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


"""The target of this module is to generate MILP inequalities for a AND operation between 2 input bits."""

from claasp.cipher_modules.models.milp.solvers import SOLVER_DEFAULT


def and_inequalities():
    valid_points = [
        [0, 0, 0, 0],
        [0, 1, 0, 1],
        [0, 1, 1, 1],
        [1, 0, 0, 1],
        [1, 0, 1, 1],
        [1, 1, 0, 1],
        [1, 1, 1, 1],
    ]
    chosen_ineqs = cutting_off_greedy(valid_points)

    return chosen_ineqs


def and_LAT():
    valid_points = [[0, 0, 0], [0, 0, 1], [0, 1, 1], [1, 0, 1], [1, 1, 1]]
    chosen_ineqs = cutting_off_greedy(valid_points)

    return chosen_ineqs


def convex_hull(valid_points):
    """
    Compute the convex hull of the differential or linear behaviour of the given S-box.

    INPUT:

    - ``valid_points`` -- **matrix**; the polyhedron representing the convex hull
    """
    from sage.geometry.polyhedron.constructor import Polyhedron

    return Polyhedron(vertices=valid_points)


def cutting_off_greedy(valid_points):
    """
    Compute a set of inequalities that is cutting-off equivalent to the H-representation of the given convex hull.

    INPUT:

    - ``valid_points`` -- **matrix**; the polyhedron representing the convex hull
    """
    from sage.modules.free_module import VectorSpace
    from sage.rings.finite_rings.finite_field_constructor import GF
    from sage.modules.free_module_element import vector

    chosen_ineqs = []
    poly = convex_hull(valid_points)
    poly_points = poly.integral_points()
    remaining_ineqs = list(poly.inequalities())
    impossible = [vector(poly.base_ring(), v) for v in VectorSpace(GF(2), poly.ambient_dim()) if v not in poly_points]

    while impossible != []:
        if len(remaining_ineqs) == 0:
            raise ValueError("no more inequalities to choose, but still %d impossible points left" % len(impossible))

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
        impossible = [v for v in impossible if chosen_ineqs[-1].contains(v)]

    return chosen_ineqs


def cutting_off_milp(valid_points, number_of_ineqs=None):
    """
    Compute a set of inequalities that is cutting-off equivalent to the H-representation of the given convex hull by solving a MILP.

    The representation can either be computed from the minimal number of necessary inequalities, or by a given number
    of inequalities. This second variant might be faster, because the MILP solver that later uses this representation
    can do some optimizations itself.

    INPUT:
    - ``valid_points`` -- **matrix**; the polyhedron representing the convex hull
    - ``number_of_ineqs`` -- **integer** (default: `None`); number of inequalities that should be used for representing the
      S-box

    .. [SasTod17]_ "New Algorithm for Modeling S-box in MILP Based Differential and Division Trail Search"
    """
    from sage.matrix.constructor import matrix
    from sage.modules.free_module import VectorSpace
    from sage.modules.free_module_element import vector
    from sage.numerical.mip import MixedIntegerLinearProgram
    from sage.rings.finite_rings.finite_field_constructor import GF

    poly = convex_hull(valid_points)
    ineqs = list(poly.inequalities())
    poly_points = poly.integral_points()
    impossible = [vector(poly.base_ring(), v) for v in VectorSpace(GF(2), poly.ambient_dim()) if v not in poly_points]

    # precompute which inequality removes which impossible point
    precomputation = matrix([[int(not (ineq.contains(p))) for p in impossible] for ineq in ineqs])
    milp = MixedIntegerLinearProgram(maximization=False, solver=SOLVER_DEFAULT)
    var_ineqs = milp.new_variable(binary=True, name="ineqs")

    # either use the minimal number of inequalities for the representation
    if number_of_ineqs is None:
        milp.set_objective(sum([var_ineqs[i] for i in range(len(ineqs))]))
    # or the given number
    else:
        milp.add_constraint(sum([var_ineqs[i] for i in range(len(ineqs))]) == number_of_ineqs)

    nrows, ncols = precomputation.dimensions()
    for c in range(ncols):
        lhs = sum([var_ineqs[r] for r in range(nrows) if precomputation[r][c] == 1])
        # milp.add_constraint(lhs >= 1)
        if not isinstance(lhs, int):
            milp.add_constraint(lhs >= 1)

    milp.solve()

    remaining_ineqs = [ineq for ineq, (var, val) in zip(ineqs, milp.get_values(var_ineqs).items()) if val == 1]

    return remaining_ineqs
