
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


def mod_binary_operation_polynomials(x, y, z, c, is_addition):
    """
    Return a set of polynomials representing `(x * y) mod 2^{n}`.

    Where `*` is either addition or subtraction depends on whether `is_addition` argument is set to `True` or `False`.
    If the carry variable `c` is `None`, it generates a set of algebraic normal form of each coordinate Boolean
    function.

    INPUT:

    - ``x`` -- **list/tuple**; input variables
    - ``y`` -- **list/tuple**; input variables
    - ``z`` -- **list/tuple**; output variables
    - ``c`` -- **list/tuple**; carry variables
    - ``is_addition`` -- **boolean**
    """
    if not (isinstance(x, (list, tuple)) and isinstance(y, (list, tuple)) and isinstance(z, (list, tuple))):
        raise TypeError("x, y, z must either be a list or tuple")

    n = len(x)
    if len(y) != n or len(z) != n:
        raise ValueError("the length of x, y, z must be equal")

    #  the algebraic normal form of majority function
    def maj(xi, yi, zi):
        return xi * yi + xi * zi + yi * zi

    if is_addition:
        f = lambda x: x
    else:
        f = lambda x: x + 1

    F = []
    if c is not None:
        if not isinstance(c, (list, tuple)):
            raise TypeError("c must either be a list or tuple")

        F += [c[0] + 0]
        F += [x[0] + y[0] + z[0] + c[0]]
        for i in range(1, n):
            F += [c[i] + maj(f(x[i - 1]), y[i - 1], c[i - 1])]
            F += [x[i] + y[i] + z[i] + c[i]]
    else:
        ci = 0
        F += [x[0] + y[0] + z[0] + ci]
        for i in range(1, n):
            ci = maj(f(x[i - 1]), y[i - 1], ci)
            F += [x[i] + y[i] + z[i] + ci]

    return F


def mod_addition_polynomials(x, y, z, c=None):
    """
    Return a set of polynomials representing `(x + y) mod 2^{n}`.

    If the carry variable `c` is not provided, it generates a set of algebraic normal form of each coordinate Boolean
    function.

    INPUT:

    - ``x`` -- **list/tuple**; input variables
    - ``y`` -- **list/tuple**; input variables
    - ``z`` -- **list/tuple**; output variables
    - ``c`` -- **list/tuple** (default: `None`); carry variables

    EXAMPLES::

        sage: from claasp.cipher_modules.models.algebraic.constraints import mod_addition_polynomials
        sage: lx = [ "x%d" % (i) for i in range(8) ]
        sage: ly = [ "y%d" % (i) for i in range(8) ]
        sage: lz = [ "z%d" % (i) for i in range(8) ]
        sage: lc = [ "c%d" % (i) for i in range(8) ]
        sage: R = BooleanPolynomialRing(32, lx + ly + lz + lc)
        sage: x = [ R(v) for v in lx ]
        sage: y = [ R(v) for v in ly ]
        sage: z = [ R(v) for v in lz ]
        sage: c = [ R(v) for v in lc ]
        sage: F0 = Sequence(mod_addition_polynomials(x, y, z, c))
        sage: F0
        [c0,
         x0 + y0 + z0 + c0,
         x0*y0 + x0*c0 + y0*c0 + c1,
         x1 + y1 + z1 + c1,
         x1*y1 + x1*c1 + y1*c1 + c2,
         x2 + y2 + z2 + c2,
         x2*y2 + x2*c2 + y2*c2 + c3,
         x3 + y3 + z3 + c3,
         x3*y3 + x3*c3 + y3*c3 + c4,
         x4 + y4 + z4 + c4,
         x4*y4 + x4*c4 + y4*c4 + c5,
         x5 + y5 + z5 + c5,
         x5*y5 + x5*c5 + y5*c5 + c6,
         x6 + y6 + z6 + c6,
         x6*y6 + x6*c6 + y6*c6 + c7,
         x7 + y7 + z7 + c7]

        sage: F1 = Sequence(mod_addition_polynomials(x, y, z))
        sage: len(F1) == 8
        True

        sage: V = VectorSpace(GF(2), 8)
        sage: vx = V.random_element()
        sage: vy = V.random_element()
        sage: sub_vars = { x[i] : vx[i] for i in range(8) }
        sage: sub_vars.update( { y[i] : vy[i] for i in range(8) } )
        sage: F0s, F1s = F0.subs(sub_vars), F1.subs(sub_vars)
        sage: F0s_elim = F0s.eliminate_linear_variables(skip=lambda lm, tail: str(lm)[0] == 'z')
        sage: F1s == F0s_elim
        True

        sage: nx, ny = ZZ(list(vx), base=2), ZZ(list(vy), base=2)
        sage: nz = (nx + ny) % 2**8
        sage: bz = ZZ(nz).digits(base=2, padto=8)
        sage: bz == [ f.constant_coefficient() for f in F0s_elim ]
        True

        sage: bz == [ f.constant_coefficient() for f in F1s ]
        True
    """
    return mod_binary_operation_polynomials(x, y, z, c, is_addition=True)


def mod_subtraction_polynomials(x, y, z, c=None):
    """
    Return a set of polynomials representing `(x - y) mod 2^{n}`.

    If the carry variable `c` is not provided, it generates a set of algebraic normal form of each coordinate Boolean
    function.

    INPUT:

    - ``x`` -- **list/tuple**; input variables
    - ``y`` -- **list/tuple**; input variables
    - ``z`` -- **list/tuple**; output variables
    - ``c`` -- **list/tuple** (default: `None`); carry variables

    EXAMPLES::

        sage: from claasp.cipher_modules.models.algebraic.constraints import mod_subtraction_polynomials
        sage: lx = [ "x%d" % (i) for i in range(8) ]
        sage: ly = [ "y%d" % (i) for i in range(8) ]
        sage: lz = [ "z%d" % (i) for i in range(8) ]
        sage: lc = [ "c%d" % (i) for i in range(8) ]
        sage: R = BooleanPolynomialRing(32, lx + ly + lz + lc)
        sage: x = [ R(v) for v in lx ]
        sage: y = [ R(v) for v in ly ]
        sage: z = [ R(v) for v in lz ]
        sage: c = [ R(v) for v in lc ]
        sage: F0 = Sequence(mod_subtraction_polynomials(x, y, z, c))
        sage: F0
        [c0,
         x0 + y0 + z0 + c0,
         x0*y0 + x0*c0 + y0*c0 + y0 + c0 + c1,
         x1 + y1 + z1 + c1,
         x1*y1 + x1*c1 + y1*c1 + y1 + c1 + c2,
         x2 + y2 + z2 + c2,
         x2*y2 + x2*c2 + y2*c2 + y2 + c2 + c3,
         x3 + y3 + z3 + c3,
         x3*y3 + x3*c3 + y3*c3 + y3 + c3 + c4,
         x4 + y4 + z4 + c4,
         x4*y4 + x4*c4 + y4*c4 + y4 + c4 + c5,
         x5 + y5 + z5 + c5,
         x5*y5 + x5*c5 + y5*c5 + y5 + c5 + c6,
         x6 + y6 + z6 + c6,
         x6*y6 + x6*c6 + y6*c6 + y6 + c6 + c7,
         x7 + y7 + z7 + c7]

        sage: F1 = Sequence(mod_subtraction_polynomials(x, y, z))
        sage: len(F1) == 8
        True

        sage: V = VectorSpace(GF(2), 8)
        sage: vx = V.random_element()
        sage: vy = V.random_element()
        sage: sub_vars = { x[i] : vx[i] for i in range(8) }
        sage: sub_vars.update( { y[i] : vy[i] for i in range(8) } )
        sage: F0s, F1s = F0.subs(sub_vars), F1.subs(sub_vars)
        sage: F0s_elim = F0s.eliminate_linear_variables(skip=lambda lm, tail: str(lm)[0] == 'z')
        sage: F1s == F0s_elim
        True

        sage: nx, ny = ZZ(list(vx), base=2), ZZ(list(vy), base=2)
        sage: nz = (nx - ny) % 2**8
        sage: bz = ZZ(nz).digits(base=2, padto=8)
        sage: bz == [ f.constant_coefficient() for f in F0s_elim ]
        True

        sage: bz == [ f.constant_coefficient() for f in F1s ]
        True
    """
    return mod_binary_operation_polynomials(x, y, z, c, is_addition=False)


def equality_polynomials(x, y):
    """
    Return a list of polynomials that represent ``x = y``.

    INPUT:

    - ``x`` -- **list**; variables
    - ``y`` -- **list**; variables

    EXAMPLES::

        sage: from claasp.cipher_modules.models.algebraic.constraints import equality_polynomials
        sage: R.<x0, x1, x2, y0, y1, y2> = GF(2)[]
        sage: equality_polynomials([x0, x1, x2], [y0, y1, y2])
        [x0 + y0, x1 + y1, x2 + y2]
    """
    if len(x) != len(y):
        raise ValueError("the length of x must be equal to the length of y")
    from operator import sub

    return list(map(sub, x, y))
