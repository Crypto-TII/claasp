import pytest
from sage.rings.integer_ring import ZZ
from sage.structure.sequence import Sequence
from sage.modules.free_module import VectorSpace
from sage.rings.polynomial.pbori.pbori import BooleanPolynomialRing
from sage.rings.polynomial.polynomial_ring_constructor import PolynomialRing
from sage.rings.finite_rings.finite_field_constructor import FiniteField as GF

from claasp.cipher_modules.models.algebraic.constraints import (mod_addition_polynomials, mod_subtraction_polynomials,
                                                                equality_polynomials)


def test_equality_polynomials():
    R = PolynomialRing(GF(2), ['x0', 'x1', 'x2', 'y0', 'y1', 'y2'])
    x0 = R.gen(0)
    x1 = R.gen(1)
    x2 = R.gen(2)
    y0 = R.gen(3)
    y1 = R.gen(4)
    y2 = R.gen(5)
    assert equality_polynomials([x0, x1, x2], [y0, y1, y2]) == [x0 + y0, x1 + y1, x2 + y2]

    with pytest.raises(ValueError, match="the length of x must be equal to the length of y"):
        equality_polynomials([x0, x1, x2], [y0, y1])


def test_mod_addition_polynomials():
    lx = ["x%d" % i for i in range(8)]
    ly = ["y%d" % i for i in range(8)]
    lz = ["z%d" % i for i in range(8)]
    lc = ["c%d" % i for i in range(8)]
    R = BooleanPolynomialRing(32, lx + ly + lz + lc)
    x = [R(v) for v in lx]
    y = [R(v) for v in ly]
    z = [R(v) for v in lz]
    c = [R(v) for v in lc]
    F0 = Sequence(mod_addition_polynomials(x, y, z, c))

    assert str(F0) == f'[c0,' \
                      f' x0 + y0 + z0 + c0,' \
                      f' x0*y0 + x0*c0 + y0*c0 + c1,' \
                      f' x1 + y1 + z1 + c1,' \
                      f' x1*y1 + x1*c1 + y1*c1 + c2,' \
                      f' x2 + y2 + z2 + c2,' \
                      f' x2*y2 + x2*c2 + y2*c2 + c3,' \
                      f' x3 + y3 + z3 + c3,' \
                      f' x3*y3 + x3*c3 + y3*c3 + c4,' \
                      f' x4 + y4 + z4 + c4,' \
                      f' x4*y4 + x4*c4 + y4*c4 + c5,' \
                      f' x5 + y5 + z5 + c5,' \
                      f' x5*y5 + x5*c5 + y5*c5 + c6,' \
                      f' x6 + y6 + z6 + c6,' \
                      f' x6*y6 + x6*c6 + y6*c6 + c7,' \
                      f' x7 + y7 + z7 + c7]'

    lx = ["x%d" % i for i in range(8)]
    ly = ["y%d" % i for i in range(8)]
    lz = ["z%d" % i for i in range(8)]
    lc = ["c%d" % i for i in range(8)]
    R = BooleanPolynomialRing(32, lx + ly + lz + lc)
    x = [R(v) for v in lx]
    y = [R(v) for v in ly]
    z = [R(v) for v in lz]

    F1 = Sequence(mod_addition_polynomials(x, y, z))
    assert len(F1) == 8

    V = VectorSpace(GF(2), 8)
    vx = V.random_element()
    vy = V.random_element()
    sub_vars = {x[i]: vx[i] for i in range(8)}
    sub_vars.update({y[i]: vy[i] for i in range(8)})
    F0s, F1s = F0.subs(sub_vars), F1.subs(sub_vars)
    F0s_elim = F0s.eliminate_linear_variables(skip=lambda lm, tail: str(lm)[0] == 'z')
    assert F1s == F0s_elim

    nx, ny = ZZ(list(vx), base=2), ZZ(list(vy), base=2)
    nz = (nx + ny) % 2 ** 8
    bz = ZZ(nz).digits(base=2, padto=8)
    assert bz == [f.constant_coefficient() for f in F0s_elim]

    assert bz == [f.constant_coefficient() for f in F1s]


def test_mod_subtraction_polynomials():
    lx = ["x%d" % i for i in range(8)]
    ly = ["y%d" % i for i in range(8)]
    lz = ["z%d" % i for i in range(8)]
    lc = ["c%d" % i for i in range(8)]
    R = BooleanPolynomialRing(32, lx + ly + lz + lc)
    x = [R(v) for v in lx]
    y = [R(v) for v in ly]
    z = [R(v) for v in lz]
    c = [R(v) for v in lc]
    F0 = Sequence(mod_subtraction_polynomials(x, y, z, c))
    assert str(F0) == f'[c0,' \
                      f' x0 + y0 + z0 + c0,' \
                      f' x0*y0 + x0*c0 + y0*c0 + y0 + c0 + c1,' \
                      f' x1 + y1 + z1 + c1,' \
                      f' x1*y1 + x1*c1 + y1*c1 + y1 + c1 + c2,' \
                      f' x2 + y2 + z2 + c2,' \
                      f' x2*y2 + x2*c2 + y2*c2 + y2 + c2 + c3,' \
                      f' x3 + y3 + z3 + c3,' \
                      f' x3*y3 + x3*c3 + y3*c3 + y3 + c3 + c4,' \
                      f' x4 + y4 + z4 + c4,' \
                      f' x4*y4 + x4*c4 + y4*c4 + y4 + c4 + c5,' \
                      f' x5 + y5 + z5 + c5,' \
                      f' x5*y5 + x5*c5 + y5*c5 + y5 + c5 + c6,' \
                      f' x6 + y6 + z6 + c6,' \
                      f' x6*y6 + x6*c6 + y6*c6 + y6 + c6 + c7,' \
                      f' x7 + y7 + z7 + c7]'

    F1 = Sequence(mod_subtraction_polynomials(x, y, z))
    assert len(F1) == 8

    V = VectorSpace(GF(2), 8)
    vx = V.random_element()
    vy = V.random_element()
    sub_vars = {x[i]: vx[i] for i in range(8)}
    sub_vars.update({y[i]: vy[i] for i in range(8)})
    F0s, F1s = F0.subs(sub_vars), F1.subs(sub_vars)
    F0s_elim = F0s.eliminate_linear_variables(skip=lambda lm, tail: str(lm)[0] == 'z')
    assert F1s == F0s_elim

    nx, ny = ZZ(list(vx), base=2), ZZ(list(vy), base=2)
    nz = (nx - ny) % 2 ** 8
    bz = ZZ(nz).digits(base=2, padto=8)
    assert bz == [f.constant_coefficient() for f in F0s_elim]

    assert bz == [f.constant_coefficient() for f in F1s]
