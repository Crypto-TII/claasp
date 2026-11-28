"""Check the bounded logarithm model at interval ends and old failure points."""

import math

from minizinc import Instance, Model, Solver

from claasp.cipher_modules.models.cp.minizinc_utils.mzn_approx_logarithm_predicate import (
    get_approx_logarithm_operation,
)


def test_piecewise_logarithm_bounds_and_continuity():
    points = [0.0, 2**-33, 2**-32, 0.0010214536, 0.0010214538]
    points += [2**-bits for bits in range(31, 0, -1)]
    points += [0.595815289564374, 0.7, 0.998000001, 0.999, 1.0]
    model = Model()
    model.add_string(get_approx_logarithm_operation())
    model.add_string(
        f"array[0..{len(points) - 1}] of float: p = "
        f"array1d(0..{len(points) - 1}, {points});\n"
        f"array[0..{len(points) - 1}] of var 0..3200: w;\n"
        f"constraint forall(i in 0..{len(points) - 1})(approx_prob_log(p[i], w[i]));\n"
        "solve satisfy;\n"
    )
    weights = Instance(Solver.lookup("gecode"), model).solve()["w"]
    assert weights[:3] == [3200, 3200, 3200]
    for point, weight in zip(points[3:], weights[3:]):
        exact = -math.log2(point)
        assert exact - 1e-7 <= weight / 100
        if point >= 2**-20:
            assert weight / 100 <= exact + 0.10
        elif point >= 2**-32:
            assert weight / 100 <= exact + 1.0
    assert weights[-1] == 0
    assert abs(weights[3] - weights[4]) <= 1
