"""Single-witness execution for the public exact characteristic queries."""

from claasp.drivers.solvers import SatStatus, Z3Solver
from claasp.representations.constraints._execution import _checked_assignment


def first_characteristic(model, solver=None):
    driver = Z3Solver() if solver is None else solver
    if not callable(getattr(driver, "solve", None)):
        raise TypeError("solver must provide a solve(formula) method")
    formula = model.smt_formula().to_cnf()
    result = driver.solve(formula)
    if result.status is SatStatus.UNSATISFIABLE:
        return None
    if result.status is not SatStatus.SATISFIABLE:
        raise RuntimeError("solver did not complete the characteristic query")
    characteristic = model.decode_characteristic(_checked_assignment(formula, result))
    if not model.check_characteristic(characteristic):
        raise RuntimeError("characteristic failed independent graph validation")
    return characteristic
