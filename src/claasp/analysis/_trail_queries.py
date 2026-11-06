"""Single-witness execution for the public exact characteristic queries."""

from claasp.drivers.solvers import SatStatus, Z3Solver


def first_characteristic(model, solver=None):
    driver = Z3Solver() if solver is None else solver
    if not callable(getattr(driver, "solve", None)):
        raise TypeError("solver must provide a solve(formula) method")
    result = driver.solve(model.smt_formula())
    if result.status is SatStatus.UNSATISFIABLE:
        return None
    if result.status is not SatStatus.SATISFIABLE:
        raise RuntimeError("solver did not complete the characteristic query")
    if result.assignment is None:
        raise RuntimeError("solver returned SAT without a characteristic assignment")
    characteristic = model.decode_characteristic(result.assignment)
    if not model.check_characteristic(characteristic):
        raise RuntimeError("characteristic failed independent graph validation")
    return characteristic
