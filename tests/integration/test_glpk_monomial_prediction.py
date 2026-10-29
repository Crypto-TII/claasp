"""Open-source solver integration for exact monomial transitions."""

import pytest

from claasp.drivers.solvers import GLPKSolver, MILPStatus
from claasp.representations.constraints.milp import MonomialTransitionMILPModel

pytestmark = pytest.mark.external

PRESENT = (12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2)


def test_glpk_accepts_exact_and_rejects_impossible_present_monomial_transitions():
    representation = MonomialTransitionMILPModel(PRESENT)
    output_mask = 1
    possible = min(representation.table[output_mask])
    impossible = next(mask for mask in range(16) if mask not in representation.table[output_mask])
    solver = GLPKSolver(timeout_seconds=10)

    accepted = solver.solve(representation.milp_model(possible, output_mask))
    rejected = solver.solve(representation.milp_model(impossible, output_mask))

    assert accepted.status is MILPStatus.OPTIMAL
    assert accepted.assignment is not None
    assert rejected.status is MILPStatus.INFEASIBLE


def test_high_level_degree_cancels_paths_instead_of_claiming_reachability_is_exact():
    from claasp import Primitive, UnitArrayType
    from claasp.components import Xor
    from claasp.unit_types import Bit

    primitive = Primitive("cancel", {"plaintext": UnitArrayType(Bit(), (1,))})
    primitive._builder.add_round()
    source = primitive.graph.input("plaintext")
    output = primitive._builder.add_component(Xor((source, source)))
    primitive._builder.set_output(output)
    bound = primitive.analysis.algebraic_degree(solver=GLPKSolver(timeout_seconds=10))
    assert bound.upper_bound == 1 and bound.exact_degree is None
    exact = primitive.analysis.algebraic_degree(
        exact=True, solver=GLPKSolver(timeout_seconds=10)
    ).require_complete()
    assert exact.exact_degree == -1
    assert exact.enumerated_paths == 2
    limited = primitive.analysis.algebraic_degree(
        exact=True, maximum_paths=1, solver=GLPKSolver(timeout_seconds=10)
    )
    assert not limited.complete and limited.exact_degree is None
    with pytest.raises(RuntimeError):
        limited.require_complete()


def test_solver_superpoly_matches_exact_symbolic_cube_coefficient():
    from claasp.primitives import Simon

    primitive = Simon(number_of_rounds=2)
    positions = (1, 8)
    solver = GLPKSolver(timeout_seconds=10)
    result = primitive.analysis.superpoly(
        positions, output_bit=0, solver=solver, zero_outside_cube=True
    ).require_complete()
    anf = primitive.analysis.anf(output_bit=0)
    cube = tuple(f"p{i}" for i in positions)
    fixed = {f"p{i}": 0 for i in range(32) if i not in positions}
    expected = anf.superpoly(cube, fixed_variables=fixed).polynomials[0]
    assert result.polynomial == expected
    limited = primitive.analysis.superpoly(positions, output_bit=0, solver=solver, maximum_paths=1)
    if not limited.complete:
        assert limited.polynomial is None


def test_superpoly_keeps_public_variables_and_can_select_the_key_coefficient():
    from claasp.primitives import Simon

    primitive = Simon(number_of_rounds=1)
    full = primitive.analysis.superpoly((1,), output_bit=0).require_complete()
    key_coefficient = primitive.analysis.superpoly(
        (1,), output_bit=0, zero_outside_cube=True
    ).require_complete()
    assert full.polynomial == primitive.analysis.anf(output_bit=0).superpoly(("p1",)).polynomials[0]
    assert full.polynomial.degree == 1
    assert key_coefficient.polynomial.degree == -1
    degree = primitive.analysis.algebraic_degree(
        output_bit=0, variable_positions=(1,), exact=True
    ).require_complete()
    assert degree.exact_degree == 1


def test_monomial_workflow_api_doctests():
    """Run optional-solver API examples with their real driver in CI."""
    import doctest
    import importlib

    from claasp.analysis import Analysis, find_algebraic_degree, recover_superpoly

    runner = doctest.DocTestRunner()
    for method in (
        Analysis.algebraic_degree,
        Analysis.superpoly,
        find_algebraic_degree,
        recover_superpoly,
    ):
        module = importlib.import_module(method.__module__)
        docstring = method.__doc__
        assert docstring is not None
        test = doctest.DocTestParser().get_doctest(
            docstring, vars(module).copy(), method.__qualname__, module.__file__, 0
        )
        assert test.examples
        for example in test.examples:
            example.options[doctest.SKIP] = False
        runner.run(test)
    assert runner.summarize().failed == 0
