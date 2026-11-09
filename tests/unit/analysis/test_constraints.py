from itertools import product

import pytest

from claasp import Primitive, UnitArrayType
from claasp.analysis import (
    AnalysisProblem,
    Equal,
    FixedValue,
    HammingWeight,
    MinimizeWeight,
    Nonzero,
    NotEqual,
)
from claasp.analysis.boolean import lower_boolean_problem
from claasp.components import Add
from claasp.drivers.solvers import SatResult, SatStatus
from claasp.unit_types import Bit


def _xor_primitive():
    primitive = Primitive(
        "xor", {"left": UnitArrayType(Bit(), (1,)), "key": UnitArrayType(Bit(), (1,))}
    )
    primitive._builder.add_round()
    output = primitive._builder.add_component(
        Add((primitive.graph.input("left"), primitive.graph.input("key")))
    )
    primitive._builder.set_output(output)
    return primitive


def _satisfying_assignments(formula):
    for values in product((0, 1), repeat=formula.variable_count):
        assignment = dict(zip(formula.variables, values))
        if formula.is_satisfied(assignment):
            yield assignment


class _ExhaustiveSolver:
    def solve(self, formula):
        assignment = next(_satisfying_assignments(formula), None)
        status = SatStatus.SATISFIABLE if assignment is not None else SatStatus.UNSATISFIABLE
        return SatResult(status, assignment, 0.0, "", "")


def test_fixed_values_and_graph_level_projection_need_no_solver_names():
    primitive = _xor_primitive()
    problem = AnalysisProblem(
        primitive,
        (FixedValue(primitive.graph.input("left"), 1), FixedValue(primitive.graph.output, 0)),
        {"recovered_key": primitive.graph.input("key")},
    )
    solutions = list(_satisfying_assignments(lower_boolean_problem(problem)))
    assert len(solutions) == 1
    assert solutions[0]["key_0"] == 1


def test_equality_inequality_nonzero_and_weight_constraints_lower_to_cnf():
    primitive = _xor_primitive()
    equal = AnalysisProblem(
        primitive, (Equal(primitive.graph.input("left"), primitive.graph.input("key")),)
    )
    assert len(list(_satisfying_assignments(lower_boolean_problem(equal)))) == 2
    unequal = AnalysisProblem(
        primitive, (NotEqual(primitive.graph.input("left"), primitive.graph.input("key")),)
    )
    assert len(list(_satisfying_assignments(lower_boolean_problem(unequal)))) == 2
    nonzero = AnalysisProblem(primitive, (Nonzero(primitive.graph.input("left")),))
    assert all(item["left_0"] for item in _satisfying_assignments(lower_boolean_problem(nonzero)))
    weight = AnalysisProblem(primitive, (HammingWeight(primitive.graph.input("left"), 1, 1),))
    assert all(item["left_0"] for item in _satisfying_assignments(lower_boolean_problem(weight)))


def test_objectives_are_portable_but_plain_minisat_lowering_rejects_optimization():
    primitive = _xor_primitive()
    problem = AnalysisProblem(primitive, objective=MinimizeWeight(primitive.graph.input("key")))
    with pytest.raises(NotImplementedError, match="optimization-capable"):
        lower_boolean_problem(problem)


def test_recovery_api_validates_user_facing_input_names():
    primitive = _xor_primitive()
    with pytest.raises(ValueError, match="unknown primitive input"):
        primitive.analysis.recover_input("missing", known_inputs={"left": 0}, output=0)
    with pytest.raises(ValueError, match="must not also be fixed"):
        primitive.analysis.recover_input("key", known_inputs={"left": 0, "key": 0}, output=0)


def test_fixed_value_rejects_wrong_sequence_length():
    primitive = _xor_primitive()
    problem = AnalysisProblem(primitive, (FixedValue(primitive.graph.input("left"), (0, 1)),))
    with pytest.raises(ValueError, match="length"):
        lower_boolean_problem(problem)


def test_solution_enumeration_blocks_projected_values_and_honors_limit():
    primitive = _xor_primitive()
    problem = AnalysisProblem(
        primitive,
        (FixedValue(primitive.graph.output, 0),),
        {"key": primitive.graph.input("key")},
    )
    results = primitive.analysis.enumerate_solutions(problem, limit=5, solver=_ExhaustiveSolver())
    assert {result.value("key") for result in results} == {0, 1}
    assert len(results) == 2
    assert all(result.provenance.realization is primitive.realization for result in results)
    assert all(result.provenance.driver.name == "_ExhaustiveSolver" for result in results)
    assert all(result.reproducibility["realization"] == "default" for result in results)


def test_solution_enumeration_requires_a_positive_limit_and_projection():
    primitive = _xor_primitive()
    with pytest.raises(ValueError, match="positive"):
        primitive.analysis.enumerate_solutions(
            AnalysisProblem(primitive, projections={"key": primitive.graph.input("key")}),
            limit=0,
            solver=_ExhaustiveSolver(),
        )
    with pytest.raises(ValueError, match="projection"):
        primitive.analysis.enumerate_solutions(
            AnalysisProblem(primitive), limit=1, solver=_ExhaustiveSolver()
        )


def test_recovery_rejects_a_solver_assignment_that_violates_the_requested_output():
    class InvalidSolver:
        def solve(self, formula):
            return SatResult(SatStatus.SATISFIABLE, dict.fromkeys(formula.variables, 0), 0, "", "")

    primitive = _xor_primitive()
    with pytest.raises(ValueError, match="invalid functional witness"):
        primitive.analysis.recover_input(
            "key", known_inputs={"left": 0}, output=1, solver=InvalidSolver()
        )


def test_trail_constraint_validation_and_snapshot():
    from claasp.analysis import Constraints
    from claasp.analysis.constraints import _trail_constraints
    from claasp.primitives import ToySpeck

    p = ToySpeck(1)
    for make in (
        lambda: Constraints().equal("key", True),
        lambda: Constraints().nonzero(""),
        lambda: Constraints().zero("key", bit_positions=()),
        lambda: Constraints().zero("key", bit_positions=(1, 1)),
        lambda: Constraints().zero("key", bit_positions=(True,)),
        lambda: Constraints().hamming_weight("key", exactly=True),
        lambda: Constraints().hamming_weight("key", minimum=3, maximum=1),
        lambda: Constraints().hamming_weight("key", exactly=1, maximum=2),
    ):
        with pytest.raises(ValueError):
            make()
    for c in (
        Constraints().zero("missing"),
        Constraints().zero("key", bit_positions=(16,)),
        Constraints().equal("key", 4, bit_positions=(0, 1)),
        Constraints().hamming_weight("key", exactly=17),
    ):
        with pytest.raises(ValueError):
            _trail_constraints(c, p)
    with pytest.raises(TypeError):
        _trail_constraints([], p)
    c = Constraints().nonzero("key")
    snapshot = _trail_constraints(c, p)
    c.zero("key")
    assert len(snapshot._items) == 1 and len(c._items) == 2


@pytest.mark.parametrize("kind", ["linear", "differential"])
def test_multiple_nonzero_inputs_and_selected_bit_weights(kind):
    import shutil

    if not shutil.which("z3"):
        pytest.skip("requires Z3")
    from claasp.analysis import Constraints
    from claasp.primitives import ToySpeck

    c = Constraints().nonzero("plaintext").hamming_weight("key", exactly=1)
    result = getattr(ToySpeck(1).analysis, f"find_one_xor_{kind}_trail")(constraints=c)
    inputs = dict(result.input_masks if kind == "linear" else result.input_differences)
    assert inputs["key"].bit_count() == 1 and inputs["plaintext"] != 0
    partial = Constraints().equal("key", 1, bit_positions=(0, 15)).hamming_weight("key", maximum=2)
    result = getattr(ToySpeck(1).analysis, f"find_one_xor_{kind}_trail")(constraints=partial)
    key = dict(result.input_masks if kind == "linear" else result.input_differences)["key"]
    assert key & 1 and not key & (1 << 15) and key.bit_count() <= 2
    # Contradictory restrictions are a valid UNSAT query, not a malformed search.
    assert (
        getattr(ToySpeck(1).analysis, f"find_one_xor_{kind}_trail")(
            constraints=Constraints().zero("key").nonzero("key")
        )
        is None
    )


@pytest.mark.parametrize(
    "backend,executable", [("sat", "kissat"), ("smt", "z3"), ("milp", "glpsol"), ("cp", "minizinc")]
)
def test_constraints_are_enforced_by_each_exact_backend(backend, executable):
    import shutil

    if not shutil.which(executable):
        pytest.skip(f"requires {executable}")
    from claasp.analysis import Constraints
    from claasp.primitives import ToySpeck

    if backend == "cp":
        import subprocess

        available = subprocess.run(
            [executable, "--solvers"], capture_output=True, text=True, check=True
        ).stdout
        if "gecode" not in available.lower():
            pytest.skip("requires a configured MiniZinc Gecode solver")
    c = Constraints().nonzero("key").nonzero("plaintext").hamming_weight("key", exactly=1)
    result = ToySpeck(1).analysis.find_optimal_trail("xor_linear", backend=backend, constraints=c)
    assert result.is_optimal
    # Obtain retained input masks from the backend-neutral component/round evidence.
    assert result.trail.input_pattern.value != 0
    inputs = dict(result.input_patterns)
    assert inputs["key"].value.bit_count() == 1 and inputs["plaintext"].value != 0
    from io import StringIO

    output = StringIO()
    result.to_terminal(file=output)
    assert "External input patterns" in output.getvalue() and "key" in output.getvalue()
    # The optimum is independently checked by the backend's decoded characteristic.
    assert result.trail.total_weight == 0


def test_constraint_auxiliaries_do_not_duplicate_enumerated_trails():
    import shutil

    if not shutil.which("z3"):
        pytest.skip("requires Z3")
    from claasp.analysis import Constraints
    from claasp.primitives.single_component_primitives import BitwiseNot

    p = BitwiseNot(3)
    c = Constraints().hamming_weight("input", exactly=1)
    results = p.analysis.enumerate_xor_linear_trails(constraints=c, limit=10).require_complete()
    assert len(results.trails) == 3
    assert {dict(trail.input_masks)["input"] for trail in results.trails} == {1, 2, 4}
    target = p.graph.components[0].component_id
    trail = p.analysis.find_one_xor_linear_trail(
        constraints=Constraints().equal(target, 2).equal("output", 2)
    )
    assert trail.output_mask == 2


def test_independent_constraint_checker_rejects_valid_but_disallowed_characteristic():
    import shutil

    if not shutil.which("z3"):
        pytest.skip("requires Z3")
    from claasp.analysis import Constraints
    from claasp.drivers.solvers import Z3Solver
    from claasp.primitives import ToySpeck
    from claasp.representations.constraints.smt import WordXorLinearSMTModel

    p = ToySpeck(1)
    base = WordXorLinearSMTModel(p, nonzero_input="plaintext", fixed_input_masks={"key": 0})
    solved = Z3Solver().solve(base.smt_formula())
    trail = base.decode_characteristic(solved.assignment)
    assert base.check_characteristic(trail)
    restricted = WordXorLinearSMTModel(
        p, nonzero_input="plaintext", constraints=Constraints().nonzero("key")
    )
    restricted.smt_formula()
    assert not restricted.check_characteristic(trail)


def test_constrained_search_cannot_silently_use_unconstrained_specialized_path():
    from claasp.analysis import Constraints
    from claasp.primitives import Speck

    with pytest.raises(NotImplementedError, match="solver-backed"):
        Speck(number_of_rounds=2).analysis.find_optimal_trail(
            backend="dependency_free", constraints=Constraints().nonzero("key")
        )


@pytest.mark.parametrize(
    "options,expected",
    [
        ({"minimum": 3}, {7}),
        ({"maximum": 3}, set(range(1, 8))),
        ({"maximum": 0}, set()),
        ({"minimum": 2, "maximum": 2}, {3, 5, 6}),
        ({"exactly": 1, "bit_positions": (0, 2)}, {1, 3, 4, 6}),
    ],
)
def test_hamming_bounds_and_ordered_bit_selection_match_exhaustive_reference(options, expected):
    import shutil

    if not shutil.which("z3"):
        pytest.skip("requires Z3")
    from claasp.analysis import Constraints
    from claasp.primitives.single_component_primitives import BitwiseNot

    p = BitwiseNot(3)
    result = p.analysis.enumerate_xor_linear_trails(
        constraints=Constraints().hamming_weight("input", **options), limit=20
    ).require_complete()
    assert {dict(trail.input_masks)["input"] for trail in result.trails} == expected


def test_not_equal_packed_value_and_explicit_defaults_are_not_silently_overridden():
    import shutil

    if not shutil.which("z3"):
        pytest.skip("requires Z3")
    from claasp.analysis import Constraints
    from claasp.primitives import ToySpeck
    from claasp.primitives.single_component_primitives import BitwiseNot

    result = (
        BitwiseNot(3)
        .analysis.enumerate_xor_linear_trails(
            constraints=Constraints().not_equal("input", 5), limit=20
        )
        .require_complete()
    )
    assert {dict(t.input_masks)["input"] for t in result.trails} == {1, 2, 3, 4, 6, 7}
    assert (
        ToySpeck(1).analysis.find_one_xor_linear_trail(
            fixed_input_masks={"key": 0}, constraints=Constraints().nonzero("key")
        )
        is None
    )


def test_invalid_explicit_patterns_are_not_removed_by_constraint_defaults():
    from claasp.analysis import Constraints
    from claasp.primitives import ToySpeck

    class ForbiddenSolver:
        def solve(self, formula):
            raise AssertionError("invalid input must fail before solving")

    with pytest.raises(ValueError, match="fixed masks"):
        ToySpeck(1).analysis.find_lowest_weight_xor_linear_trail(
            constraints=Constraints().nonzero("key"),
            fixed_input_masks={"key": None},
            solver=ForbiddenSolver(),
        )
