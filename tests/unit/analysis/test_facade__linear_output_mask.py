"""Public fixed linear endpoints are solver constraints, with independent checks."""

from dataclasses import replace
from itertools import product
from types import SimpleNamespace

import pytest

from claasp import Primitive, UnitArrayType
from claasp.components import BitwiseAnd, Xor
from claasp.drivers.solvers import SatResult, SatStatus
from claasp.primitives import BitVectorSBox
from claasp.representations.constraints.cp import WordXorLinearCPModel
from claasp.representations.constraints.milp import WordXorLinearMILPModel
from claasp.representations.constraints.sat import (
    WordXorLinearNativeXorSATModel,
    WordXorLinearSATModel,
)
from claasp.representations.constraints.smt import WordXorLinearSMTModel
from claasp.unit_types import Word


class _ExhaustiveSolver:
    """Tiny exhaustive Boolean oracle; no optional solver installation required."""

    def solve(self, formula):
        for values in product((0, 1), repeat=len(formula.variables)):
            assignment = dict(zip(formula.variables, values))
            if formula.is_satisfied(assignment):
                return SatResult(SatStatus.SATISFIABLE, assignment, 0, "", "")
        return SatResult(SatStatus.UNSATISFIABLE, None, 0, "", "")


def _formula(model):
    return (
        model.smt_formula().to_cnf()
        if isinstance(model, WordXorLinearSMTModel)
        else model.cnf_formula()
    )


def _and():
    p = Primitive("and", {"plaintext": UnitArrayType(Word(1), (2,))})
    p._builder.add_round()
    source = p.graph.input("plaintext")
    p._builder.set_output(p._builder.add_component(BitwiseAnd((source[0], source[1]))))
    return p


@pytest.mark.parametrize(
    "model_type", [WordXorLinearSMTModel, WordXorLinearSATModel, WordXorLinearNativeXorSATModel]
)
def test_fixed_formula_endpoints_and_independent_validator(model_type):
    p = BitVectorSBox(2, (0, 1, 2, 3))
    solver = _ExhaustiveSolver()
    for output, possible in ((1, True), (2, False), (0, False)):
        model = model_type(p, maximum_weight=0, fixed_input_masks={"input": 1}, output_mask=output)
        formula = _formula(model)
        assert "fixed_output_mask" in formula.provenance
        solved = solver.solve(formula)
        assert (solved.status is SatStatus.SATISFIABLE) == possible
        if possible:
            trail = model.decode_characteristic(solved.assignment)
            assert trail.output_mask == output
            assert model.check_characteristic(trail)
            assert not model.check_characteristic(replace(trail, output_mask=2))
    # A valid unrestricted witness for another endpoint must fail the restricted
    # independent validator even though its graph relations remain valid.
    unrestricted = model_type(p, maximum_weight=0, fixed_input_masks={"input": 2})
    other = unrestricted.decode_characteristic(solver.solve(_formula(unrestricted)).assignment)
    restricted = model_type(p, maximum_weight=0, output_mask=1)
    _formula(restricted)
    assert not restricted.check_characteristic(other)


@pytest.mark.parametrize("model_type", [WordXorLinearSMTModel, WordXorLinearSATModel])
def test_zero_is_explicit_and_none_is_unrestricted(model_type):
    p = BitVectorSBox(2, (0, 1, 2, 3))
    zero = model_type(p, maximum_weight=0, output_mask=0)
    solved = _ExhaustiveSolver().solve(_formula(zero))
    assert zero.decode_characteristic(solved.assignment).output_mask == 0
    active = model_type(p, maximum_weight=0, output_mask=0, nonzero_input="input")
    assert _ExhaustiveSolver().solve(_formula(active)).status is SatStatus.UNSATISFIABLE
    unrestricted = model_type(p, maximum_weight=0, nonzero_input="input")
    assert "fixed_output_mask" not in _formula(unrestricted).provenance
    result = unrestricted.enumerate_trails(_ExhaustiveSolver(), limit=8).require_complete()
    assert {trail.output_mask for trail in result.trails} == {1, 2, 3}


@pytest.mark.parametrize(
    "model_type",
    [
        WordXorLinearSMTModel,
        WordXorLinearSATModel,
        WordXorLinearNativeXorSATModel,
        WordXorLinearMILPModel,
        WordXorLinearCPModel,
    ],
)
@pytest.mark.parametrize("value", [-1, 4, True, 1.0, "01"])
def test_invalid_masks_are_rejected_at_all_direct_constructors(model_type, value):
    with pytest.raises(ValueError, match="output mask"):
        model_type(BitVectorSBox(2, (0, 1, 2, 3)), maximum_weight=0, output_mask=value)


@pytest.mark.parametrize("model_type", [WordXorLinearSMTModel, WordXorLinearSATModel])
def test_multi_unit_selected_output_and_final_xor_fanout(model_type):
    p = Primitive("selected_xor", {"plaintext": UnitArrayType(Word(1), (3,))})
    p._builder.add_round()
    source = p.graph.input("plaintext")
    final = p._builder.add_component(Xor((source, source.select(1, 2, 0))))
    p._builder.set_output(final.select(2, 0))
    # Output 01 selects final bit 0 = x0 XOR x1; the external mask has
    # two units, whereas the final component has three. Input 110 is required.
    for output_mask, input_mask, possible in (
        (0b01, 0b110, True),
        (0b01, 0b101, False),
        (0b10, 0b101, True),
        (0b11, 0b011, True),
    ):
        model = model_type(
            p,
            maximum_weight=0,
            fixed_input_masks={"plaintext": input_mask},
            output_mask=output_mask,
        )
        solved = _ExhaustiveSolver().solve(_formula(model))
        assert (solved.status is SatStatus.SATISFIABLE) == possible
        if possible:
            trail = model.decode_characteristic(solved.assignment)
            assert trail.output_mask == output_mask and model.check_characteristic(trail)
    with pytest.raises(ValueError, match="output mask"):
        model_type(p, maximum_weight=0, output_mask=0b100)


@pytest.mark.parametrize("query", ["one", "fixed", "bounded", "enumerate"])
def test_facade_helpers_fix_both_endpoints_without_post_filtering(query):
    analysis = BitVectorSBox(3, tuple(range(8))).analysis
    solver = _ExhaustiveSolver()
    for mask, possible in ((0b001, True), (0b010, False), (0, False)):
        options = dict(solver=solver, fixed_input_masks={"input": 0b001}, output_mask=mask)
        if query == "one":
            result = analysis.find_one_xor_linear_trail(maximum_weight=0, **options)
        elif query == "fixed":
            result = analysis.find_one_xor_linear_trail_with_fixed_weight(0, **options)
        else:
            method = (
                analysis.find_all_xor_linear_trails_with_weight_at_most
                if query == "bounded"
                else analysis.enumerate_xor_linear_trails
            )
            collection = method(maximum_weight=0, limit=8, **options).require_complete()
            assert dict(collection.reproducibility)["output_mask"] == repr(mask)
            result = collection.trails[0] if collection.trails else None
        assert (result is not None) == possible
        if result is not None:
            assert result.output_mask == mask


@pytest.mark.parametrize("model_type", [WordXorLinearSMTModel, WordXorLinearSATModel])
def test_enumeration_restricts_before_limit_and_preserves_sign_and_weight(model_type):
    model = model_type(_and(), maximum_weight=1, output_mask=1, nonzero_input="plaintext")
    limited = model.enumerate_trails(_ExhaustiveSolver(), limit=1)
    assert not limited.complete and len(limited.trails) == 1
    assert all(trail.output_mask == 1 for trail in limited.trails)
    complete = model.enumerate_trails(_ExhaustiveSolver(), limit=8).require_complete()
    assert len(complete.trails) == 3
    assert dict(complete.reproducibility)["output_mask"] == "1"
    for trail in complete.trails:
        mask = dict(trail.input_masks)["plaintext"]
        coefficient = (
            sum((-1) ** (((mask & x).bit_count() + ((x >> 1) & x & 1)) % 2) for x in range(4)) / 4
        )
        assert trail.output_mask == 1 and trail.total_weight == 1
        assert trail.sign == (1 if coefficient > 0 else -1)
        assert model.check_characteristic(trail)
    assert any(trail.sign == -1 for trail in complete.trails)


def test_output_mask_preserves_default_and_explicit_concrete_keys():
    p = Primitive(
        "keyed_xor",
        {"plaintext": UnitArrayType(Word(1), (1,)), "key": UnitArrayType(Word(1), (1,))},
    )
    p._builder.add_round()
    p._builder.set_output(
        p._builder.add_component(Xor((p.graph.input("plaintext"), p.graph.input("key"))))
    )
    solver = _ExhaustiveSolver()
    default = p.analysis.enumerate_xor_linear_trails(
        0, output_mask=1, solver=solver
    ).require_complete()
    assert dict(default.reproducibility)["fixed_inputs"] == "(('key', 0),)"
    assert len(default.trails) == 1 and default.trails[0].sign == 1
    explicit = p.analysis.find_one_xor_linear_trail(
        0, fixed_input_masks={"plaintext": 1}, fixed_inputs={"key": 1}, output_mask=1, solver=solver
    )
    assert explicit is not None and explicit.sign == -1
    assert dict(explicit.input_masks) == {"plaintext": 1, "key": 0}


@pytest.mark.parametrize("query", ["find_one_xor_linear_trail", "enumerate_xor_linear_trails"])
@pytest.mark.parametrize("behavior", ["raise", "unknown"])
def test_solver_failures_never_become_proved_unsat(query, behavior):
    class Interrupted:
        def solve(self, formula):
            if behavior == "raise":
                raise TimeoutError("interrupted")
            return SimpleNamespace(status="unknown", runtime_seconds=0)

    method = getattr(BitVectorSBox(2, (0, 1, 2, 3)).analysis, query)
    if behavior == "raise":
        with pytest.raises(TimeoutError):
            method(0, output_mask=1, solver=Interrupted())
    elif query == "find_one_xor_linear_trail":
        with pytest.raises(RuntimeError, match="did not complete"):
            method(0, output_mask=1, solver=Interrupted())
    else:
        result = method(0, output_mask=1, solver=Interrupted())
        assert not result.complete and not result.trails


def test_requested_mask_is_reached_before_the_enumeration_limit():
    # Without a solver-side restriction the exhaustive oracle returns mask
    # 001 first. Post-filtering a one-trail budget would miss mask 111.
    result = BitVectorSBox(3, tuple(range(8))).analysis.enumerate_xor_linear_trails(
        maximum_weight=0, output_mask=0b111, limit=1, solver=_ExhaustiveSolver()
    )
    assert len(result.trails) == 1
    assert result.trails[0].output_mask == 0b111


@pytest.mark.parametrize(
    "query",
    [
        "find_one_xor_linear_trail",
        "find_one_xor_linear_trail_with_fixed_weight",
        "find_all_xor_linear_trails_with_weight_at_most",
        "enumerate_xor_linear_trails",
    ],
)
@pytest.mark.parametrize("mask", [-1, 0b1000, False])
def test_facade_rejects_invalid_masks_before_solver_execution(query, mask):
    class Forbidden:
        def solve(self, formula):
            raise AssertionError("invalid output mask reached solver")

    method = getattr(BitVectorSBox(3, tuple(range(8))).analysis, query)
    with pytest.raises(ValueError, match="output mask"):
        method(0, output_mask=mask, solver=Forbidden())
