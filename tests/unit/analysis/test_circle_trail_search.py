"""Independent finite-function controls for the generic circle solver path."""

import shutil
from fractions import Fraction
from io import StringIO
from math import log2
from random import Random
from typing import Any, cast

import pytest

from claasp.analysis._circle_coordinates import circle_coordinate_graph
from claasp.analysis.circle_trail_search import find_circle_characteristic
from claasp.components import Constant, ModularAdd, SBox, Xor
from claasp.graph import Primitive, UnitArrayType
from claasp.primitives import ULBC, BitVectorSBox, Craft, Noekeon, Pride, Simon
from claasp.primitives.block_ciphers.craft import CRAFT_SBOX
from claasp.primitives.block_ciphers.pride import PRIDE_SBOX
from claasp.semantics.cryptanalysis import TrailKind
from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace, CircleBasis
from claasp.unit_types import Word

OPERATION = BinaryBibrace(4, ((8, 0, 8, 5),), (5,))
SOLVER = pytest.mark.skipif(shutil.which("kissat") is None, reason="requires kissat")


@pytest.mark.parametrize("factory", [Craft, Pride, Noekeon, ULBC, Simon])
def test_coordinate_graph_matches_original_real_cipher_with_fixed_nonzero_key(factory):
    p = factory(number_of_rounds=2)
    rng = Random(112)
    fixed = {
        name: rng.getrandbits(array.array_type.encoded_bit_size)
        for name, array in p.graph.input_arrays.items()
        if name != "plaintext"
    }
    result = circle_coordinate_graph(p, bibrace=OPERATION, fixed_inputs=fixed)
    assert set(result.primitive.graph.input_arrays) == {"plaintext"}
    for _ in range(12):
        x = rng.getrandbits(result.input_basis.width)
        expected = result.output_basis.theta(
            p.evaluate(
                {
                    "plaintext": result.input_basis.theta(x),
                    **fixed,
                }
            )
        )
        assert result.primitive.evaluate(x) == expected


def test_single_lookup_cancels_outer_coordinate_changes_without_orphan_weights():
    p = BitVectorSBox(4, CRAFT_SBOX)
    result = circle_coordinate_graph(p, bibrace=OPERATION, input_name="input")
    components = result.primitive.graph.components
    assert len(components) == 1
    assert components[0].table == tuple(
        OPERATION.theta(CRAFT_SBOX[OPERATION.theta(x)]) for x in range(16)
    )


def test_large_basis_uses_quadratic_circuit_and_heterogeneous_boundaries():
    operation = BinaryBibrace(9, ((256, 0, 0, 0, 0, 0, 0, 0, 1),), (2,))
    p = BitVectorSBox(9, tuple(range(512)))
    result = circle_coordinate_graph(
        p,
        input_name="input",
        input_basis=CircleBasis((operation,)),
        output_basis=CircleBasis((BinaryBibrace(4), BinaryBibrace(5))),
    )
    for x in range(512):
        assert result.primitive.evaluate(x) == operation.theta(x)
    assert all(
        len(c.table) <= 512 for c in result.primitive.graph.components if hasattr(c, "table")
    )
    # The only dense table is the original primitive's lookup, never theta.
    assert sum(hasattr(c, "table") for c in result.primitive.graph.components) == 1


@SOLVER
@pytest.mark.parametrize("kind", [TrailKind.XOR_DIFFERENTIAL, TrailKind.XOR_LINEAR])
@pytest.mark.parametrize("input_pattern", [1, 7, 9])
def test_generic_solver_optimum_matches_direct_circle_ddt_and_lat(kind, input_pattern):
    p = BitVectorSBox(4, CRAFT_SBOX)
    result = find_circle_characteristic(
        p,
        kind,
        bibrace=OPERATION,
        input_name="input",
        input_pattern=input_pattern,
    )
    if kind is TrailKind.XOR_DIFFERENTIAL:
        counts = [
            sum(
                OPERATION.circle(CRAFT_SBOX[x], CRAFT_SBOX[OPERATION.circle(x, input_pattern)]) == b
                for x in range(16)
            )
            for b in range(16)
        ]
        probability = Fraction(max(counts), 16)
        assert counts[result.output_pattern] == max(counts)
    else:
        walsh = [
            sum(
                (-1)
                ** (OPERATION.character(input_pattern, x) ^ OPERATION.character(b, CRAFT_SBOX[x]))
                for x in range(16)
            )
            for b in range(16)
        ]
        probability = Fraction(max(abs(w) for w in walsh), 16)
        assert abs(walsh[result.output_pattern]) == max(abs(w) for w in walsh)
    assert result.weight == pytest.approx(-log2(probability))
    assert result.is_optimal
    assert result.input_pattern == input_pattern
    endpoint = result.evaluate_endpoint()
    measured = endpoint.probability if kind is TrailKind.XOR_DIFFERENTIAL else abs(endpoint)
    assert measured == probability
    text = StringIO()
    result.to_terminal(file=text)
    assert "circle-coordinate component graph" in text.getvalue()
    assert "Proved optimal" in text.getvalue()


def test_nonlinear_key_schedule_and_unequal_round_layers_are_specialized_exactly():
    array = UnitArrayType(Word(4), (1,))
    p = Primitive("heterogeneous_key_schedule", {"plaintext": array, "key": array})
    b = p._builder
    b.add_round()
    key = b.add_component(ModularAdd((p.graph.input("key"), p.graph.input("key"))))
    state = b.add_component(Xor((p.graph.input("plaintext"), key)))
    state = b.add_component(SBox(state, CRAFT_SBOX))
    b.add_round()
    state = b.add_component(ModularAdd((state, b.add_component(Constant(array, (3,))))))
    b.set_output(state)
    for key_value in (1, 7, 13):
        result = circle_coordinate_graph(p, bibrace=OPERATION, fixed_inputs={"key": key_value})
        for x in range(16):
            evaluated = p.evaluate(OPERATION.theta(x), key_value)
            assert isinstance(evaluated, int)
            assert result.primitive.evaluate(x) == OPERATION.theta(evaluated)
    with pytest.raises(ValueError, match="fixed_inputs"):
        circle_coordinate_graph(p, bibrace=OPERATION)


@SOLVER
def test_public_facades_use_general_solver_without_plaintext_enumeration():
    p = BitVectorSBox(4, CRAFT_SBOX)
    differential = p.analysis.find_lowest_weight_circle_differential_trail(
        bibrace=OPERATION,
        input_name="input",
        backend="sat",
        maximum_inputs=1,
    )
    linear = p.analysis.find_lowest_weight_circle_linear_trail(
        bibrace=OPERATION,
        input_name="input",
        backend="sat",
    )
    assert differential.is_optimal and linear.is_optimal
    assert differential.input_pattern and linear.input_pattern
    assert linear.weight == 0


@pytest.mark.parametrize("backend,executable", [("smt", "z3"), ("milp", "glpsol")])
def test_generic_circle_search_reuses_alternative_solver_drivers(backend, executable):
    if shutil.which(executable) is None:
        pytest.skip(f"requires {executable}")
    p = BitVectorSBox(4, CRAFT_SBOX)
    result = p.analysis.find_lowest_weight_circle_differential_trail(
        bibrace=OPERATION,
        input_name="input",
        input_difference=1,
        backend=backend,
    )
    assert result.is_optimal and result.weight == 2
    assert result.evaluate_endpoint().probability == Fraction(1, 4)


@SOLVER
def test_endpoint_sampling_is_seeded_and_separate_from_search():
    p = BitVectorSBox(4, CRAFT_SBOX)
    result = p.analysis.find_lowest_weight_circle_differential_trail(
        bibrace=OPERATION,
        input_name="input",
        input_difference=1,
        backend="sat",
    )
    first = result.evaluate_endpoint(samples=128, seed=12)
    second = result.evaluate_endpoint(samples=128, seed=12)
    assert first == second and not first.complete
    assert first.lower <= Fraction(1, 4) <= first.upper
    with pytest.raises(ValueError, match="maximum_inputs"):
        result.evaluate_endpoint(maximum_inputs=1)


@SOLVER
def test_large_denominator_probability_optimum_is_certified_without_bitwise_bisection():
    from claasp.drivers.solvers import KissatSolver

    class CountingSolver:
        def __init__(self):
            self.driver = KissatSolver()
            self.calls = 0

        def solve(self, formula):
            self.calls += 1
            return self.driver.solve(formula)

    p = Primitive("parallel_fractional", {"plaintext": UnitArrayType(Word(4), (16,))})
    p._builder.add_round()
    p._builder.set_output(p._builder.add_component(SBox(p.graph.input("plaintext"), PRIDE_SBOX)))
    solver = CountingSolver()
    result = p.analysis.find_lowest_weight_circle_differential_trail(
        bibrace=OPERATION,
        backend="sat",
        solver=solver,
    )
    # Independent DDT enumeration: the best nonzero cell difference has 8/16
    # probability, so a single active cell achieves the global bank optimum.
    counts = [
        sum(
            OPERATION.circle(PRIDE_SBOX[x], PRIDE_SBOX[OPERATION.circle(x, a)]) == b
            for x in range(16)
        )
        for a in range(1, 16)
        for b in range(16)
    ]
    assert max(counts) == 8
    assert result.is_optimal and result.weight == 1
    assert solver.calls <= 8


@SOLVER
def test_output_difference_constraint_is_applied_in_circle_coordinates():
    p = BitVectorSBox(4, CRAFT_SBOX)
    result = p.analysis.find_lowest_weight_circle_differential_trail(
        bibrace=OPERATION,
        input_name="input",
        input_difference=1,
        output_difference=11,
        backend="sat",
    )
    assert result.input_pattern == 1 and result.output_pattern == 11
    assert result.evaluate_endpoint().probability > 0
    with pytest.raises(RuntimeError, match="no nonzero"):
        p.analysis.find_lowest_weight_circle_differential_trail(
            bibrace=OPERATION,
            input_name="input",
            input_difference=1,
            output_difference=12,
            backend="sat",
        )


@SOLVER
@pytest.mark.parametrize(
    "factory,differential_weight,linear_weight", [(Craft, 1, 0), (Simon, 0, 0)]
)
def test_real_primitive_solver_searches_use_shared_characteristic_checks(
    factory, differential_weight, linear_weight
):
    p = factory(number_of_rounds=1)
    fixed = {name: 0 for name in p.graph.input_arrays if name != "plaintext"}
    for kind, expected in (("differential", differential_weight), ("linear", linear_weight)):
        result = getattr(p.analysis, f"find_lowest_weight_circle_{kind}_trail")(
            bibrace=OPERATION,
            fixed_inputs=fixed,
            backend="sat",
        )
        assert result.is_optimal and result.weight == expected


@SOLVER
def test_circle_plot_reuses_shared_series_and_declares_its_graph_scope():
    matplotlib = pytest.importorskip("matplotlib")
    matplotlib.use("Agg")
    from matplotlib import pyplot as plt

    result = BitVectorSBox(4, CRAFT_SBOX).analysis.find_lowest_weight_circle_linear_trail(
        bibrace=OPERATION,
        input_name="input",
        input_mask=1,
        backend="sat",
    )
    artifact = result.plot(show=False)
    assert "coordinate graph" in cast(Any, artifact.figure).axes[0].get_title()
    assert artifact.series == result.search_result.plot(show=False).series
    plt.close("all")
