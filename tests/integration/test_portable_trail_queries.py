"""Real-backend coverage of the public exact Boolean query contract."""

import importlib.util
import os
import shutil
import subprocess
from itertools import product
from math import isclose, log2

import pytest

from claasp.analysis import Constraints
from claasp.components import BitVectorSBox, Xor
from claasp.drivers.solvers import (
    GLPKSolver,
    HighsSolver,
    KissatSolver,
    MinisatSolver,
    MiniZincSolver,
    Z3Solver,
)
from claasp.graph import Primitive, UnitArrayType
from claasp.primitives import Speck
from claasp.primitives.toy_primitives.heys import HEYS_SBOX
from claasp.representations.constraints.sat import (
    WordDeterministicTruncatedSATModel,
    WordXorDifferentialSATModel,
    WordXorLinearSATModel,
)
from claasp.unit_types import Bit

pytestmark = pytest.mark.external
_SELECTED = os.environ.get("CLAASP_QUERY_BACKENDS")
_BACKENDS = (_SELECTED or "kissat,minisat,z3,glpk,highs,minizinc").split(",")


@pytest.fixture(params=_BACKENDS)
def driver(request):
    name = request.param
    factories = {
        "kissat": KissatSolver,
        "minisat": MinisatSolver,
        "z3": Z3Solver,
        "glpk": GLPKSolver,
        "highs": HighsSolver,
        "minizinc": MiniZincSolver,
    }
    assert name in factories, f"unknown query test backend {name}"
    executable = {
        "kissat": "kissat",
        "minisat": "minisat",
        "z3": "z3",
        "glpk": "glpsol",
        "minizinc": "minizinc",
    }.get(name)
    available = (
        bool(shutil.which(executable))
        if executable
        else importlib.util.find_spec("scipy") is not None
    )
    if name == "minizinc" and available:
        assert executable is not None
        listing = subprocess.run(
            [executable, "--solvers"], capture_output=True, text=True, check=True
        )
        available = "gecode" in listing.stdout.lower()
    if not available:
        if _SELECTED:
            pytest.fail(f"CI explicitly selected unavailable backend {name}")
        pytest.skip(f"requires configured {name}")
    if name == "minizinc":
        return MiniZincSolver(solver="gecode", timeout_seconds=30)
    return factories[name](timeout_seconds=30)


def _and_primitive(keyed=False):
    inputs = {"plaintext": UnitArrayType(Bit(), (2,))}
    if keyed:
        inputs["key"] = inputs["plaintext"]
    p = Primitive("two_bit_and", inputs)
    p._builder.add_round()
    source = p.graph.input("plaintext")
    if keyed:
        source = p._builder.add_component(Xor((source, p.graph.input("key"))))
    output = p._builder.add_component(BitVectorSBox(source, (0, 0, 0, 1), output_bit_size=1))
    p._builder.set_output(output)
    return p


def _fixed(kind):
    return {
        "fixed_input_masks" if kind == "linear" else "fixed_input_differences": {"plaintext": 1}
    }


def _assert_exact_one(trail, kind):
    assert trail.total_weight == 1
    if kind == "linear":
        assert dict(trail.input_masks)["plaintext"] == 1
        assert trail.output_mask == 1
        assert trail.sign == 1
        # Independent Walsh sum, not the model's transition table.
        assert sum((-1) ** (((x & 1).bit_count() + ((x >> 1) & x & 1)) % 2) for x in range(4)) == 2
    else:
        assert dict(trail.input_differences)["plaintext"] == 1
        assert trail.output_difference == 1
        # Independent DDT count for AND under XOR difference 01.
        f = lambda x: (x >> 1) & x & 1
        assert sum(f(x) ^ f(x ^ 1) == 1 for x in range(4)) == 2


@pytest.mark.parametrize("kind", ("linear", "differential"))
@pytest.mark.parametrize("query", ("one", "fixed", "bounded", "enumerate"))
def test_all_eight_public_query_entry_points_use_the_supplied_backend(driver, kind, query):
    analysis = _and_primitive().analysis
    options = dict(solver=driver, constraints=Constraints().equal("output", 1), **_fixed(kind))
    if query == "one":
        result = getattr(analysis, f"find_one_xor_{kind}_trail")(
            minimum_weight=1, maximum_weight=1, **options
        )
    elif query == "fixed":
        result = getattr(analysis, f"find_one_xor_{kind}_trail_with_fixed_weight")(1, **options)
    else:
        method = (
            f"find_all_xor_{kind}_trails_with_weight_at_most"
            if query == "bounded"
            else f"enumerate_xor_{kind}_trails"
        )
        result = getattr(analysis, method)(minimum_weight=1, maximum_weight=1, limit=10, **options)
        assert result.require_complete().complete and len(result.trails) == 1
        result = result.trails[0]
    assert result is not None
    _assert_exact_one(result, kind)


@pytest.mark.parametrize("kind", ("linear", "differential"))
def test_empty_intervals_and_semantic_enumeration_limits_are_preserved(driver, kind):
    analysis = _and_primitive().analysis
    options = dict(solver=driver, constraints=Constraints().equal("output", 1))
    assert getattr(analysis, f"find_one_xor_{kind}_trail_with_fixed_weight")(0, **options) is None
    empty = getattr(analysis, f"enumerate_xor_{kind}_trails")(0, **options)
    assert empty.complete and not empty.trails
    bounded = getattr(analysis, f"enumerate_xor_{kind}_trails")(
        1, minimum_weight=1, limit=1, **options
    )
    assert len(bounded.trails) == 1 and not bounded.complete
    with pytest.raises(RuntimeError, match="incomplete"):
        bounded.require_complete()
    all_trails = getattr(analysis, f"enumerate_xor_{kind}_trails")(
        1, minimum_weight=1, limit=10, **options
    )
    assert all_trails.complete and len(all_trails.trails) == 3
    masks = [
        dict(t.input_masks if kind == "linear" else t.input_differences)["plaintext"]
        for t in all_trails.trails
    ]
    assert sorted(masks) == [1, 2, 3]


@pytest.mark.parametrize("kind", ("linear", "differential"))
def test_related_key_constraints_reach_every_portable_backend(driver, kind):
    p = _and_primitive(keyed=True)
    constraints = (
        Constraints()
        .nonzero("plaintext")
        .nonzero("key")
        .hamming_weight("key", exactly=1)
        .equal("output", 1)
    )
    trail = getattr(p.analysis, f"find_one_xor_{kind}_trail")(
        1, solver=driver, constraints=constraints
    )
    assert trail is not None and trail.total_weight == 1
    inputs = dict(trail.input_masks if kind == "linear" else trail.input_differences)
    assert inputs["plaintext"] != 0 and inputs["key"].bit_count() == 1

    def evaluate(x, k):
        value = x ^ k
        return (value >> 1) & value & 1

    assert all(
        p.evaluate(plaintext=x, key=k) == evaluate(x, k) for x, k in product(range(4), repeat=2)
    )
    if kind == "differential":
        count = sum(
            (evaluate(x, k) ^ evaluate(x ^ inputs["plaintext"], k ^ inputs["key"])) == 1
            for x, k in product(range(4), repeat=2)
        )
        assert count == 8
    else:
        walsh = sum(
            (-1)
            ** (
                (x & inputs["plaintext"]).bit_count()
                + (k & inputs["key"]).bit_count()
                + evaluate(x, k)
            )
            for x, k in product(range(4), repeat=2)
        )
        assert abs(walsh) == 8


@pytest.mark.parametrize("kind,weight", (("differential", 1.415), ("linear", 0.415)))
def test_fractional_physical_weight_intervals_survive_portable_execution(driver, kind, weight):
    p = Primitive("fractional_sbox", {"plaintext": UnitArrayType(Bit(), (4,))})
    p._builder.add_round()
    p._builder.set_output(
        p._builder.add_component(BitVectorSBox(p.graph.input("plaintext"), HEYS_SBOX))
    )
    # Derive a reference transition by direct exhaustive counting, without
    # calling the library DDT/LAT implementation.
    for a, b in product(range(1, 16), repeat=2):
        count = (
            sum(HEYS_SBOX[x] ^ HEYS_SBOX[x ^ a] == b for x in range(16))
            if kind == "differential"
            else abs(
                sum(
                    (-1) ** ((a & x).bit_count() + (b & HEYS_SBOX[x]).bit_count())
                    for x in range(16)
                )
            )
        )
        if count == (6 if kind == "differential" else 12):
            break
    else:
        raise AssertionError("reference S-box must contain the fractional transition")
    options = {
        "fixed_input_differences" if kind == "differential" else "fixed_input_masks": {
            "plaintext": a
        }
    }
    trail = getattr(p.analysis, f"find_one_xor_{kind}_trail_with_fixed_weight")(
        weight,
        weight_tolerance=0.001,
        solver=driver,
        constraints=Constraints().equal("output", b),
        **options,
    )
    assert trail is not None and weight - 0.001 <= trail.total_weight <= weight + 0.001
    assert isclose(trail.total_weight, -log2(count / 16))


def test_reported_speck_kissat_query_is_supported(driver):
    if not isinstance(driver, KissatSolver):
        pytest.skip("the reported Kissat regression")
    result = Speck(number_of_rounds=2).analysis.find_all_xor_linear_trails_with_weight_at_most(
        minimum_weight=1, maximum_weight=1, solver=driver, limit=1
    )
    assert len(result.trails) == 1 and result.trails[0].total_weight == 1


@pytest.mark.parametrize("kind", ("linear", "differential", "truncated"))
def test_sat_model_enumeration_accepts_z3_incremental_sessions(driver, kind):
    if not isinstance(driver, Z3Solver):
        pytest.skip("the Z3/CNF incremental regression")
    p = _and_primitive()
    model: WordXorLinearSATModel | WordXorDifferentialSATModel | WordDeterministicTruncatedSATModel
    if kind == "linear":
        model = WordXorLinearSATModel(p, maximum_weight=1, fixed_input_masks={"plaintext": 1})
    elif kind == "differential":
        model = WordXorDifferentialSATModel(
            p, maximum_weight=1, fixed_input_differences={"plaintext": 1}, output_difference=1
        )
    else:
        model = WordDeterministicTruncatedSATModel(p, fixed_input_patterns={"plaintext": "01"})
    result = model.enumerate_trails(driver, limit=10)
    assert result.complete and result.trails
    assert all(model.check_characteristic(trail) for trail in result.trails)


@pytest.mark.parametrize("kind", ("linear", "differential"))
@pytest.mark.parametrize("route", ("facade", "sat_model"))
def test_repeated_base_witness_is_rejected_when_it_violates_a_block(driver, kind, route):
    class Replay:
        def __init__(self):
            self.result = None

        def solve(self, formula):
            if self.result is None:
                self.result = driver.solve(formula)
            return self.result

    primitive = _and_primitive()
    replay = Replay()
    with pytest.raises(RuntimeError, match="enumeration blocks"):
        if route == "facade":
            getattr(primitive.analysis, f"enumerate_xor_{kind}_trails")(1, solver=replay, limit=2)
        else:
            model = (
                WordXorLinearSATModel(primitive, maximum_weight=1, nonzero_input="plaintext")
                if kind == "linear"
                else WordXorDifferentialSATModel(
                    primitive, maximum_weight=1, nonzero_input="plaintext"
                )
            )
            model.enumerate_trails(replay, limit=2)
