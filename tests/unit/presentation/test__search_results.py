"""Public search-result coverage and independently specified presentation evidence."""

from fractions import Fraction
from io import StringIO
from types import SimpleNamespace

import pytest

from claasp.analysis.advanced_trails import CPCharacteristicResult, TruncatedPropagationResult
from claasp.analysis.boomerang_search import BoomerangSearchResult, BoomerangSearchStatus
from claasp.analysis.composed_search import (
    ImpossibleCandidate,
    ImpossibleSearchResult,
    XorDifferentialLinearSearchResult,
)
from claasp.analysis.continuous_differential import ContinuousCorrelationResult
from claasp.analysis.division_property import _DivisionPropertyTrail
from claasp.analysis.minimax_differential import MinimaxDifferentialResult
from claasp.analysis.quasidifferential import (
    FixedKeyProbabilityResult,
    QuasidifferentialEnumeration,
    QuasidifferentialTrail,
)
from claasp.analysis.wordwise_activity import ActiveSBoxResult
from claasp.presentation._search_results import _view
from claasp.representations.constraints.cp.trails import (
    ModularAddBoomerangTrailResult,
    PresentKeyScheduleXorDifferentialTrail,
    SBoxBoomerangTrailResult,
)
from claasp.representations.constraints.milp.trails import WordwiseActivityResult
from claasp.representations.constraints.sat.boomerang import ARXBoomerangTrail
from claasp.representations.constraints.sat.partitioned_differential import (
    PartitionedDifferentialTrail,
)
from claasp.representations.constraints.sat.trails import (
    AutomaticWordImpossibleSATResult,
    SemiDeterministicModularAddTransition,
    SharedDifferencePairedSATTrail,
    SharedDifferencePairedXorDifferentialLinearSATTrail,
    SpeckSemiDeterministicTruncatedTrail,
    WordDeterministicTruncatedCharacteristic,
    WordDeterministicTruncatedEnumeration,
    WordDeterministicXorDifferentialLinearSATTrail,
    WordImpossibleSATTrail,
    WordSemiDeterministicXorDifferentialLinearSATTrail,
    WordwiseDeterministicTruncatedCharacteristic,
    WordwiseImpossibleMiddle,
    WordwiseImpossibleSATTrail,
)
from claasp.representations.constraints.smt.word_xor_differential import (
    WordXorDifferentialCharacteristic,
    WordXorDifferentialEnumeration,
)
from claasp.representations.constraints.smt.word_xor_linear import (
    WordXorLinearCharacteristic,
    WordXorLinearEnumeration,
)
from claasp.semantics.cryptanalysis import (
    BoomerangConnectivity,
    BoomerangSwitchBoundary,
    BoomerangTrail,
    ImpossiblePropagationBoundary,
    ProbabilisticTruncatedModularAddTransition,
    ProbabilisticTruncatedTrail,
    Trail,
    TrailKind,
    TrailStep,
    Transition,
    TruncatedXorDifference,
    WordwiseDifferenceKind,
    WordwiseXorDifference,
    XorDifference,
    XorDifferentialLinearTrail,
    XorMask,
)
from claasp.semantics.cryptanalysis.quasidifferential import QuasidifferentialTransition


def _fixtures():
    zero = TruncatedXorDifference.parse("00?")
    one = TruncatedXorDifference.parse("01?")
    boundary = ImpossiblePropagationBoundary(one, zero)
    truncated = WordDeterministicTruncatedCharacteristic((("plaintext", one),), zero, (), ())
    impossible = WordImpossibleSATTrail(truncated, truncated, boundary, ())
    known = WordwiseXorDifference.known(4, 3)
    unknown = WordwiseXorDifference(4, WordwiseDifferenceKind.UNKNOWN)
    words = WordwiseDeterministicTruncatedCharacteristic(
        (("plaintext", (known, unknown)),), (known, unknown), (), ()
    )
    word_impossible = WordwiseImpossibleSATTrail(
        words, words, WordwiseImpossibleMiddle((1, 3), (0, 3), (0,)), ()
    )
    dt = Transition(TrailKind.XOR_DIFFERENTIAL, XorDifference(1, 2), XorDifference(2, 2), 1, 4)
    lt = Transition(TrailKind.XOR_LINEAR, XorMask(1, 2), XorMask(2, 2), 1, 8, sign=-1)
    differential = WordXorDifferentialCharacteristic(
        (("plaintext", 1),), 2, (TrailStep("sbox_0", dt),), ()
    )
    linear = WordXorLinearCharacteristic((("plaintext", 1),), 2, (TrailStep("sbox_0", lt),), 1, ())
    partitioned = PartitionedDifferentialTrail(differential, 2, 3)
    boomerang = ARXBoomerangTrail(
        differential, differential, (("add_1", (0, 0, 0, 0), Fraction(1, 4)),), 4
    )
    composed = WordDeterministicXorDifferentialLinearSATTrail(differential, truncated, linear)
    paired = SharedDifferencePairedSATTrail(differential, differential)
    probabilistic = ProbabilisticTruncatedTrail(
        zero,
        zero,
        (ProbabilisticTruncatedModularAddTransition(zero, zero, zero, zero, (100, 41, 0)),),
    )
    # A unit signed coefficient supplies a simple local-factor witness.
    qstep = QuasidifferentialTransition((0, 0), 0, (1, 1), 1, Fraction(1))
    qtrail = QuasidifferentialTrail("toy", {}, {}, 0, 1, (("xor_0", qstep),), Fraction(1))
    semantic_diff = Trail(
        TrailKind.XOR_DIFFERENTIAL,
        XorDifference(1, 2),
        XorDifference(2, 2),
        (TrailStep("sbox_0", dt),),
    )
    semantic_linear = Trail(
        TrailKind.XOR_LINEAR, XorMask(1, 2), XorMask(2, 2), (TrailStep("sbox_0", lt),)
    )
    connector_pattern = TruncatedXorDifference.parse("00")
    connector = ProbabilisticTruncatedTrail(
        connector_pattern,
        connector_pattern,
        (
            ProbabilisticTruncatedModularAddTransition(
                connector_pattern, connector_pattern, connector_pattern, connector_pattern, (100, 0)
            ),
        ),
    )
    switch = BoomerangSwitchBoundary(
        XorDifference(2, 2), XorDifference(0, 2), XorDifference(0, 2), XorDifference(1, 2), 1.0
    )
    return {
        "semantic_boomerang": BoomerangTrail(semantic_diff, switch, semantic_diff),
        "semantic_differential_linear": XorDifferentialLinearTrail(
            semantic_diff, connector, semantic_linear
        ),
        "characteristic_differential": differential,
        "characteristic_linear": linear,
        "enumeration_differential": WordXorDifferentialEnumeration((differential,), False, 0),
        "enumeration_linear": WordXorLinearEnumeration((linear,), True, 0),
        "truncated": truncated,
        "truncated_enumeration": WordDeterministicTruncatedEnumeration((truncated,), False, 0, ()),
        "wordwise": words,
        "impossible_trail": impossible,
        "wordwise_impossible": word_impossible,
        "impossible_search": ImpossibleSearchResult(
            (ImpossibleCandidate(1, impossible, "bitwise"),), (1,), False, "candidate limit"
        ),
        "automatic_impossible": AutomaticWordImpossibleSATResult(1, impossible, (1,), "found"),
        "boundary": boundary,
        "propagation": TruncatedPropagationResult((one, zero), "toy"),
        "cp_impossible": CPCharacteristicResult(boundary, 0, "fixture", ()),
        "cp_probabilistic": CPCharacteristicResult(probabilistic, 0, "fixture", ()),
        "cp_bct": CPCharacteristicResult(
            BoomerangConnectivity(XorDifference(1, 2), XorDifference(2, 2), 2), 0, "fixture", ()
        ),
        "probabilistic": probabilistic,
        "semideterministic": SpeckSemiDeterministicTruncatedTrail(zero, zero, ()),
        "differential_linear": composed,
        "differential_linear_search": XorDifferentialLinearSearchResult(
            composed, (1, 1, 1), Fraction(1, 256), ((1, 1, 1),), True
        ),
        "semideterministic_linear": WordSemiDeterministicXorDifferentialLinearSATTrail(
            differential,
            SpeckSemiDeterministicTruncatedTrail(
                zero, zero, (SemiDeterministicModularAddTransition(zero, zero, zero, 41),)
            ),
            linear,
        ),
        "paired": paired,
        "paired_linear": SharedDifferencePairedXorDifferentialLinearSATTrail(paired, linear),
        "minimax": MinimaxDifferentialResult("satisfiable", partitioned, True),
        "partitioned": partitioned,
        "boomerang": boomerang,
        "boomerang_search": BoomerangSearchResult(
            BoomerangSearchStatus.SATISFIABLE, boomerang, True
        ),
        "quasidifferential": qtrail,
        "quasidifferential_enumeration": QuasidifferentialEnumeration(
            (qtrail,), False, "trail limit"
        ),
        "fixed_key": FixedKeyProbabilityResult(
            Fraction(1), False, 1, "trail limit", trails=(qtrail,)
        ),
        "continuous": ContinuousCorrelationResult({}, (-0.5, 0.25, 0.75), 0b101, False, "analytic"),
        "activity": ActiveSBoxResult("feasible", 5, False),
        "activity_witness": WordwiseActivityResult(1, (("sbox_0", 1),)),
        "key_schedule": PresentKeyScheduleXorDifferentialTrail(1, (1, 2), (2,), 2),
        "cp_add_boomerang": ModularAddBoomerangTrailResult(
            differential, SimpleNamespace(weight=1), differential
        ),
        "cp_sbox_boomerang": SBoxBoomerangTrailResult(
            differential, SimpleNamespace(weight=1), differential, 0
        ),
        "semantic_trail": Trail(
            TrailKind.XOR_DIFFERENTIAL,
            XorDifference(1, 2),
            XorDifference(2, 2),
            (TrailStep("sbox_0", dt),),
        ),
        "division": _DivisionPropertyTrail([28, 10, 4, 2, 1]),
    }


@pytest.fixture(autouse=True)
def _close_figures():
    matplotlib = pytest.importorskip("matplotlib", reason="requires the presentation extra")
    matplotlib.use("Agg")
    yield
    from matplotlib import pyplot as plt

    plt.close("all")


@pytest.mark.parametrize("name", list(_fixtures()))
def test_all_search_result_families_render_retained_evidence(name, tmp_path):
    result = _fixtures()[name]
    output = StringIO()
    result.to_terminal(file=output)
    assert output.getvalue().strip()
    target = tmp_path / (name + ".png")
    artifact = result.plot(show=False, save_to=target)
    assert artifact.kind == "search_evidence"
    assert target.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    # Compare the figure artists to the returned data, not just method existence.
    plotted = [tuple(line.get_ydata()) for ax in artifact.figure.axes for line in ax.lines]
    assert plotted == [values for _, values in artifact.series]
    assert len(artifact.figure.axes) == max(1, len(_view(result).panels))


def _series(result):
    return dict(result.plot(show=False).series)


def test_exact_characteristic_weights_and_linear_sign():
    samples = _fixtures()
    assert list(_series(samples["characteristic_differential"]).values()) == [(2.0,), (2.0,)]
    assert list(_series(samples["characteristic_linear"]).values()) == [(3.0,), (3.0,)]
    assert samples["characteristic_linear"].sign == -1
    assert "correlation sign: -1" in "\n".join(_view(samples["characteristic_linear"]).notes)


def test_impossible_contradictions_and_unknown_categories():
    data = list(_series(_fixtures()["impossible_search"]).values())
    assert data == [(0.0, 1.0, 2.0), (0.0, 0.0, 2.0), (0.0, 1.0, 0.0)]
    # Both unknown bits are represented explicitly and do not contradict.
    artifact = _fixtures()["impossible_search"].plot(show=False)
    assert [tick.get_text() for tick in artifact.figure.axes[0].get_yticklabels()] == [
        "0",
        "1",
        "?",
    ]
    data = list(_series(_fixtures()["wordwise_impossible"]).values())
    assert data == [(1.0, 3.0), (0.0, 3.0), (1.0, 0.0)]


def test_model_objectives_are_not_interchanged():
    samples = _fixtures()
    assert list(_series(samples["differential_linear_search"]).values()) == [(2.0, 6.0)]
    assert list(_series(samples["minimax"]).values()) == [(2.0, 3.0)]
    assert samples["minimax"].trail.objective_weight == 3
    assert list(_series(samples["boomerang"]).values()) == [(2.0, 2.0), (0.25,)]
    assert list(_series(samples["cp_add_boomerang"]).values()) == [(4.0, 1.0, 4.0)]
    assert list(_series(samples["probabilistic"]).values()) == [(1.41,), (1.41,)]
    assert list(_series(samples["semideterministic_linear"]).values()) == [(2.0, 6.0), (0.41,)]


def test_signed_factors_and_partial_sums_preserve_negative_values():
    # A reported signed sequence, independent of any solver or plotting implementation.
    steps = tuple(
        (f"c{i}", QuasidifferentialTransition((0,), 0, (0,), 0, value))
        for i, value in enumerate((Fraction(-1, 2), Fraction(1, 4), Fraction(-1)))
    )
    trail = QuasidifferentialTrail("fixture", {}, {}, 0, 0, steps, Fraction(1, 8))
    assert list(_series(trail).values()) == [(-0.5, 0.25, -1.0), (-0.5, -0.125, 0.125)]
    negative = QuasidifferentialTrail("fixture", {}, {}, 0, 0, (), Fraction(-1, 2))
    positive = QuasidifferentialTrail("fixture", {}, {}, 0, 0, (), Fraction(1, 4))
    result = FixedKeyProbabilityResult(
        Fraction(-1, 4), False, 2, "trail limit", trails=(negative, positive)
    )
    assert list(_series(result).values()) == [(-0.5, -0.25)]
    assert "not a probability proof" in " ".join(_view(result).notes)
    with pytest.raises(RuntimeError):
        _ = result.probability


def test_continuous_mask_uses_msb_order_and_retains_signed_correlations():
    result = _fixtures()["continuous"]
    assert list(_series(result).values()) == [(-0.5, 0.25, 0.75), (1.0, 0.0, 1.0)]
    assert result.correlation == 0.375
    assert "Heuristic" in " ".join(_view(result).notes)


@pytest.mark.parametrize(
    "result",
    [
        ImpossibleSearchResult((), (1, 2), False, "solver unknown"),
        ImpossibleSearchResult((), (1, 2), True, "exhausted UNSAT"),
        XorDifferentialLinearSearchResult(None, None, None, (), False),
        MinimaxDifferentialResult("unknown", diagnostic="timeout"),
        BoomerangSearchResult(BoomerangSearchStatus.UNSATISFIABLE),
        QuasidifferentialEnumeration((), False, "timeout"),
        WordXorDifferentialEnumeration((), True, 0),
        ActiveSBoxResult("unknown", None, False),
    ],
)
def test_empty_unsat_and_interrupted_searches_do_not_invent_witnesses(result):
    artifact = result.plot(show=False)
    assert artifact.series == ()
    assert not artifact.figure.axes[0].lines
    assert "No retained witness" in artifact.figure.axes[0].texts[0].get_text()
    notes = " ".join(_view(result).notes)
    assert any(word in notes for word in ("False", "True", "unsatisfiable", "unknown"))


def test_show_save_failure_cleanup_and_no_solver_call(monkeypatch, tmp_path):
    from matplotlib import pyplot as plt

    from claasp.drivers.solvers import KissatSolver, Z3Solver

    def forbidden(*args, **kwargs):
        pytest.fail("presentation must never invoke a solver")

    monkeypatch.setattr(KissatSolver, "solve", forbidden)
    monkeypatch.setattr(Z3Solver, "solve", forbidden)
    shown = []
    monkeypatch.setattr(plt, "show", lambda: shown.append(True))
    result = _fixtures()["impossible_search"]
    result.to_terminal(file=StringIO())
    result.plot(show=False)
    assert not shown
    result.plot(show=True)
    assert shown == [True]
    before = set(plt.get_fignums())
    with pytest.raises(FileNotFoundError):
        result.plot(show=False, save_to=tmp_path / "missing" / "plot.png")
    assert set(plt.get_fignums()) == before


def test_dependency_free_import_and_terminal_without_matplotlib():
    import os
    import subprocess
    import sys

    script = """
import sys
sys.modules['matplotlib'] = None
from claasp.analysis import ImpossibleSearchResult
from io import StringIO
result = ImpossibleSearchResult((), (1,), False, 'unknown')
result.to_terminal(file=StringIO())
try:
    result.plot(show=False)
except ImportError as error:
    assert "optional 'presentation' dependency" in str(error)
else:
    raise AssertionError('missing optional dependency must be reported')
"""
    subprocess.run([sys.executable, "-c", script], check=True, env=os.environ.copy())


def test_division_property_list_compatibility_and_step_axis():
    from claasp.primitives import Present

    search = Present(number_of_rounds=2).analysis.division_property()
    result = search.find_division_property_trail(search.todo_input(28))
    assert isinstance(result, list)
    assert result == [28, 10, 4, 2, 1]
    assert list(_series(result).values()) == [(28.0, 10.0, 4.0, 2.0, 1.0)]


def test_result_family_inventory_covers_all_new_reporting_methods():
    """Every result with these presentation adapters must have a rendering fixture."""
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parents[3] / "src" / "claasp"
    expected = set()
    for path in root.rglob("*.py"):
        for node in ast.parse(path.read_text()).body:
            if isinstance(node, ast.ClassDef) and any(
                isinstance(method, ast.FunctionDef)
                and method.name == "plot"
                and any(
                    isinstance(child, ast.ImportFrom)
                    and child.module == "claasp.drivers.renderers._search_results"
                    for child in ast.walk(method)
                )
                for method in node.body
            ):
                expected.add(node.name)
    assert expected == {type(result).__name__ for result in _fixtures().values()}


@pytest.mark.parametrize(
    "method,options",
    [
        ("find_one_xor_differential_trail", {}),
        ("find_one_xor_differential_trail_with_fixed_weight", {"fixed_weight": 1}),
        ("find_all_xor_differential_trails_with_weight_at_most", {"maximum_weight": 1, "limit": 2}),
        ("find_lowest_weight_xor_differential_trail", {}),
        ("find_one_xor_linear_trail", {}),
        ("find_one_xor_linear_trail_with_fixed_weight", {"fixed_weight": 1}),
        ("find_all_xor_linear_trails_with_weight_at_most", {"maximum_weight": 1, "limit": 2}),
        ("find_lowest_weight_xor_linear_trail", {}),
        ("search_impossible_differentials", {}),
        ("search_impossible_differentials", {"representation": "wordwise"}),
        ("find_optimal_xor_differential_linear_trail", {}),
        ("find_minimax_xor_differential_trail", {}),
        ("find_one_boomerang_trail", {"switch_round": 1}),
        ("find_lowest_weight_boomerang_trail", {"switch_round": 1}),
    ],
)
def test_real_public_search_results_support_terminal_and_plot(method, options):
    import shutil

    if not all(shutil.which(name) for name in ("kissat", "z3")):
        pytest.skip("real search checks require Kissat and Z3")
    from claasp.primitives import ToyAES, ToySpeck

    primitive = (
        ToyAES(number_of_rounds=2, word_size=4, state_size=2)
        if options.get("representation") == "wordwise"
        else ToySpeck(3)
    )
    result = getattr(primitive.analysis, method)(**options)
    assert result is not None
    output = StringIO()
    result.to_terminal(file=output)
    assert output.getvalue().strip()
    artifact = result.plot(show=False)
    assert artifact.series
    # Actual impossible-search indicator must match independently decoded contradictions.
    if method == "search_impossible_differentials":
        trail = result.candidates[0].trail
        positions = (
            trail.boundary.contradictory_positions
            if options == {}
            else trail.middle.contradictory_positions
        )
        indicator = artifact.series[-1][1]
        assert tuple(i for i, value in enumerate(indicator) if value) == positions


def test_multiple_candidates_and_complete_relaxation_keep_labels():
    sample = _fixtures()["impossible_search"]
    second = ImpossibleCandidate(2, sample.candidates[0].trail, "bitwise")
    result = ImpossibleSearchResult((*sample.candidates, second), (1, 2), False, "candidate limit")
    artifact = result.plot(show=False)
    assert len(artifact.series) == 6
    assert "middle round 2" in artifact.series[-1][0]
    bound = ActiveSBoxResult("optimal", 5, True)
    assert "proved lower bound" in _view(bound).panels[0].labels
    with pytest.raises(TypeError, match="No search evidence view"):
        _view(object())


def test_semantic_composed_objectives_retain_connector_conventions():
    samples = _fixtures()
    assert list(_series(samples["semantic_boomerang"]).values()) == [(4.0, 1.0, 4.0)]
    from math import log2

    values = list(_series(samples["semantic_differential_linear"]).values())
    assert values == [(2.0, log2(3), 6.0)]
    assert sum(values[0]) == samples["semantic_differential_linear"].total_weight


def test_feistel_division_preserves_minimal_vector_pairs():
    from claasp.analysis.division_property import (
        feistel_division_property_trail,
        spn_division_property_trail,
    )

    result = feistel_division_property_trail(4, 2, (0, 3))
    assert result == [[(3, 0)], [(2, 0), (1, 1), (0, 3)], [(1, 0), (0, 2)], [(1, 0), (0, 1)]]
    data = list(_series(result).values())
    assert data == [
        (3.0,),
        (0.0,),
        (2.0, 1.0, 0.0),
        (0.0, 1.0, 3.0),
        (1.0, 0.0),
        (0.0, 2.0),
        (1.0, 0.0),
        (0.0, 1.0),
    ]
    assert callable(spn_division_property_trail(4, 3, 16, [4] * 7 + [0] * 9).plot)
