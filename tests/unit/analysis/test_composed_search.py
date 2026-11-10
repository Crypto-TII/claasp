import shutil

import pytest

from claasp.analysis import ImpossibleSearchResult, XorDifferentialLinearSearchResult
from claasp.primitives import ToySpeck


def test_composed_status_never_conflates_unknown_with_exhaustion():
    from enum import Enum

    class Status(Enum):
        UNKNOWN = "unknown"

    class UnknownSolver:
        def solve(self, formula):
            from types import SimpleNamespace

            return SimpleNamespace(status=Status.UNKNOWN, assignment=None, runtime_seconds=0)

    primitive = ToySpeck(3)
    result = primitive.analysis.search_impossible_differentials(solver=UnknownSolver())
    assert not result.complete and not result.found
    with pytest.raises(RuntimeError):
        result.require_complete()
    result = primitive.analysis.find_optimal_xor_differential_linear_trail(solver=UnknownSolver())
    assert not result.complete and not result.found
    with pytest.raises(RuntimeError):
        result.require_complete()


def test_search_validation_precedes_execution():
    primitive = ToySpeck(3)
    for options in (
        {"middle_round": 0},
        {"split_order": (1, 1)},
        {"limit": 0},
        {"representation": "invented"},
    ):
        with pytest.raises(ValueError):
            primitive.analysis.search_impossible_differentials(**options)
    with pytest.raises(ValueError):
        primitive.analysis.find_optimal_xor_differential_linear_trail(prefix_rounds=3)
    assert ImpossibleSearchResult((), (), True, "exhausted UNSAT").require_complete().complete
    assert XorDifferentialLinearSearchResult(None, None, None, (), True).require_complete().complete


def test_aes_defaults_to_explicitly_reported_wordwise_model():
    import shutil

    if not shutil.which("kissat"):
        pytest.skip("requires Kissat")
    from claasp.primitives import AES

    result = AES(number_of_rounds=2).analysis.search_impossible_differentials()
    assert result.found and not result.complete
    candidate = result.candidates[0]
    assert candidate.representation == "wordwise"
    assert candidate.trail.middle.contradictory_positions
    assert candidate.middle_round == 2  # After the first published encryption round.
    # Independent concrete checks of an abstract impossible external pattern.
    from claasp.semantics.cryptanalysis import WordwiseDifferenceKind as Kind

    forward = dict(candidate.trail.forward.input_differences)["plaintext"]
    backward = dict(candidate.trail.backward.input_differences)["output"]
    delta = sum(
        ((item.value or 0) if item.kind in (Kind.ZERO, Kind.KNOWN) else 1) << (8 * (15 - i))
        for i, item in enumerate(forward)
    )
    primitive = AES(number_of_rounds=2)
    for x in range(16):
        first = primitive.evaluate(plaintext=x, key=0x12345678)
        second = primitive.evaluate(plaintext=x ^ delta, key=0x12345678)
        assert isinstance(first, int) and isinstance(second, int)
        value = first ^ second
        words = tuple((value >> (8 * (15 - i))) & 255 for i in range(16))

        def matches(word, abstract):
            return (
                word == abstract.value
                if abstract.kind in (Kind.ZERO, Kind.KNOWN)
                else word != 0
                if abstract.kind is Kind.NONZERO
                else True
            )

        assert not all(matches(word, abstract) for word, abstract in zip(words, backward))


def test_full_aes_returns_model_exhaustion_not_a_domain_error():
    import shutil

    if not shutil.which("kissat"):
        pytest.skip("requires Kissat")
    from claasp.primitives import AES

    result = AES().analysis.search_impossible_differentials()
    assert not result.found and result.complete
    assert result.representation == "wordwise"
    assert result.termination == "exhausted UNSAT"
    assert result.attempted_rounds == tuple(range(2, 11))
    from io import StringIO

    output = StringIO()
    result.to_terminal(file=output)
    assert "Truncated model: wordwise" in output.getvalue()
    assert "only to the selected truncated model" in output.getvalue()


def test_explicit_bitwise_search_supports_small_binary_field_graphs():
    import shutil

    if not shutil.which("kissat"):
        pytest.skip("requires Kissat")
    from claasp.primitives import ToyAES

    result = ToyAES(
        number_of_rounds=2, word_size=4, state_size=2
    ).analysis.search_impossible_differentials(representation="bitwise")
    assert result.representation == "bitwise"
    assert result.complete or result.found


@pytest.mark.parametrize(
    "name", ("Speck", "Simon", "ChaChaPermutation", "SalsaPermutation", "ChaChaBlockFunction")
)
@pytest.mark.skipif(shutil.which("kissat") is None, reason="requires Kissat")
def test_extended_wordwise_search_returns_checked_candidates(name):
    from claasp import primitives

    p = getattr(primitives, name)(number_of_rounds=2)
    active = (
        "plaintext" if "plaintext" in p.graph.input_arrays else next(iter(p.graph.input_arrays))
    )
    result = p.analysis.search_impossible_differentials(
        active_input=active, representation="wordwise"
    )
    assert result.found and not result.complete
    candidate = result.candidates[0]
    assert candidate.representation == "wordwise"
    assert candidate.trail.middle.contradictory_positions


@pytest.mark.skipif(shutil.which("kissat") is None, reason="requires Kissat")
def test_wordwise_arx_candidate_cannot_match_any_small_concrete_pair():
    from itertools import product

    from claasp.semantics.cryptanalysis import WordwiseDifferenceKind as Kind

    p = ToySpeck(2)
    candidate = p.analysis.search_impossible_differentials(representation="wordwise").candidates[0]
    inputs = dict(candidate.trail.forward.input_differences)["plaintext"]
    outputs = dict(candidate.trail.backward.input_differences)["output"]

    def allowed(difference):
        if difference.kind in (Kind.ZERO, Kind.KNOWN):
            return (difference.value,)
        return range(int(difference.kind is Kind.NONZERO), 1 << difference.width)

    width = inputs[0].width
    for words in product(*(allowed(item) for item in inputs)):
        delta = sum(value << (width * (len(words) - 1 - i)) for i, value in enumerate(words))
        for value in range(1 << (width * len(words))):
            first = p.evaluate(plaintext=value, key=0)
            second = p.evaluate(plaintext=value ^ delta, key=0)
            assert isinstance(first, int) and isinstance(second, int)
            actual = first ^ second
            actual_words = tuple(
                (actual >> (width * (len(words) - 1 - i))) & ((1 << width) - 1)
                for i in range(len(words))
            )
            assert not all(word in allowed(item) for word, item in zip(actual_words, outputs))
