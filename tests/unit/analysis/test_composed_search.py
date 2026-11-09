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
    assert candidate.middle_round == 1  # Immediately after initial AddRoundKey.
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
    assert result.attempted_rounds == tuple(range(1, 11))
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
