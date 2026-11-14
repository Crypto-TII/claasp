"""Full retained impossible trails are rendered in one evidence column."""

from dataclasses import replace
from io import StringIO

import pytest

from claasp.analysis.composed_search import ImpossibleCandidate, ImpossibleSearchResult
from claasp.representations.constraints.sat.trails import (
    AutomaticWordImpossibleSATResult,
    WordDeterministicTruncatedCharacteristic,
    WordImpossibleSATTrail,
    WordwiseDeterministicTruncatedCharacteristic,
    WordwiseImpossibleMiddle,
    WordwiseImpossibleSATTrail,
)
from claasp.semantics.cryptanalysis import (
    ImpossiblePropagationBoundary,
)
from claasp.semantics.cryptanalysis import (
    TruncatedXorDifference as Pattern,
)
from claasp.semantics.cryptanalysis import (
    WordwiseDifferenceKind as Kind,
)
from claasp.semantics.cryptanalysis import (
    WordwiseXorDifference as Difference,
)


def _sample():
    above, below = Pattern.parse("01?0"), Pattern.parse("00?0")
    source, target, intermediate = (
        Pattern.parse("0001"),
        Pattern.parse("1000"),
        Pattern.parse("001?"),
    )
    forward = WordDeterministicTruncatedCharacteristic(
        (("plaintext", source),), above, (("forward_component", intermediate),), ()
    )
    backward = WordDeterministicTruncatedCharacteristic(
        (("output", target),), below, (("inverse_component", intermediate),), ()
    )
    trail = WordImpossibleSATTrail(
        forward,
        backward,
        ImpossiblePropagationBoundary(above, below),
        (),
        2,
        ((1, intermediate), (2, above)),
        ((3, target),),
    )
    return ImpossibleSearchResult(
        (ImpossibleCandidate(2, trail, "bitwise"),), (1, 2), False, "candidate limit"
    )


@pytest.mark.parametrize("details", (False, True))
@pytest.mark.parametrize("notation", ("hex", "binary", "underscore_one"))
def test_single_column_full_path_and_duplicated_contradiction(details, notation):
    result = _sample()
    output = StringIO()
    result.to_terminal(details=details, value_format=notation, file=output)
    text = output.getvalue()
    assert "plaintext" in text and "ciphertext" in text
    meeting = [line for line in text.splitlines() if "meeting state" in line]
    assert len(meeting) == 2 and all(".!.." in line for line in meeting)
    assert "above ↓" in meeting[0] and "below ↑" in meeting[1]
    assert "0b01?0" in text if notation != "underscore_one" else "_1?_" in text
    assert ("forward_component" in text and "inverse_component" in text) == details
    assert "candidate limit" in text and "Complete: False" in text


def _wordwise_sample():
    known = Difference.known(4, 3)
    zero, unknown, nonzero = (
        Difference(4, kind) for kind in (Kind.ZERO, Kind.UNKNOWN, Kind.NONZERO)
    )
    above, below = (known, unknown, nonzero), (zero, unknown, nonzero)
    f = WordwiseDeterministicTruncatedCharacteristic(
        (("plaintext", above),), above, (("forward_word", above),), ()
    )
    b = WordwiseDeterministicTruncatedCharacteristic(
        (("output", below),), below, (("backward_word", below),), ()
    )
    return WordwiseImpossibleSATTrail(
        f, b, WordwiseImpossibleMiddle((1, 3, 2), (0, 3, 2), (0,)), (), 1
    )


def test_wordwise_known_value_nonzero_and_unknown_remain_distinct():
    output = StringIO()
    _wordwise_sample().to_terminal(value_format="binary", file=output)
    text = output.getvalue()
    assert "[0b0011, ?, *]" in text and "[0b0000, ?, *]" in text
    assert text.count("!..") == 2


def test_plot_image_data_and_both_contradiction_markers_match_retained_states(tmp_path):
    import matplotlib

    matplotlib.use("Agg")
    import numpy as np
    from matplotlib import pyplot as plt

    result = _sample()
    target = tmp_path / "impossible.png"
    artifact = result.plot(show=False, save_to=target)
    try:
        assert target.read_bytes().startswith(b"\x89PNG")
        assert "Red crosses mark" in artifact.figure._suptitle.get_text()
        axis = next(ax for ax in artifact.figure.axes if ax.images)
        matrix = axis.images[0].get_array()
        # Two meeting rows (after plaintext and boundary 1) preserve 0/1/? categories.
        assert tuple(np.ma.compressed(matrix[2])) == (0.0, 1.0, 2.0, 0.0)
        assert tuple(np.ma.compressed(matrix[3])) == (0.0, 0.0, 2.0, 0.0)
        markers = [
            tuple(point) for collection in axis.collections for point in collection.get_offsets()
        ]
        assert markers == [(1.0, 2.0), (1.0, 3.0)]
        assert artifact.series[-1][1] == (0.0, 1.0, 0.0, 0.0)
        assert any("ciphertext" in tick.get_text() for tick in axis.get_yticklabels())
    finally:
        plt.close(artifact.figure)


def test_empty_unknown_search_does_not_invent_a_trail():
    output = StringIO()
    ImpossibleSearchResult((), (1,), False, "solver unknown").to_terminal(
        details=True, value_format="binary", file=output
    )
    assert "No retained witness" in output.getvalue() and "solver unknown" in output.getvalue()


def test_empty_complete_search_keeps_model_and_qualified_exhaustion_scope():
    output = StringIO()
    ImpossibleSearchResult((), (2, 3), True, "exhausted UNSAT", "wordwise").to_terminal(file=output)
    assert "Truncated model: wordwise" in output.getvalue()
    assert "Exhaustion applies only to the selected truncated model." in output.getvalue()
    assert "No retained witness" in output.getvalue()


def _default_case(family):
    if family in ("wordwise", "wordwise_search"):
        trail = _wordwise_sample()
        result = (
            trail
            if family == "wordwise"
            else ImpossibleSearchResult(
                (ImpossibleCandidate(1, trail, "wordwise"),), (1,), False, "candidate limit"
            )
        )
        return result, ("[0b0011, ?, *]", "[0b0000, ?, *]"), "0x3", "__11"
    if family == "boundary":
        result = ImpossiblePropagationBoundary(Pattern.parse("0001"), Pattern.parse("00?0"))
        return result, ("0b0001", "0b00?0"), "0x1", "___1"
    result = _sample()
    trail = result.candidates[0].trail
    # An exact all-zero key beside partial states reproduces the tutorial issue.
    forward = replace(
        trail.forward,
        input_patterns=(*trail.forward.input_patterns, ("key", Pattern.parse("0" * 16))),
    )
    trail = replace(trail, forward=forward)
    result = replace(result, candidates=(replace(result.candidates[0], trail=trail),))
    if family == "trail":
        result = trail
    elif family == "automatic":
        result = AutomaticWordImpossibleSATResult(2, trail, (1, 2), "candidate limit")
    return result, ("0b0001", "0b1000", "0b001?", "0b" + "0" * 16), "0x1", "___1"


@pytest.mark.parametrize("details", (False, True))
@pytest.mark.parametrize(
    "family", ("search", "trail", "automatic", "boundary", "wordwise", "wordwise_search")
)
def test_impossible_terminal_defaults_to_width_preserving_binary_for_every_result(family, details):
    result, expected, _, _ = _default_case(family)
    output, explicit = StringIO(), StringIO()
    assert result.to_terminal(details=details, file=output) is None
    result.to_terminal(details=details, value_format="binary", file=explicit)
    assert output.getvalue() == explicit.getvalue()
    assert "0x" not in output.getvalue()
    assert all(value in output.getvalue() for value in expected)
    assert "Contradiction !" in output.getvalue()
    if family in ("wordwise", "wordwise_search"):
        assert ("forward_word" in output.getvalue()) == details
        assert ("backward_word" in output.getvalue()) == details


@pytest.mark.parametrize("details", (False, True))
@pytest.mark.parametrize("notation", ("hex", "underscore_one"))
@pytest.mark.parametrize(
    "family", ("search", "trail", "automatic", "boundary", "wordwise", "wordwise_search")
)
def test_explicit_impossible_formats_still_override_the_default(family, notation, details):
    result, _, hexadecimal, underscore = _default_case(family)
    output = StringIO()
    result.to_terminal(details=details, value_format=notation, file=output)
    assert (hexadecimal if notation == "hex" else underscore) in output.getvalue()
    if notation == "underscore_one":
        assert "0x" not in output.getvalue() and "0b" not in output.getvalue()


@pytest.mark.parametrize("notation", (None, "octal"))
def test_bad_impossible_format_is_rejected_before_printing(notation):
    output = StringIO()
    with pytest.raises(ValueError, match="value_format"):
        _sample().to_terminal(value_format=notation, file=output)
    assert output.getvalue() == ""
