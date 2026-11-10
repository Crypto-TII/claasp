"""Real bitwise and wordwise searches retain and present every published cut."""

import shutil
from io import StringIO

import pytest

from claasp.primitives import AES, Simon, Speck, ToyFeistel

pytestmark = pytest.mark.external


@pytest.mark.parametrize(
    "primitive",
    (
        Speck(number_of_rounds=6),
        AES(number_of_rounds=2),
        Simon(number_of_rounds=4),
        ToyFeistel(number_of_rounds=5),
    ),
)
def test_public_search_retains_original_round_labels_and_meeting_patterns(primitive):
    if shutil.which("kissat") is None:
        pytest.skip("Kissat not installed")
    result = primitive.analysis.search_impossible_differentials()
    candidate = result.candidates[0]
    trail = candidate.trail
    expected = tuple(number + 1 for number, _ in primitive.graph.round_output_boundaries)
    assert tuple(n for n, _ in trail.forward_rounds) == tuple(
        n for n in expected if n <= candidate.middle_round
    )
    assert tuple(n for n, _ in trail.backward_rounds) == tuple(
        n for n in expected if n > candidate.middle_round
    )
    if candidate.representation == "bitwise":
        assert trail.forward_rounds[-1][1] == trail.boundary.forward
        assert trail.backward.output_pattern == trail.boundary.backward
        output = dict(trail.backward.input_patterns)["output"]
    else:
        assert trail.forward_rounds[-1][1] == trail.forward.output_differences
        assert (
            tuple(item.kind.value for item in trail.backward.output_differences)
            == trail.middle.backward_states
        )
        output = dict(trail.backward.input_differences)["output"]
    assert trail.backward_rounds[-1][1] == output
    stream = StringIO()
    result.to_terminal(value_format="underscore_one", file=stream)
    assert stream.getvalue().count("meeting state") == 2
    assert "ciphertext" in stream.getvalue()
    if candidate.representation == "bitwise":
        assert "round output" in stream.getvalue()


def test_inverse_round_labels_survive_an_unkeyed_slice_with_renumbered_rounds():
    if shutil.which("kissat") is None:
        pytest.skip("Kissat not installed")
    from claasp import Primitive, UnitArrayType
    from claasp.components import Identity
    from claasp.unit_types import Bit

    primitive = Primitive("three_identity_rounds", {"plaintext": UnitArrayType(Bit(), (2,))})
    value = primitive.graph.input("plaintext")
    for _ in range(3):
        primitive._builder.add_round()
        value = primitive._builder.add_component(Identity(value))
        primitive._builder.set_round_output(value)
    primitive._builder.set_output(value)
    result = primitive.analysis.search_impossible_differentials(
        middle_round=2, input_pattern="01", output_pattern="10", representation="bitwise"
    )
    trail = result.candidates[0].trail
    assert tuple(n for n, _ in trail.forward_rounds) == (1, 2)
    assert tuple(n for n, _ in trail.backward_rounds) == (3,)
    assert str(trail.backward_rounds[0][1]) == "10"
