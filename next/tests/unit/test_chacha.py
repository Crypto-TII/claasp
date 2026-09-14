import pytest

from claasp_next.primitives.permutations.chacha import ChaCha
from claasp_next.encoding import units_from_int
from claasp_next.representations.execution import BatchEvaluator


def test_retained_standard_chacha20_vector():
    state = int(
        "617078653320646e79622d326b206574"
        "03020100070605040b0a09080f0e0d0c"
        "13121110171615141b1a19181f1e1d1c"
        "00000001090000004a00000000000000",
        16,
    )
    expected = int(
        "837778abe238d763a67ae21e5950bb2f"
        "c4f2d0c7fc62bb2f8fa018fc3f5ec7b7"
        "335271c2f29489f3eabda8fc82e46ebd"
        "d19c12b4b04e16de9e83d0cb4e3c50a2",
        16,
    )

    assert ChaCha().evaluate(state) == expected


@pytest.mark.parametrize(
    ("rounds", "expected"),
    (
        (1, 0x81000000AD0000005600000046000000),
        (4, 0xE023858E713FEB86A730656AC909F76A),
    ),
)
def test_retained_toy_chacha_vectors(rounds, expected):
    state = 1 << 120
    permutation = ChaCha(
        number_of_rounds=rounds,
        word_size=8,
        rotations=(4, 3, 2, 1),
    )

    assert permutation.evaluate(state) == expected


def test_retained_toy_vector_uses_batch_execution_too():
    permutation = ChaCha(number_of_rounds=4, word_size=8, rotations=(4, 3, 2, 1))
    state = units_from_int(1 << 120, 8, 16)

    result = BatchEvaluator().evaluate(permutation, {"state": (state, state)})

    expected = units_from_int(0xE023858E713FEB86A730656AC909F76A, 8, 16)
    assert result.outputs == (expected, expected)


def test_rounds_and_parameters_are_validated():
    with pytest.raises(ValueError, match="positive"):
        ChaCha(number_of_rounds=0)
    with pytest.raises(ValueError, match="four integers"):
        ChaCha(word_size=8, rotations=(4, 3, 2, 8))


def test_graph_exposes_standard_round_boundaries():
    permutation = ChaCha(number_of_rounds=2)

    assert len(permutation.rounds) == 2
    assert len(permutation.components) == 2 * 4 * 12 + 1
