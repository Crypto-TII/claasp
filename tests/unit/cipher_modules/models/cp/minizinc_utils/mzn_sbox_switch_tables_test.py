"""Independent quartet-count checks for local S-box switch tables."""

import math
from collections import Counter

import pytest

from claasp.cipher import Cipher
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_sbox_switch_tables import (
    minizinc_sbox_switch_table,
    sbox_switch_counts,
)
from claasp.cipher_modules.models.cp.mzn_models.mzn_hadipour_boomerang_model import (
    MznHadipourBoomerangModel,
)

PRESENT_SBOX = (12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2)


def _forward_quartet_counts(mapping, kind="bct"):
    """Enumerate four S-box inputs using only forward evaluations."""
    coordinates = {
        "bct": ("upper_input", "lower_output"),
        "ubct": ("upper_input", "upper_output", "lower_output"),
        "lbct": ("upper_input", "lower_input", "lower_output"),
        "ebct": ("upper_input", "upper_output", "lower_input", "lower_output"),
    }[kind]
    counts = Counter()
    for upper_input in range(len(mapping)):
        for x0 in range(len(mapping)):
            x1 = x0 ^ upper_input
            for x2 in range(len(mapping)):
                x3 = x2 ^ upper_input
                lower_output = mapping[x0] ^ mapping[x2]
                if mapping[x1] ^ mapping[x3] == lower_output:
                    values = {
                        "upper_input": upper_input,
                        "upper_output": mapping[x0] ^ mapping[x1],
                        "lower_input": x0 ^ x2,
                        "lower_output": lower_output,
                    }
                    counts[tuple(values[name] for name in coordinates)] += 1
    return dict(counts)


def _minizinc_rows(declaration, columns):
    values = [
        int(value)
        for value in declaration.rsplit("[", 1)[1].split("]", 1)[0].split(",")
    ]
    return {
        tuple(values[index : index + columns])
        for index in range(0, len(values), columns)
    }


def _bits(value, width=4):
    return tuple(int(bit) for bit in f"{value:0{width}b}")


def test_present_bct_matches_all_forward_quartet_counts():
    counts = sbox_switch_counts(PRESENT_SBOX, "bct")
    assert counts == _forward_quartet_counts(PRESENT_SBOX)
    assert counts.get((1, 1), 0) == 0
    assert counts[1, 5] == 16
    assert counts[2, 3] == 6


@pytest.mark.parametrize("kind", ["ubct", "lbct", "ebct"])
def test_extended_tables_match_all_forward_quartet_counts(kind):
    counts = sbox_switch_counts(PRESENT_SBOX, kind)
    assert counts == _forward_quartet_counts(PRESENT_SBOX, kind)
    assert sum(counts.values()) == sum(sbox_switch_counts(PRESENT_SBOX, "bct").values())
    name, declaration = minizinc_sbox_switch_table(PRESENT_SBOX, kind)
    assert name.startswith(f"sbox_{kind}_")
    columns = 4 * len(next(iter(counts))) + 1
    assert f"array[1..{len(counts)}, 1..{columns}]" in declaration
    expected_rows = {
        tuple(bit for difference in differences for bit in _bits(difference))
        + (round(-100 * math.log2(count / 16)),)
        for differences, count in _forward_quartet_counts(PRESENT_SBOX, kind).items()
    }
    assert _minizinc_rows(declaration, columns) == expected_rows


def test_bct_minizinc_weights_use_local_quartet_probabilities():
    name, declaration = minizinc_sbox_switch_table(PRESENT_SBOX, "bct")
    assert name.startswith("sbox_bct_")
    assert "array[1..149, 1..9]" in declaration
    rows = _minizinc_rows(declaration, 9)
    assert (0, 0, 1, 0, 0, 0, 1, 1, 142) in rows  # (2, 3): -log2(6/16)
    assert len(rows) == len(sbox_switch_counts(PRESENT_SBOX, "bct"))
    assert minizinc_sbox_switch_table(PRESENT_SBOX, "bct") == (name, declaration)


def test_single_middle_sbox_uses_local_bct_table():
    cipher = Cipher("single_sbox", "permutation", ["plaintext"], [4], 4)
    cipher.add_round()
    output = cipher.add_sbox_component(
        ["plaintext"], [list(range(4))], 4, list(PRESENT_SBOX)
    )
    cipher.add_cipher_output_component([output.id], [list(range(4))], 4)
    model = MznHadipourBoomerangModel(
        cipher,
        {
            "top_part_number_of_rounds": 0,
            "middle_part_number_of_rounds": 1,
            "bottom_part_number_of_rounds": 0,
        },
    )
    model.build_hadipour_boomerang_model()
    text = model.assemble_model()
    assert "sbox_bct_" in text
    assert "constraint table(" in text
    assert len(model._middle_probabilities) == 1
    assert text == model.assemble_model()


def test_three_middle_sboxes_use_extended_tables():
    cipher = Cipher("three_sboxes", "permutation", ["plaintext"], [4], 4)
    input_id = "plaintext"
    for _ in range(3):
        cipher.add_round()
        output = cipher.add_sbox_component(
            [input_id], [list(range(4))], 4, list(PRESENT_SBOX)
        )
        input_id = output.id
    cipher.add_cipher_output_component([input_id], [list(range(4))], 4)
    model = MznHadipourBoomerangModel(
        cipher,
        {
            "top_part_number_of_rounds": 0,
            "middle_part_number_of_rounds": 3,
            "bottom_part_number_of_rounds": 0,
        },
    )
    model.build_hadipour_boomerang_model()
    text = model.assemble_model()
    for kind in ("ubct", "ebct", "lbct"):
        assert f"sbox_{kind}_" in text
    assert len(model._middle_probabilities) == 3


@pytest.mark.parametrize("mapping", [(0, 0, 2, 3), tuple(range(512))])
def test_local_bct_rejects_nonpermutations_and_oversized_sboxes(mapping):
    with pytest.raises(
        NotImplementedError, match="bijective S-box of at most eight bits"
    ):
        sbox_switch_counts(mapping, "bct")
