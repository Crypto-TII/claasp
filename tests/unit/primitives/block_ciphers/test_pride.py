"""Published vectors and independent-circuit checks for the research catalogue.

NOEKEON: designers' Noekeon_ref.zip/NoekeonTestVectors.txt.
PRIDE: Appendix J vectors, also reproduced in obfusk/pypride's examples.
uLBC: https://doi.org/10.62056/a63zzoja5, Appendix A (all six vectors).
"""

import json
from pathlib import Path

import pytest

from claasp.primitives import Pride


@pytest.mark.parametrize(
    "p,k,c",
    [
        (0, 0, 0x82B4109FCC70BD1F),
        (0xFFFFFFFFFFFFFFFF, 0, 0xD70E60680A17B956),
        (0, 0xFFFFFFFFFFFFFFFF0000000000000000, 0x28F19F97F5E846A9),
        (0, 0x0000000000000000FFFFFFFFFFFFFFFF, 0xD123EBAF368FCE62),
        (0x0123456789ABCDEF, 0xFEDCBA9876543210, 0xD1372929712D336E),
    ],
)
def test_pride_published_vectors(p, k, c):
    assert Pride().evaluate(plaintext=p, key=k) == c


@pytest.mark.parametrize(
    "vector",
    json.loads(
        (Path(__file__).parents[3] / "fixtures/primitives/pride_crosscheck.json").read_text()
    )["vectors"],
)
def test_pride_full_and_reduced_rounds_against_independent_implementation(vector):
    assert Pride(number_of_rounds=vector["rounds"]).evaluate(
        plaintext=int(vector["plaintext"], 16), key=int(vector["key"], 16)
    ) == int(vector["ciphertext"], 16)
