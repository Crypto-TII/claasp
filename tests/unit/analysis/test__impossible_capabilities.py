"""Unsupported graphs identify their domain or operation before solver execution."""

import pytest

from claasp.analysis._impossible_capabilities import _require_impossible_capability
from claasp.analysis.trail_search import TrailSearchCapabilityError
from claasp.primitives import MiMC, ToyAES
from claasp.primitives.single_component_primitives import ModularAdd


def test_prime_field_is_reported_even_with_published_rounds():
    p = MiMC(17, 3, (1, 2, 4))
    assert p.graph.round_output_boundaries
    with pytest.raises(TrailSearchCapabilityError, match="mimc.*bitwise.*PrimeField"):
        p.analysis.search_impossible_differentials(active_input="state")


@pytest.mark.parametrize("representation", ("bitwise", "wordwise"))
def test_non_power_of_two_modulus_does_not_silently_use_word_addition(representation):
    with pytest.raises(TrailSearchCapabilityError, match="ModularAdd.*power-of-two"):
        _require_impossible_capability(ModularAdd(3, modulus=7), representation)


def test_nonbijective_wordwise_sbox_names_the_component():
    with pytest.raises(TrailSearchCapabilityError, match="SBox.*bijection"):
        _require_impossible_capability(
            ToyAES(number_of_rounds=2, word_size=2, state_size=2), "wordwise"
        )
