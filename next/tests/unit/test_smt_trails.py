from claasp_next.ciphers import PresentBlockCipher
from claasp_next.smt import PresentDifferentialSMTModel


def test_present_weighted_smt_formula_is_deterministic_and_scalable():
    cipher = PresentBlockCipher(number_of_rounds=2)
    first = PresentDifferentialSMTModel(cipher, maximum_weight=4).smt_formula()
    second = PresentDifferentialSMTModel(cipher, maximum_weight=4).smt_formula()

    assert first == second
    assert len(first.variables) < 700
    assert first.assertion_count < 30000
    assert "nonzero_input" in first.provenance
    assert "weight_bound" in first.provenance
