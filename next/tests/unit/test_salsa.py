from claasp_next.primitives.permutations.salsa import Salsa
from claasp_next.encoding import units_from_int
from claasp_next.representations.execution import BatchEvaluator


def test_retained_sparse_salsa_vector():
    state = 1 << (15 * 32)
    expected = int(
        "8186a22d0040a2848247921006929051"
        "080000900240220000004000008000000"
        "001020020400000080081040000000020"
        "500000a00000400008180a612a8020",
        16,
    )

    assert Salsa(number_of_rounds=2).evaluate(state) == expected


def test_retained_dense_salsa_vector_and_batch_execution():
    state = int(
        "de5010666f9eb8f7e4fbbd9b454e3f57"
        "b75540d343e93a4c3a6f2aa0726d6b36"
        "9243f4849145d1e84fa9d247dc8dee11"
        "054bf545254dd653d9421b6d67b276c1",
        16,
    )
    expected = int(
        "ccaaf67223d960f79153e63acd9a60d0"
        "50440492f07cad19ae344aa0df4cfdfc"
        "ca531c298e7943dbac1680cdd503ca00"
        "a74b2ad6bc331c5c1dda24c7ee928277",
        16,
    )
    permutation = Salsa(number_of_rounds=2)

    assert permutation.evaluate(state) == expected
    result = BatchEvaluator().evaluate(
        permutation,
        {"state": (units_from_int(state, 32, 16),)},
    )
    assert result.outputs == (units_from_int(expected, 32, 16),)


def test_parameters_and_standard_round_boundaries():
    permutation = Salsa(number_of_rounds=2)

    assert len(permutation.rounds) == 2
    assert len(permutation.components) == 2 * 4 * 12


def test_invalid_parameters_are_rejected():
    for invalid in (0, -1):
        try:
            Salsa(number_of_rounds=invalid)
        except ValueError as error:
            assert "positive" in str(error)
        else:
            raise AssertionError("invalid round count was accepted")
