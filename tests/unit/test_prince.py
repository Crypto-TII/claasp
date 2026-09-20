"""Independent identity and fixed-vector checks for PRINCE and PRINCEv2."""

from claasp.primitives import Prince, PrinceV2


def test_prince_and_prince_v2_are_distinct_primitive_identities():
    prince = Prince()
    prince_v2 = PrinceV2()

    assert prince.family_name == "prince"
    assert prince_v2.family_name == "prince_v2"
    assert Prince.__module__ == "claasp.primitives.block_ciphers.prince"
    assert PrinceV2.__module__ == "claasp.primitives.block_ciphers.prince_v2"


def test_prince_preserves_its_legacy_fixed_vector():
    assert (
        Prince().evaluate(
            0x0000000000000000,
            0xFFFFFFFFFFFFFFFF0000000000000000,
        )
        == 0x9FB51935FC3DF524
    )


def test_prince_v2_preserves_its_specification_fixed_vector():
    assert PrinceV2().evaluate(0, 0) == 0x0125FC7359441690
