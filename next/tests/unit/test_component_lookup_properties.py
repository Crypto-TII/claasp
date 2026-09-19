import pytest

from claasp_next.analysis.component_properties import (
    ComponentProperty,
    DiagnosticCode,
    PropertyClaim,
    PropertyDomain,
    PropertyRequest,
    analyze_component_property,
    analyze_lookup_table,
)
from claasp_next.components import LookupTable
from claasp_next.primitives.block_ciphers.aes import AES_SBOX
from claasp_next.primitives.block_ciphers.present import PRESENT_SBOX


def _property(table, property_):
    return analyze_lookup_table(
        table,
        PropertyRequest(property_, PropertyDomain.LOOKUP_TABLE),
    )


def test_aes_sbox_fixed_properties_are_exact_and_independent():
    table = LookupTable(AES_SBOX, 8)

    assert _property(table, ComponentProperty.DIFFERENTIAL_UNIFORMITY).value == 4
    assert _property(table, ComponentProperty.NONLINEARITY).value == 112
    assert _property(table, ComponentProperty.ALGEBRAIC_DEGREE).value == 7
    assert _property(table, ComponentProperty.BALANCED).value is True
    assert _property(table, ComponentProperty.APN).value is False


def test_present_lookup_branch_and_boomerang_properties_are_exact():
    table = LookupTable(PRESENT_SBOX, 4)

    assert _property(table, ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER).value == 3
    assert _property(table, ComponentProperty.LINEAR_BRANCH_NUMBER).value == 2
    assert _property(table, ComponentProperty.BOOMERANG_UNIFORMITY).value == 16
    assert _property(table, ComponentProperty.BOOMERANG_UNIFORMITY).claim is PropertyClaim.EXACT


def test_reduced_width_lookup_facts_match_direct_exhaustive_definitions():
    table = LookupTable((0, 2, 3, 1), 2)
    ddt_counts = [
        sum(table.values[x] ^ table.values[x ^ alpha] == beta for x in range(4))
        for alpha in range(1, 4)
        for beta in range(4)
    ]
    direct_branch = min(
        alpha.bit_count() + beta.bit_count()
        for alpha in range(1, 4)
        for beta in range(4)
        if any(table.values[x] ^ table.values[x ^ alpha] == beta for x in range(4))
    )

    assert _property(table, ComponentProperty.DIFFERENTIAL_UNIFORMITY).value == max(ddt_counts)
    assert _property(table, ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER).value == direct_branch


def test_rectangular_lookup_has_precise_boomerang_diagnostic():
    table = LookupTable((0, 1, 2, 3), 2, 3)
    result = _property(table, ComponentProperty.BOOMERANG_UNIFORMITY)

    assert result.claim is PropertyClaim.UNAVAILABLE
    assert result.diagnostic.code is DiagnosticCode.INAPPLICABLE_DOMAIN


def test_component_dispatch_rejects_wrong_domain_without_fabricated_value():
    from claasp_next.components import BitVectorSBox
    from claasp_next.primitives import Present

    component = next(
        item for item in Present(number_of_rounds=1).components if isinstance(item, BitVectorSBox)
    )
    result = analyze_component_property(
        component,
        PropertyRequest(ComponentProperty.NONLINEARITY, PropertyDomain.WORD_OPERATION),
    )

    assert not result.is_available
    assert result.value is None
    assert result.diagnostic.code is DiagnosticCode.INAPPLICABLE_DOMAIN


def test_lookup_validation_precedes_analysis():
    with pytest.raises(ValueError, match="must contain 4 entries"):
        LookupTable((0, 1), 2)
