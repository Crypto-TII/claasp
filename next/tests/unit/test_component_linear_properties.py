from claasp_next.analysis.component_properties import (
    ComponentProperty,
    DiagnosticCode,
    PropertyDomain,
    PropertyRequest,
    analyze_component_property,
)
from claasp_next.components import BinaryAffineMap, LinearMap, Permutation
from claasp_next.composites.aes import AES_FIELD
from claasp_next.domains import BinaryExtensionField, Bit
from claasp_next.graph import Port, ValueType
from claasp_next.primitives.toy_primitives.toyaes import MIX_COLUMN_MATRICES


def _analyze(component, property_, domain=PropertyDomain.BIT_LINEAR, **options):
    return analyze_component_property(
        component,
        PropertyRequest(property_, domain, tuple(options.items())),
    )


def test_identity_and_permutation_linear_properties_are_exact():
    port = Port("x", ValueType(Bit(), (4,)))
    identity = LinearMap(port, ((1, 0, 0, 0), (0, 1, 0, 0), (0, 0, 1, 0), (0, 0, 0, 1)))
    permutation = Permutation(port, (1, 2, 3, 0))

    assert _analyze(identity, ComponentProperty.RANK).value == 4
    assert _analyze(identity, ComponentProperty.INVERTIBLE).value is True
    assert _analyze(identity, ComponentProperty.ORDER).value == 1
    assert _analyze(identity, ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER).value == 2
    assert _analyze(identity, ComponentProperty.LINEAR_BRANCH_NUMBER).value == 2
    assert _analyze(permutation, ComponentProperty.ORDER).value == 4
    assert _analyze(permutation, ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER).value == 2


def test_aes_mixcolumn_word_branch_number_and_mds_status():
    matrix = ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))
    component = LinearMap(Port("column", ValueType(AES_FIELD, (4,))), matrix)

    assert _analyze(component, ComponentProperty.RANK, PropertyDomain.WORD_LINEAR).value == 4
    assert _analyze(component, ComponentProperty.MDS, PropertyDomain.WORD_LINEAR).value is True
    assert _analyze(component, ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER, PropertyDomain.WORD_LINEAR).value == 5
    assert _analyze(component, ComponentProperty.LINEAR_BRANCH_NUMBER, PropertyDomain.WORD_LINEAR).value == 5


def test_toyaes_gf4_non_mds_matrix_has_exact_branch_three():
    field = BinaryExtensionField(2, 0x7)
    matrix = MIX_COLUMN_MATRICES[(2, 4)]
    component = LinearMap(Port("column", ValueType(field, (4,))), matrix)

    assert _analyze(component, ComponentProperty.MDS, PropertyDomain.WORD_LINEAR).value is False
    assert _analyze(component, ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER, PropertyDomain.WORD_LINEAR).value == 3


def test_asymmetric_matrix_applies_linear_transpose_rule():
    matrix = (
        (0, 0, 0, 1),
        (0, 1, 1, 0),
        (1, 0, 1, 0),
        (1, 1, 1, 1),
    )
    component = LinearMap(Port("x", ValueType(Bit(), (4,))), matrix)

    assert _analyze(component, ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER).value == 3
    assert _analyze(component, ComponentProperty.LINEAR_BRANCH_NUMBER).value == 2


def test_binary_affine_order_includes_offset_not_only_linear_matrix():
    identity = tuple(tuple(int(row == column) for column in range(8)) for row in range(8))
    component = BinaryAffineMap(
        Port("x", ValueType(AES_FIELD, (1,))), identity, 0x63
    )
    linear_only = BinaryAffineMap(
        Port("x", ValueType(AES_FIELD, (1,))), identity, 0
    )

    assert _analyze(component, ComponentProperty.ORDER).value == 2
    assert _analyze(linear_only, ComponentProperty.ORDER).value == 1


def test_large_exact_bit_branch_request_reports_budget_exhaustion():
    matrix = ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))
    component = LinearMap(Port("column", ValueType(AES_FIELD, (4,))), matrix)
    result = _analyze(
        component, ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER,
        PropertyDomain.BIT_LINEAR, maximum_vectors=16,
    )

    assert not result.is_available
    assert result.diagnostic.code is DiagnosticCode.BUDGET_EXHAUSTED
