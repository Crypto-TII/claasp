from claasp_next.analysis.component_properties import (
    ComponentProperty,
    DiagnosticCode,
    PropertyClaim,
    PropertyDomain,
    PropertyRequest,
)
from claasp_next.components import LinearMap
from claasp_next.domains import Bit
from claasp_next.drivers.analysis import (
    BoundedBranchNumberDriver,
    MiniZincBranchNumberDriver,
)
from claasp_next.graph import Port, ValueType

ASYMMETRIC = (
    (0, 0, 0, 1),
    (0, 1, 1, 0),
    (1, 0, 1, 0),
    (1, 1, 1, 1),
)


def _component():
    return LinearMap(Port("x", ValueType(Bit(), (4,))), ASYMMETRIC)


def _request(kind=ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER):
    return PropertyRequest(kind, PropertyDomain.BIT_LINEAR)


def test_bounded_driver_labels_incomplete_candidate_as_proved_upper_bound():
    result = BoundedBranchNumberDriver(1).analyze(_component(), _request())

    assert result.value == 3
    assert result.claim is PropertyClaim.PROVED_UPPER_BOUND
    assert result.complete is False
    assert result.provenance.driver.name == "bounded_branch_enumeration"


def test_bounded_driver_becomes_exact_on_complete_support_coverage():
    result = BoundedBranchNumberDriver(4).analyze(_component(), _request())

    assert result.value == 3
    assert result.claim is PropertyClaim.EXACT
    assert result.complete is True


def test_bounded_driver_can_prove_exactness_at_mathematical_lower_bound():
    identity = LinearMap(
        Port("x", ValueType(Bit(), (4,))),
        ((1, 0, 0, 0), (0, 1, 0, 0), (0, 0, 1, 0), (0, 0, 0, 1)),
    )
    result = BoundedBranchNumberDriver(1).analyze(identity, _request())

    assert result.value == 2
    assert result.claim is PropertyClaim.EXACT


def test_minizinc_missing_executable_returns_typed_unavailable_result():
    result = MiniZincBranchNumberDriver(executable="definitely-not-a-minizinc-binary").analyze(
        _component(), _request()
    )

    assert result.claim is PropertyClaim.UNAVAILABLE
    assert result.diagnostic.code is DiagnosticCode.DRIVER_UNAVAILABLE
