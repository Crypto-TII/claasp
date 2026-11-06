from claasp.analysis.component_properties import (
    ComponentProperty,
    DiagnosticCode,
    PropertyClaim,
    PropertyDomain,
    PropertyRequest,
)
from claasp.components import LinearMap
from claasp.drivers.analysis import (
    BoundedBranchNumberDriver,
    MiniZincBranchNumberDriver,
)
from claasp.graph import UnitArray, UnitArrayType
from claasp.unit_types import Bit

ASYMMETRIC = (
    (0, 0, 0, 1),
    (0, 1, 1, 0),
    (1, 0, 1, 0),
    (1, 1, 1, 1),
)


def _component():
    return LinearMap(UnitArray("x", UnitArrayType(Bit(), (4,))), ASYMMETRIC)


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
        UnitArray("x", UnitArrayType(Bit(), (4,))),
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


def test_word_compression_matches_exhaustive_independent_binary_matrix_weights():
    from itertools import product

    from claasp.drivers.analysis.branch_number import _identical_word_strands

    scalar = ((1, 1, 0), (0, 1, 1), (1, 1, 1))
    matrix = tuple(
        tuple(scalar[row // 2][column // 2] if row % 2 == column % 2 else 0 for column in range(6))
        for row in range(6)
    )
    assert _identical_word_strands(matrix, 2) == scalar

    def minimum(matrix, width):
        values = []
        for bits in product((0, 1), repeat=len(matrix[0])):
            if not any(bits):
                continue
            output = tuple(sum(a * b for a, b in zip(row, bits)) % 2 for row in matrix)
            values.append(
                sum(
                    any(vector[start : start + width])
                    for vector in (bits, output)
                    for start in range(0, len(vector), width)
                )
            )
        return min(values)

    assert minimum(matrix, 2) == minimum(scalar, 1)


def test_branch_witness_validation_rejects_wrong_outputs():
    import pytest

    from claasp.drivers.analysis.branch_number import _checked_branch_number

    with pytest.raises(ValueError, match="matrix evaluation"):
        _checked_branch_number(((1, 0), (0, 1)), 1, {"input_bits": [1, 0], "output_bits": [0, 0]})


def test_independent_blocks_preserve_every_small_binary_branch_number():
    from claasp.drivers.analysis.branch_number import _independent_binary_blocks

    def minimum(matrix):
        masks = tuple(sum(bit << column for column, bit in enumerate(row)) for row in matrix)
        return min(
            value.bit_count() + sum((row & value).bit_count() % 2 for row in masks)
            for value in range(1, 1 << len(matrix[0]))
        )

    for encoded in range(1 << 9):
        matrix = tuple(
            tuple((encoded >> (3 * row + column)) & 1 for column in range(3)) for row in range(3)
        )
        blocks = _independent_binary_blocks(matrix)
        assert sorted(column for _, columns, _ in blocks for column in columns) == [0, 1, 2]
        assert min(minimum(block) for block, _, _ in blocks) == minimum(matrix)
        for block, columns, rows in blocks:
            assert block == tuple(tuple(matrix[row][column] for column in columns) for row in rows)
            assert all(
                not matrix[row][column]
                for row in rows
                for column in range(3)
                if column not in columns
            )
