"""Fixed legacy paired-Speck evidence on the immutable v5 graph."""

import shutil

import pytest

from claasp import paired_xor_primitive, units_from_int
from claasp.drivers.solvers import MinisatSolver, SatStatus
from claasp.primitives import Speck
from claasp.representations.constraints.sat import BooleanCNFModel
from claasp.representations.constraints.sat.encoding import (
    encode_unit,
    resolved_selection_variable_names,
)

pytestmark = pytest.mark.external


SINGLE_KEY_DATA = (
    0x20400040,
    0x80008100,
    0x80008402,
    0x8D029D08,
    0x60021420,
    0x106040E0,
    0x03800001,
    0x00040000,
    0x08000800,
    0x08102810,
    0x0800A840,
)

RELATED_KEY_SAT = (
    (0x1000, 0, 0x31, 0x80, 0x200, 0x2800, 0, 0, 0x40, 0, 0, 0x8000, 0x8000, 0x8002),
    (
        0x14080008,
        0x200000,
        0x40004000,
        0xC0B1C0B0,
        0x667764B4,
        0x907002A1,
        0x08810205,
        0x00140800,
        0x20000000,
        0,
        0,
        0,
        0x80008000,
        0x01000102,
        0x8102850A,
    ),
    0x0A80088000681000,
)

RELATED_KEY_UNSAT = (
    (
        0x0025,
        0x0080,
        0x0200,
        0x0800,
        0,
        0,
        0,
        0x0040,
        0x0140,
        0x0240,
        0x87C0,
        0x0042,
        0x8140,
        0x0557,
    ),
    (
        0x50A45021,
        0x508100A0,
        0x02810001,
        0x00040000,
        0,
        0,
        0,
        0,
        0x00400040,
        0x81008000,
        0x81428140,
        0x80028500,
        0x80429440,
        0x9000C102,
        0xC575C17E,
    ),
    0x0001400008800025,
)


def _fix_selection(primitive, selection, value, assumptions):
    value_type = selection.value_type
    units = units_from_int(
        value,
        value_type.domain.width,
        value_type.unit_count,
    )
    groups = resolved_selection_variable_names(primitive, selection)
    for names, unit in zip(groups, units):
        for name, bit in zip(names, encode_unit(unit, value_type)):
            assumptions[name] = bit


def _solve(rounds, data, *, keys=(), key_difference=0, shared_key=False):
    assert shutil.which("minisat") is not None, "the external test job must install MiniSat"
    result = paired_xor_primitive(
        Speck(number_of_rounds=rounds),
        shared_inputs=("key",) if shared_key else (),
    )
    primitive = result.primitive
    assumptions = {}
    _fix_selection(
        primitive,
        result.differences_by_input["plaintext"],
        data[0],
        assumptions,
    )
    if not shared_key:
        _fix_selection(
            primitive,
            result.differences_by_input["key"],
            key_difference,
            assumptions,
        )
    for selection, value in zip(result.round_differences, data[1:]):
        _fix_selection(primitive, selection, value, assumptions)
    for selection, value in zip(result.key_differences, keys):
        _fix_selection(primitive, selection, value, assumptions)
    formula = BooleanCNFModel(primitive).cnf_formula()
    return MinisatSolver(timeout_seconds=60).solve(formula, assumptions)


def test_legacy_single_key_compatible_trail_is_satisfiable():
    """Preserve the ten-round compatible trail from Song et al., Table 5."""

    assert _solve(10, SINGLE_KEY_DATA, shared_key=True).status is SatStatus.SATISFIABLE


def test_legacy_related_key_compatible_trail_is_satisfiable():
    keys, data, key_difference = RELATED_KEY_SAT
    assert (
        _solve(14, data, keys=keys, key_difference=key_difference).status is SatStatus.SATISFIABLE
    )


def test_legacy_related_key_incompatible_trail_is_unsatisfiable():
    """Preserve the fourteen-round incompatible trail from Sadeghi et al., Table 28."""

    keys, data, key_difference = RELATED_KEY_UNSAT
    assert (
        _solve(14, data, keys=keys, key_difference=key_difference).status is SatStatus.UNSATISFIABLE
    )
