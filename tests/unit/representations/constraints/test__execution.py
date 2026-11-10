"""Query-local checks reject stale, incomplete and non-Boolean witnesses."""

from types import SimpleNamespace

import pytest

from claasp.representations.constraints._execution import _checked_assignment
from claasp.representations.constraints.sat import CNFFormula


@pytest.mark.parametrize("assignment", (None, {}, {"x": 2}, {"x": 0}))
def test_invalid_witnesses_are_not_accepted(assignment):
    formula = CNFFormula(("x",), ((1,),), ("fixed",))
    with pytest.raises(RuntimeError, match="assignment"):
        _checked_assignment(formula, SimpleNamespace(assignment=assignment))


def test_a_base_witness_is_rejected_after_an_enumeration_block():
    base = CNFFormula(("x",), ((1,),), ("fixed",))
    result = SimpleNamespace(assignment={"x": 1})
    assert _checked_assignment(base, result) == {"x": 1}
    blocked = CNFFormula(("x",), ((1,), (-1,)), ("fixed", "block"))
    with pytest.raises(RuntimeError, match="enumeration blocks"):
        _checked_assignment(blocked, result)
