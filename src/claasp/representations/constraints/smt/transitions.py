"""Compatibility imports for SMT component transition models."""

from claasp.representations.constraints.smt.components import (
    ModularAddDifferentialSMTModel as _ModularAddDifferentialSMTModel,
)
from claasp.representations.constraints.smt.components import (
    ModularAddLinearSMTModel as _ModularAddLinearSMTModel,
)
from claasp.representations.constraints.smt.components import (
    SBoxTransitionSMTModel as _SBoxTransitionSMTModel,
)
from claasp.representations.constraints.smt.components import (
    SBoxXorDifferentialSMTModel as _SBoxXorDifferentialSMTModel,
)
from claasp.representations.constraints.smt.components import (
    SBoxXorLinearSMTModel as _SBoxXorLinearSMTModel,
)

ModularAddDifferentialSMTModel = _ModularAddDifferentialSMTModel
ModularAddLinearSMTModel = _ModularAddLinearSMTModel
SBoxTransitionSMTModel = _SBoxTransitionSMTModel
SBoxXorDifferentialSMTModel = _SBoxXorDifferentialSMTModel
SBoxXorLinearSMTModel = _SBoxXorLinearSMTModel


def _xor_equivalence(names, indices, clauses, provenance, allocate=None):
    """Encode equality between the first variable and the XOR of the rest."""

    names = tuple(names)
    if len(names) > 5:
        if allocate is None:
            raise ValueError("large XOR relations require an auxiliary-variable allocator")
        output, operands = names[0], names[1:]
        current = operands[0]
        for number, operand in enumerate(operands[1:-1]):
            auxiliary = allocate(f"xor_aux_{len(indices)}_{number}")
            _xor_equivalence((auxiliary, current, operand), indices, clauses, provenance)
            current = auxiliary
        _xor_equivalence((output, current, operands[-1]), indices, clauses, provenance)
        return
    for assignment in range(1 << len(names)):
        values = tuple((assignment >> (len(names) - 1 - bit)) & 1 for bit in range(len(names)))
        if sum(values) % 2 == 0:
            continue
        clauses.append(
            tuple(-indices[name] if value else indices[name] for name, value in zip(names, values))
        )
        provenance.append("xor_equivalence")
