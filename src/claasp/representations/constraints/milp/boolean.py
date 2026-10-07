"""Compatibility imports for graph-wide Boolean MILP lowering."""

from claasp.representations.constraints.milp.lowering import (
    BooleanGraphMILPModel as _BooleanGraphMILPModel,
)
from claasp.representations.constraints.milp.lowering import (
    cnf_to_milp as _cnf_to_milp,
)

BooleanGraphMILPModel = _BooleanGraphMILPModel
cnf_to_milp = _cnf_to_milp
