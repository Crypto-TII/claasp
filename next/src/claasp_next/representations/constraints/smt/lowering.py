"""Lower typed Boolean-encodable graphs to the SMT representation."""

from claasp_next.graph import Primitive
from claasp_next.representations.constraints.sat import BooleanCNFModel
from claasp_next.representations.constraints.smt.formula import SMTFormula


class BooleanSMTModel:
    """Compile the supported Bit/Word graph subset to Boolean SMT assertions.

    EXAMPLES::

        >>> try:
        ...     BooleanSMTModel()
        ... except TypeError:
        ...     print("required configuration rejected")
        required configuration rejected
    """

    def __init__(self, primitive: Primitive) -> None:
        self.primitive = primitive

    def smt_formula(self) -> SMTFormula:
        """Return a deterministic solver-independent SMT representation."""

        return SMTFormula.from_cnf(BooleanCNFModel(self.primitive).cnf_formula())
