"""Lower typed Boolean-encodable graphs to the SMT representation."""

from claasp.graph import Primitive
from claasp.representations.constraints import ConstraintBackend, _direct_model
from claasp.representations.constraints.sat import BooleanCNFModel
from claasp.representations.constraints.smt.model import SMTFormula


class BooleanSMTModel:
    """Compile the supported Bit/Word graph subset to Boolean SMT assertions.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> formula = BooleanSMTModel(Speck(number_of_rounds=1)).smt_formula()
        >>> formula.assertion_count > 400
        True
        >>> "modular_add_0_1" in formula.provenance
        True
    """

    model_provenance = _direct_model(
        ConstraintBackend.SMT,
        "BooleanSMTModel",
        "functional",
        "literal CNF-to-SMT graph lowering",
        "Every CNF clause is translated mechanically and component provenance is retained.",
    )

    def __init__(self, primitive: Primitive) -> None:
        self.primitive = primitive

    def smt_formula(self) -> SMTFormula:
        """Return a deterministic solver-independent SMT representation."""

        return SMTFormula.from_cnf(BooleanCNFModel(self.primitive).cnf_formula())
