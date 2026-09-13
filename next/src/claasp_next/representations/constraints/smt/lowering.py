"""Lower typed Boolean-encodable graphs to the SMT representation."""

from claasp_next.representations.constraints.sat import BooleanCNFModel
from claasp_next.core import Cipher
from claasp_next.representations.constraints.smt.formula import SMTFormula


class BooleanSMTModel:
    """Compile the supported Bit/Word graph subset to Boolean SMT assertions."""

    def __init__(self, cipher: Cipher) -> None:
        self.cipher = cipher

    def smt_formula(self) -> SMTFormula:
        """Return a deterministic solver-independent SMT representation."""

        return SMTFormula.from_cnf(BooleanCNFModel(self.cipher).cnf_formula())
