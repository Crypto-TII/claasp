"""Lower typed Boolean-encodable graphs to SMT."""

from claasp_next.boolean import BooleanCNFModel
from claasp_next.core import Cipher
from claasp_next.smt.formula import SMTFormula


class BooleanSMTModel:
    """Compile the supported Bit/Word graph subset to Boolean SMT assertions."""

    def __init__(self, cipher: Cipher) -> None:
        self.cipher = cipher

    def smt_formula(self) -> SMTFormula:
        """Return a deterministic solver-independent SMT representation."""

        return SMTFormula.from_cnf(BooleanCNFModel(self.cipher).cnf_formula())
