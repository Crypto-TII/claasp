"""DIMACS serialization of the Boolean CNF representation."""

from claasp.representations.constraints.sat.cnf import CNFFormula
from claasp.representations.constraints.sat.model import NativeXorCNFFormula


class DimacsExporter:
    """Serialize :class:`~claasp.representations.constraints.sat.CNFFormula` for SAT solvers.

    EXAMPLES::

        >>> from claasp.representations.constraints.sat import CNFFormula
        >>> from claasp.representations.constraints.sat.exporters import DimacsExporter
        >>> DimacsExporter().export(CNFFormula(("x",), ((1,),), ("fixed",)), include_variable_map=False)
        'p cnf 1 1\\n1 0\\n'
    """

    def export(self, formula: CNFFormula, *, include_variable_map: bool = True) -> str:
        """Return deterministic DIMACS text, optionally with name comments."""

        if not isinstance(formula, CNFFormula):
            raise TypeError("formula must be a CNFFormula")
        lines = []
        if include_variable_map:
            lines.extend(f"c {index} {name}" for index, name in enumerate(formula.variables, 1))
        lines.append(f"p cnf {formula.variable_count} {formula.clause_count}")
        lines.extend(" ".join(map(str, clause)) + " 0" for clause in formula.clauses)
        return "\n".join(lines) + "\n"


class CryptoMiniSatDimacsExporter:
    """Serialize CNF with CryptoMiniSat's native ``x`` parity records.

    EXAMPLES::

        >>> from claasp.representations.constraints.sat import NativeXorCNFFormula
        >>> formula = NativeXorCNFFormula(("a", "b"), (), (), (), ((1, -2),), ("xor",))
        >>> CryptoMiniSatDimacsExporter().export(formula, include_variable_map=False)
        'p cnf 2 1\\nx1 -2 0\\n'
    """

    def export(self, formula: NativeXorCNFFormula, *, include_variable_map: bool = True) -> str:
        """Return deterministic extended DIMACS with native XOR records."""

        if not isinstance(formula, NativeXorCNFFormula):
            raise TypeError("formula must be a NativeXorCNFFormula")
        lines: list[str] = []
        if include_variable_map:
            lines.extend(f"c {index} {name}" for index, name in enumerate(formula.variables, 1))
        total = formula.clause_count + formula.native_xor_count
        lines.append(f"p cnf {formula.variable_count} {total}")
        lines.extend(" ".join(map(str, clause)) + " 0" for clause in formula.clauses)
        lines.extend("x" + " ".join(map(str, clause)) + " 0" for clause in formula.xor_clauses)
        return "\n".join(lines) + "\n"
