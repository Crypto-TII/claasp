"""DIMACS serialization of the Boolean CNF representation."""

from claasp_next.representations.constraints.sat.cnf import CNFFormula


class DimacsExporter:
    """Serialize :class:`~claasp_next.representations.constraints.sat.CNFFormula` for SAT solvers."""

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
