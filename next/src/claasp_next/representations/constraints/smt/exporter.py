"""SMT-LIB 2 representation exporter."""

from claasp_next.representations.constraints.smt.formula import SMTFormula


class SMTLibExporter:
    """Serialize Boolean assertions as portable SMT-LIB 2 text."""

    def export(self, formula: SMTFormula, *, include_values: bool = True) -> str:
        if not isinstance(formula, SMTFormula):
            raise TypeError("formula must be an SMTFormula")
        lines = ["(set-logic QF_UF)"]
        lines.extend(f"(declare-fun {name} () Bool)" for name in formula.variables)
        for clause in formula.assertions:
            literals = [
                formula.variables[abs(item) - 1]
                if item > 0
                else f"(not {formula.variables[abs(item) - 1]})"
                for item in clause
            ]
            expression = literals[0] if len(literals) == 1 else f"(or {' '.join(literals)})"
            lines.append(f"(assert {expression})")
        lines.append("(check-sat)")
        if include_values:
            lines.append(f"(get-value ({' '.join(formula.variables)}))")
        return "\n".join(lines) + "\n"
