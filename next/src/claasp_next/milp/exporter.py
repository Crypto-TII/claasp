"""Deterministic CPLEX-LP export for portable MILP models."""

from claasp_next.milp.model import MILPModel, VariableKind


def _number(value: float) -> str:
    return str(int(value)) if value.is_integer() else format(value, ".15g")


def _expression(terms: tuple[tuple[str, float], ...], constant: float = 0) -> str:
    pieces: list[str] = []
    for name, coefficient in terms:
        sign = "+" if coefficient > 0 else "-"
        magnitude = abs(coefficient)
        term = name if magnitude == 1 else f"{_number(magnitude)} {name}"
        pieces.append(f" {sign} {term}")
    if constant:
        pieces.append(f" {'+' if constant > 0 else '-'} {_number(abs(constant))}")
    return "".join(pieces).lstrip(" +") or "0"


class LPExporter:
    """Serialize :class:`MILPModel` using the widely supported LP format."""

    def export(self, model: MILPModel) -> str:
        """Return deterministic ASCII LP text."""

        if not isinstance(model, MILPModel):
            raise TypeError("model must be an MILPModel")
        objective = _expression(model.objective.terms, model.objective.constant)
        if objective == "0":
            objective = f"0 {model.variables[0].name}"
        lines = [model.objective_sense.value.title(), f" objective: {objective}", "Subject To"]
        for index, constraint in enumerate(model.constraints):
            name = constraint.name or f"constraint_{index}"
            rhs = constraint.rhs - constraint.expression.constant
            lines.append(f" {name}: {_expression(constraint.expression.terms)} {constraint.sense.value} {_number(rhs)}")
        lines.append("Bounds")
        for variable in model.variables:
            if variable.kind is VariableKind.BINARY:
                continue
            lower = "-inf" if variable.lower_bound is None else _number(float(variable.lower_bound))
            upper = "+inf" if variable.upper_bound is None else _number(float(variable.upper_bound))
            lines.append(f" {lower} <= {variable.name} <= {upper}")
        binaries = [variable.name for variable in model.variables if variable.kind is VariableKind.BINARY]
        generals = [variable.name for variable in model.variables if variable.kind is VariableKind.INTEGER]
        if binaries:
            lines.extend(("Binary", *(f" {name}" for name in binaries)))
        if generals:
            lines.extend(("General", *(f" {name}" for name in generals)))
        lines.append("End")
        return "\n".join(lines) + "\n"
