"""Lower graph-level analysis constraints to Boolean CNF."""

from itertools import combinations

from claasp_next.analysis.constraints import Equal, FixedValue, HammingWeight, Nonzero, NotEqual
from claasp_next.analysis.problem import AnalysisProblem
from claasp_next.boolean import BooleanCNFModel, CNFFormula
from claasp_next.domains import Bit


def lower_boolean_problem(problem: AnalysisProblem) -> CNFFormula:
    """Lower a bit-domain analysis problem to CNF."""

    if problem.objective is not None:
        raise NotImplementedError("Boolean optimization requires an optimization-capable adapter")
    formula = BooleanCNFModel(problem.cipher).cnf_formula()
    indices = {name: index for index, name in enumerate(formula.variables, 1)}
    clauses = list(formula.clauses)
    provenance = list(formula.provenance)

    def literals(selection):
        if not isinstance(selection.value_type.domain, Bit):
            raise ValueError("Boolean constraints require Bit-domain targets")
        try:
            return tuple(
                indices[f"{selection.source.owner_id}_{position}"]
                for position in selection.positions
            )
        except KeyError as error:
            raise ValueError("constraint target does not belong to the analyzed cipher") from error

    def add(clause, label):
        clauses.append(tuple(clause))
        provenance.append(label)

    for number, constraint in enumerate(problem.constraints):
        label = f"constraint_{number}_{type(constraint).__name__.lower()}"
        if isinstance(constraint, FixedValue):
            values = problem.cipher._decode_boundary(constraint.value, constraint.target.value_type)
            if len(values) != constraint.target.value_type.unit_count:
                raise ValueError("fixed value length must match its constraint target")
            for value in values:
                constraint.target.value_type.domain.validate(value)
            for variable, value in zip(literals(constraint.target), values):
                add((variable if value else -variable,), label)
        elif isinstance(constraint, NotEqual):
            left, right = literals(constraint.left), literals(constraint.right)
            # Directly forbid every assignment where both vectors are equal.
            for values in range(1 << len(left)):
                clause = []
                for i, (a, b) in enumerate(zip(left, right)):
                    bit = (values >> i) & 1
                    clause.extend((-a if bit else a, -b if bit else b))
                add(clause, label)
        elif isinstance(constraint, Equal):
            for left, right in zip(literals(constraint.left), literals(constraint.right)):
                add((-left, right), label)
                add((left, -right), label)
        elif isinstance(constraint, Nonzero):
            add(literals(constraint.target), label)
        elif isinstance(constraint, HammingWeight):
            variables = literals(constraint.target)
            for subset in combinations(variables, constraint.maximum + 1):
                add(tuple(-item for item in subset), label)
            for subset in combinations(variables, len(variables) - constraint.minimum + 1):
                add(subset, label)
    return CNFFormula(formula.variables, tuple(clauses), tuple(provenance))
