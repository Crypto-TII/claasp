"""Lower graph-level analysis constraints to Boolean CNF."""

from itertools import combinations

from claasp_next.analysis.constraints import Equal, FixedValue, HammingWeight, Nonzero, NotEqual
from claasp_next.analysis.problem import AnalysisProblem
from claasp_next.representations.constraints.sat import BooleanCNFModel, CNFFormula
from claasp_next.representations.constraints.sat.encoding import selection_variable_names
from claasp_next.domains import Bit


def lower_boolean_problem(problem: AnalysisProblem) -> CNFFormula:
    """Lower a bit-domain analysis problem to CNF."""

    if problem.objective is not None:
        raise NotImplementedError("Boolean optimization requires an optimization-capable adapter")
    formula = BooleanCNFModel(problem.primitive).cnf_formula()
    variables = list(formula.variables)
    indices = {name: index for index, name in enumerate(variables, 1)}
    clauses = list(formula.clauses)
    provenance = list(formula.provenance)

    def groups(selection):
        try:
            return tuple(
                tuple(indices[name] for name in names)
                for names in selection_variable_names(selection)
            )
        except KeyError as error:
            raise ValueError("constraint target does not belong to the analyzed primitive") from error

    def literals(selection):
        return tuple(item for group in groups(selection) for item in group)

    def add(clause, label):
        clauses.append(tuple(clause))
        provenance.append(label)

    for number, constraint in enumerate(problem.constraints):
        label = f"constraint_{number}_{type(constraint).__name__.lower()}"
        if isinstance(constraint, FixedValue):
            values = problem.primitive._decode_boundary(constraint.value, constraint.target.value_type)
            if len(values) != constraint.target.value_type.unit_count:
                raise ValueError("fixed value length must match its constraint target")
            for value in values:
                constraint.target.value_type.domain.validate(value)
            for group, value in zip(groups(constraint.target), values):
                width = len(group)
                for bit, variable in enumerate(group):
                    encoded = (value >> (width - 1 - bit)) & 1
                    add((variable if encoded else -variable,), label)
        elif isinstance(constraint, NotEqual):
            left, right = literals(constraint.left), literals(constraint.right)
            differences = []
            for bit, (a, b) in enumerate(zip(left, right)):
                name = f"__constraint_{number}_different_{bit}"
                variables.append(name)
                difference = len(variables)
                indices[name] = difference
                differences.append(difference)
                add((-a, -b, -difference), label)
                add((a, b, -difference), label)
                add((a, -b, difference), label)
                add((-a, b, difference), label)
            add(differences, label)
        elif isinstance(constraint, Equal):
            for left, right in zip(literals(constraint.left), literals(constraint.right)):
                add((-left, right), label)
                add((left, -right), label)
        elif isinstance(constraint, Nonzero):
            add(literals(constraint.target), label)
        elif isinstance(constraint, HammingWeight):
            if not isinstance(constraint.target.value_type.domain, Bit):
                raise NotImplementedError("word-unit Hamming weight requires cardinality auxiliaries")
            bounded = literals(constraint.target)
            for subset in combinations(bounded, constraint.maximum + 1):
                add(tuple(-item for item in subset), label)
            for subset in combinations(bounded, len(bounded) - constraint.minimum + 1):
                add(subset, label)
    return CNFFormula(tuple(variables), tuple(clauses), tuple(provenance))
