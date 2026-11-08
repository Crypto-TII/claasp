"""Shared Boolean circuit construction for weighted SAT analysis models."""

from claasp.representations.constraints.sat.model import CNFFormula
from claasp.representations.constraints.smt._probability_encoding import _ProductCircuit


def _negate(value):
    return not value if isinstance(value, bool) else -value


class _BooleanBuilder:
    def __init__(self, variables=(), clauses=(), labels=()):
        self.variables = list(variables)
        self.indices = {name: index + 1 for index, name in enumerate(variables)}
        self.clauses = list(clauses)
        self.labels = list(labels)
        self.logic = _ProductCircuit(
            lambda name: self.allocate("logic_" + name), self.indices, self.add
        )

    def allocate(self, name):
        if name in self.indices:
            return name
        self.variables.append(name)
        self.indices[name] = len(self.variables)
        return name

    def fresh(self, label):
        name = self.allocate(f"{label}_{len(self.variables)}")
        return self.indices[name]

    def add(self, clause, label="quasidifferential"):
        if any(value is True for value in clause):
            return
        literals = tuple(value for value in clause if value is not False)
        if not literals:
            variable = self.fresh("contradiction")
            self.clauses.extend(((variable,), (-variable,)))
            self.labels.extend((label, label))
        else:
            self.clauses.append(literals)
            self.labels.append(label)

    def require(self, value, label="quasidifferential"):
        self.add((value,), label)

    def equal(self, left, right):
        self.add((_negate(left), right))
        self.add((left, _negate(right)))

    def xor(self, values):
        result = False
        for value in values:
            result = self.logic.gate("xor", result, value)
        return result

    def and_(self, values):
        result = True
        for value in values:
            result = self.logic.gate("and", result, value)
        return result

    def or_(self, values):
        return _negate(self.and_(_negate(value) for value in values))

    def formula(self):
        return CNFFormula(tuple(self.variables), tuple(self.clauses), tuple(self.labels))
