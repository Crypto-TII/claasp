"""Boolean circuits for exact products of dyadic transition probabilities.

Vectors are little-endian signed CNF literals, with bools for constants.
No logarithms or rounded weights participate in the solver objective.
"""

from fractions import Fraction


def _negate(bit):
    return not bit if isinstance(bit, bool) else -bit


def _comparison_clauses(bits, minimum):
    """Return CNF for a little-endian unsigned vector >= an integer."""
    if minimum <= 0:
        return ()
    if minimum >= 1 << len(bits):
        return ((),)
    clauses = []
    for position, bit in enumerate(bits):
        if not minimum & (1 << position):
            continue
        clause = [bit]
        clause.extend(
            _negate(higher) if minimum & (1 << index) else higher
            for index, higher in enumerate(bits[position + 1 :], position + 1)
        )
        if any(item is True for item in clause):
            continue
        clauses.append(tuple(item for item in clause if item is not False))
    return tuple(clauses)


def _add_bound(bits, minimum, allocate, indices, add):
    for clause in _comparison_clauses(bits, minimum):
        if clause:
            add(clause, "exact_probability_bound")
        else:
            impossible = indices[allocate("impossible_probability_bound")]
            add((impossible,), "exact_probability_bound")
            add((-impossible,), "exact_probability_bound")


class _ProductCircuit:
    def __init__(self, allocate, indices, add):
        self.allocate, self.indices, self.add = allocate, indices, add
        self.gates = {}

    def gate(self, operation, left, right):
        if operation == "and":
            if left is False or right is False:
                return False
            if left is True:
                return right
            if right is True or left == right:
                return left
            if left == -right:
                return False
        else:
            if left is False:
                return right
            if right is False:
                return left
            if left is True:
                return _negate(right)
            if right is True:
                return _negate(left)
            if left == right:
                return False
            if left == -right:
                return True
        key = operation, *sorted((left, right))
        if key in self.gates:
            return self.gates[key]
        output = self.indices[self.allocate(f"probability_gate_{len(self.gates)}")]
        self.gates[key] = output
        clauses: tuple[tuple[int, ...], ...]
        if operation == "and":
            clauses = ((-output, left), (-output, right), (output, -left, -right))
        else:
            clauses = (
                (-left, -right, -output),
                (left, right, -output),
                (left, -right, output),
                (-left, right, output),
            )
        for clause in clauses:
            self.add(clause, "exact_probability_product")
        return output

    def plus(self, left, right, width):
        carry = False
        output = []
        for position in range(width):
            a = left[position] if position < len(left) else False
            b = right[position] if position < len(right) else False
            ab = self.gate("xor", a, b)
            output.append(self.gate("xor", ab, carry))
            first = self.gate("and", a, b)
            second = self.gate("and", ab, carry)
            # The carry terms are disjoint, so XOR is also their OR.
            carry = self.gate("xor", first, second)
        return tuple(output)

    def times(self, left, right, width):
        output = (False,) * width
        for shift, bit in enumerate(right):
            if bit is False:
                continue
            row = (False,) * shift + tuple(self.gate("and", value, bit) for value in left)
            output = self.plus(output, row, width)
        return output


def _encode_probability_product(factors, weights, allocate, indices, add):
    """Compose selected numerators, including existing integer-weight bits."""
    circuit = _ProductCircuit(allocate, indices, add)
    bits, exponent = (True,), 0
    for local_exponent, numerator in factors:
        exponent += local_exponent
        bits = circuit.times(bits, numerator, exponent + 1)
    for name in weights:
        # A unary weight contributes 1/2 when set and 1 otherwise.
        weight = indices[name]
        exponent += 1
        bits = circuit.times(bits, (weight, -weight), exponent + 1)
    return bits, 1 << exponent


def _probability(steps):
    result = Fraction(1)
    for step in steps:
        result *= abs(Fraction(step.transition.numerator, step.transition.denominator))
    return result


def _satisfies_weight_bound(steps, maximum=None, fixed=None):
    if maximum is None and fixed is None:
        return True
    probability = _probability(steps)
    return (maximum is None or probability >= Fraction(1, 1 << maximum)) and (
        fixed is None or probability == Fraction(1, 1 << fixed)
    )
