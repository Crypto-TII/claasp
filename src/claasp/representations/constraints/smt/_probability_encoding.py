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


def _weight_interval(maximum=None, fixed=None, minimum=None, tolerance=0):
    from decimal import Decimal, localcontext

    def decimal(value):
        if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
            raise ValueError("weights must be finite nonnegative numbers")
        result = Decimal(str(value))
        if not result.is_finite() or result < 0:
            raise ValueError("weights must be finite nonnegative numbers")
        return result

    maximum, fixed, minimum = (
        None if value is None else decimal(value) for value in (maximum, fixed, minimum)
    )
    tolerance = decimal(tolerance)
    if fixed is not None and (maximum is not None or minimum is not None):
        raise ValueError("choose a weight interval or fixed_weight, not both")
    if tolerance and fixed is None:
        raise ValueError("weight_tolerance requires fixed_weight")
    if fixed is not None:
        with localcontext() as context:
            context.prec = max(
                80, len(fixed.as_tuple().digits) + len(tolerance.as_tuple().digits) + 10
            )
            minimum, maximum = max(Decimal(0), fixed - tolerance), fixed + tolerance
    if minimum is not None and maximum is not None and minimum > maximum:
        raise ValueError("minimum_weight must not exceed maximum_weight")
    return minimum, maximum


def _scaled_probability(denominator, weight, *, ceiling):
    """Round D*2**(-weight) with certified Decimal interval arithmetic.

    ln and exp are correctly rounded by Decimal. Expanding each endpoint by
    one representable neighbor and using directed rounding for arithmetic
    encloses the true value. Increase precision until both endpoints round to
    the same integer. Integer weights use rational arithmetic directly.
    """
    from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal, localcontext

    rounding = ROUND_CEILING if ceiling else ROUND_FLOOR
    if weight > denominator.bit_length():
        return int(ceiling)
    if weight == weight.to_integral_value():
        shift = int(weight)
        # Avoid constructing huge powers when the result must be below one.
        if shift > denominator.bit_length():
            return int(ceiling)
        divisor = 1 << shift
        return (denominator + divisor - 1) // divisor if ceiling else denominator // divisor
    for precision in (80, 160, 320, 640, 1280, 2560, 5120):
        with localcontext() as context:
            context.prec = precision
            log2 = Decimal(2).ln()
            log_lower, log_upper = log2.next_minus(), log2.next_plus()
            context.rounding = ROUND_FLOOR
            exponent_lower = weight.copy_negate() * log_upper
            context.rounding = ROUND_CEILING
            exponent_upper = weight.copy_negate() * log_lower
            low_exp = exponent_lower.exp().next_minus()
            high_exp = exponent_upper.exp().next_plus()
            context.rounding = ROUND_FLOOR
            low = (Decimal(denominator) * low_exp).to_integral_value(rounding=rounding)
            context.rounding = ROUND_CEILING
            high = (Decimal(denominator) * high_exp).to_integral_value(rounding=rounding)
            if low == high:
                return int(low)
    raise ValueError("weight boundary could not be certified; use a wider weight interval")


def _numerator_interval(denominator, interval):
    minimum, maximum = interval
    lower = 0 if maximum is None else _scaled_probability(denominator, maximum, ceiling=True)
    upper = (
        denominator if minimum is None else _scaled_probability(denominator, minimum, ceiling=False)
    )
    return lower, upper


def _add_weight_interval(bits, denominator, interval, allocate, indices, add):
    lower, upper = _numerator_interval(denominator, interval)
    _add_bound(bits, lower, allocate, indices, add)
    _add_bound(
        tuple(_negate(bit) for bit in bits), (1 << len(bits)) - 1 - upper, allocate, indices, add
    )


def _within_interval(steps, interval):
    probability = _probability(steps)
    lower, upper = _numerator_interval(probability.denominator, interval)
    return lower <= probability.numerator <= upper
