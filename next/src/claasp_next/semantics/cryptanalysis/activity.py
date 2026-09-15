"""Component-table activity feasibility, independent of primitive wiring."""

from fractions import Fraction

from .trails import SBoxTransitionSemantics


def branch_number_activity_table(input_units, output_units, branch_number):
    """Return the legacy branch-bound abstraction in MSB-first row order.

    A branch number is a caller-supplied proven bound. These rows are a
    necessary condition only: for a general matrix a retained row need not
    have a concrete field-valued witness.
    """
    for size in (input_units, output_units, branch_number):
        if not isinstance(size, int) or isinstance(size, bool) or size < 1:
            raise ValueError("unit counts and branch number must be positive integers")
    total = input_units + output_units
    if branch_number > total:
        raise ValueError("branch number exceeds the combined unit count")
    if total > 16:
        raise ValueError("explicit activity tables are limited to 16 units")
    return tuple(tuple((value >> bit) & 1 for bit in reversed(range(total)))
                 for value in range(1 << total)
                 if value == 0 or value.bit_count() >= branch_number)


def possible_active_sbox_counts(tables, weight, *, maximum_active=None):
    """Return counts whose exact DDT probabilities multiply to ``2**-weight``.

    This is a table-only necessary condition, not a whole-primitive trail
    claim. Zero input differences are inactive and excluded. Non-dyadic
    entries are compared rationally without rounding logarithms.
    """
    if not isinstance(weight, int) or isinstance(weight, bool) or weight < 0:
        raise ValueError("weight must be a nonnegative integer")
    if maximum_active is not None and (not isinstance(maximum_active, int)
            or isinstance(maximum_active, bool) or maximum_active < 0):
        raise ValueError("maximum_active must be a nonnegative integer")
    probabilities = set()
    for table in tables:
        semantics = SBoxTransitionSemantics(table)
        for alpha in range(1, len(semantics.table)):
            for beta in range(len(semantics.table)):
                transition = semantics.xor_differential(alpha, beta)
                if transition.numerator:
                    probabilities.add(Fraction(transition.numerator, transition.denominator))
    target = Fraction(1, 1 << weight)
    if maximum_active is None:
        if Fraction(1) in probabilities:
            raise ValueError("probability-one active transitions require maximum_active")
        maximum_active = 0
        if probabilities:
            bound = max(probabilities)
            product = bound
            while product >= target:
                maximum_active += 1
                product *= bound
    current = {Fraction(1)}
    counts = {0} if weight == 0 else set()
    for count in range(1, maximum_active + 1):
        current = {previous * probability for previous in current
                   for probability in probabilities if previous * probability >= target}
        if target in current:
            counts.add(count)
        if not current:
            break
    return frozenset(counts)
