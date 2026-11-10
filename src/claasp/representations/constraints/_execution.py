"""Checked Boolean witnesses at portable solver execution boundaries."""


def _checked_assignment(formula, result):
    """Validate against the current query, including enumeration blocks."""
    assignment = result.assignment
    if assignment is None:
        raise RuntimeError("solver returned SAT without a characteristic assignment")
    try:
        valid = formula.is_satisfied(assignment)
    except (TypeError, ValueError) as error:
        raise RuntimeError("solver returned an incomplete or invalid Boolean assignment") from error
    if not valid:
        raise RuntimeError("solver assignment violates the current query or enumeration blocks")
    return assignment
