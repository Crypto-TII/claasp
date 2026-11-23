"""Matsui's consecutive-round bounds on integral SAT trail weights."""

from dataclasses import replace


def _validated_bounds(bounds, rounds):
    if bounds is None:
        return None
    values = tuple(bounds)
    if len(values) != rounds - 1:
        raise ValueError("matsui_bounds must contain one bound for lengths 1 through rounds - 1")
    if any(type(value) is not int or value < 0 for value in values):
        raise ValueError("Matsui bounds must be nonnegative integers")
    return (0, *values)


def _round_weights(model):
    owned = model._shared._weights_by_component
    return tuple(
        tuple(
            name
            for component in round_.components
            for name in owned.get(component.component_id, ())
        )
        for round_ in model.primitive.graph.rounds
    )


def _bounded_formula(formula, weights, by_round, maximum, bounds):
    # Reuse propagation; only the counters depend on the queried objective.
    from claasp.representations.constraints.sat.trails import _at_most

    variables = list(formula.variables)
    indices = {name: i for i, name in enumerate(variables, 1)}
    clauses, labels = list(formula.clauses), list(formula.provenance)

    def allocate(name):
        candidate = name
        while candidate in indices:
            candidate += "_"
        variables.append(candidate)
        indices[candidate] = len(variables)
        return candidate

    def add(literals, label):
        clauses.append(tuple(literals))
        labels.append("matsui_window_bound" if bounds is not None else "total_weight_bound")

    _at_most(weights, maximum, allocate, indices, add, "search_total")
    if bounds is not None:
        rounds = len(by_round)
        for first in range(rounds):
            for stop in range(first + 1, rounds + 1):
                if first == 0 and stop == rounds:
                    continue
                window = tuple(name for group in by_round[first:stop] for name in group)
                limit = maximum - bounds[first] - bounds[rounds - stop]
                _at_most(window, limit, allocate, indices, add, f"matsui_{first}_{stop}")
    return replace(
        formula, variables=tuple(variables), clauses=tuple(clauses), provenance=tuple(labels)
    )
