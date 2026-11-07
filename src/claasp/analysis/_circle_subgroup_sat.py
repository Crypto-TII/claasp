"""Symbolic spatial-mask optimization with exact affine-key refinement."""

from claasp.drivers.solvers import KissatSolver, SatStatus
from claasp.representations.constraints.sat._boolean import _BooleanBuilder, _negate
from claasp.representations.constraints.sat.trails import _at_most


def search_subgroup(
    model, *, solver=None, maximum_column_states=1 << 16, maximum_candidates=1 << 16
):
    """Prove one feasible subgroup optimum without global mask enumeration."""
    from claasp.analysis.circle_linear_trails import CircleLinearTrailSearchResult

    if (
        isinstance(maximum_candidates, bool)
        or not isinstance(maximum_candidates, int)
        or maximum_candidates < 1
    ):
        raise ValueError("maximum_candidates must be positive")
    if (
        isinstance(maximum_column_states, bool)
        or not isinstance(maximum_column_states, int)
        or maximum_column_states < 1
    ):
        raise ValueError("maximum_column_states must be positive")
    if any(1 << len(outputs) > maximum_column_states for outputs in model._column_outputs):
        raise ValueError("column cost table exceeds maximum_column_states")
    driver = KissatSolver() if solver is None else solver
    if not callable(getattr(driver, "solve", None)):
        raise TypeError("solver must provide solve(formula)")
    builder = _BooleanBuilder()
    primary = tuple(builder.fresh(f"circle_mask_{i}") for i in range(2 * model.cells))
    builder.add(primary, "nonzero_circle_mask")
    q, s = primary[: model.cells], primary[model.cells :]
    weights = []
    for r in range(model.rounds):
        q = tuple(builder.xor((a, b)) for a, b in zip(q, s))

        def permute(values):
            result = [False] * model.cells
            for i, target in enumerate(model.permutation):
                result[target] = values[i]
            return tuple(result)

        q, s = permute(q), permute(s)
        for column, (_, outputs, table) in enumerate(model._column_costs):
            for position in range(max(table)):
                name = builder.allocate(f"cost_{r}_{column}_{position}")
                variable = builder.indices[name]
                weights.append(name)
                for pattern, cost in enumerate(table):
                    mismatch = tuple(
                        _negate(q[output]) if pattern >> i & 1 else q[output]
                        for i, output in enumerate(outputs)
                    )
                    builder.add(
                        (*mismatch, variable if position < cost else -variable),
                        "circle_column_rank",
                    )

        def diffuse(values):
            return tuple(
                builder.xor(
                    values[source]
                    for source, row in enumerate(model.diffusion_rows)
                    if row >> target & 1
                )
                for target in range(model.cells)
            )

        q, s = diffuse(q), diffuse(s)

    visited = 0

    def feasible(bound):
        nonlocal visited
        while True:
            current = _BooleanBuilder(builder.variables, builder.clauses, builder.labels)
            if bound is not None:
                _at_most(
                    weights, bound, current.allocate, current.indices, current.add, "circle_weight"
                )
            formula = current.formula()
            solved = driver.solve(formula)
            if solved.status is SatStatus.UNSATISFIABLE:
                return None
            if solved.status is not SatStatus.SATISFIABLE or solved.assignment is None:
                raise RuntimeError("solver did not complete the circle subgroup query")
            if not formula.is_satisfied(solved.assignment):
                raise RuntimeError("circle solver assignment failed CNF validation")
            visited += 1
            if visited > maximum_candidates:
                raise ValueError("affine-key refinement exceeds maximum_candidates")
            code = sum(
                int(solved.assignment[builder.variables[v - 1]]) << i for i, v in enumerate(primary)
            )
            trail = model.trail(code)
            encoded_cost = sum(int(solved.assignment[name]) for name in weights)
            if encoded_cost != trail.cost:
                raise RuntimeError("symbolic circle weight failed independent validation")
            if trail.conditions.consistent:
                return trail
            builder.add(
                tuple(-v if code >> i & 1 else v for i, v in enumerate(primary)),
                "infeasible_master_key_class",
            )

    best = feasible(None)
    if best is None:
        raise ValueError("no nonzero trail survives the supplied affine key schedule")
    lower, upper = 0, best.cost
    while lower < upper:
        middle = (lower + upper) // 2
        candidate = feasible(middle)
        if candidate is None:
            lower = middle + 1
        else:
            best, upper = candidate, candidate.cost
    return CircleLinearTrailSearchResult(
        best.cost,
        None,
        best,
        backend="perfect_subgroup_sat",
    )
