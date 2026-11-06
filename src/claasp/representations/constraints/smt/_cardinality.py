"""Shared cardinality encoding for weighted Boolean trail relations."""


def _at_most(names, bound, allocate, indices, add):
    if bound >= len(names):
        return
    if bound == 0:
        for name in names:
            add((-indices[name],), "weight_bound")
        return
    previous = ()
    for position, name in enumerate(names):
        current = tuple(
            allocate(f"__weight_counter_{position}_{count}") for count in range(1, bound + 1)
        )
        add((-indices[name], indices[current[0]]), "weight_bound")
        if previous:
            for count in range(bound):
                add((-indices[previous[count]], indices[current[count]]), "weight_bound")
            for count in range(1, bound):
                add(
                    (-indices[name], -indices[previous[count - 1]], indices[current[count]]),
                    "weight_bound",
                )
            add((-indices[name], -indices[previous[-1]]), "weight_bound")
        previous = current
