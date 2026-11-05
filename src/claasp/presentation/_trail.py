"""Common round-table construction for weighted trail presentations."""

from claasp.presentation.model import Alignment, Table, TableColumn


def round_table(rows, *, pattern, quantity, cumulative_quantity=None, notes=()):
    cumulative_quantity = quantity if cumulative_quantity is None else cumulative_quantity
    return Table(
        (
            TableColumn("round", "Round", Alignment.RIGHT),
            TableColumn("pattern", pattern),
            TableColumn("relative", f"Relative {quantity}", Alignment.RIGHT),
            TableColumn("cumulative", f"Cumulative {cumulative_quantity}", Alignment.RIGHT),
        ),
        tuple(rows),
        "Round trail",
        tuple(notes),
    )
