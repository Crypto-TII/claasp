"""Optional pandas conversion kept outside the core presentation model."""

from claasp.presentation.model import Table


def to_dataframe(table: Table):
    """Return a pandas DataFrame matching an immutable table's display text.

    EXAMPLES::

        >>> try:
        ...     to_dataframe()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    try:
        import pandas
    except ImportError as error:  # pragma: no cover - optional environment
        raise ImportError("dataframe presentation requires the optional pandas package") from error
    return pandas.DataFrame(
        [[cell.text for cell in row.cells] for row in table.rows],
        columns=[column.heading for column in table.columns],
    )
