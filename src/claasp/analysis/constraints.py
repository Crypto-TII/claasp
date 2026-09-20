"""Constraints expressed over typed graph values."""

from dataclasses import dataclass

from claasp.graph import PortLike, Selection, as_selection


@dataclass(frozen=True, slots=True, init=False)
class FixedValue:
    """Fix every unit of a graph value to a supplied boundary value.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (FixedValue.__dataclass_params__.frozen, tuple(field.name for field in fields(FixedValue)))
        (True, ('target', 'value'))
    """

    target: Selection
    value: object

    def __init__(self, target: PortLike, value: object) -> None:
        object.__setattr__(self, "target", as_selection(target))
        object.__setattr__(self, "value", value)


@dataclass(frozen=True, slots=True, init=False)
class Equal:
    """Require two graph values to be equal unit by unit.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (Equal.__dataclass_params__.frozen, tuple(field.name for field in fields(Equal)))
        (True, ('left', 'right'))
    """

    left: Selection
    right: Selection

    def __init__(self, left: PortLike, right: PortLike) -> None:
        left, right = as_selection(left), as_selection(right)
        if left.value_type != right.value_type:
            raise ValueError("equality operands must have identical value types")
        object.__setattr__(self, "left", left)
        object.__setattr__(self, "right", right)


@dataclass(frozen=True, slots=True, init=False)
class NotEqual(Equal):
    """Require two graph values to differ in at least one unit.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (NotEqual.__dataclass_params__.frozen, tuple(field.name for field in fields(NotEqual)))
        (True, ('left', 'right'))
    """


@dataclass(frozen=True, slots=True, init=False)
class Nonzero:
    """Require at least one unit of a graph value to be nonzero.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (Nonzero.__dataclass_params__.frozen, tuple(field.name for field in fields(Nonzero)))
        (True, ('target',))
    """

    target: Selection

    def __init__(self, target: PortLike) -> None:
        object.__setattr__(self, "target", as_selection(target))


@dataclass(frozen=True, slots=True, init=False)
class HammingWeight:
    """Bound the number of nonzero units in a graph value.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (HammingWeight.__dataclass_params__.frozen, tuple(field.name for field in fields(HammingWeight)))
        (True, ('target', 'minimum', 'maximum'))
    """

    target: Selection
    minimum: int
    maximum: int

    def __init__(self, target: PortLike, minimum: int = 0, maximum: int | None = None) -> None:
        target = as_selection(target)
        maximum = target.value_type.unit_count if maximum is None else maximum
        if not 0 <= minimum <= maximum <= target.value_type.unit_count:
            raise ValueError("weight bounds must satisfy 0 <= minimum <= maximum <= size")
        object.__setattr__(self, "target", target)
        object.__setattr__(self, "minimum", minimum)
        object.__setattr__(self, "maximum", maximum)
