"""Constraints expressed over typed graph values."""

from dataclasses import dataclass

from claasp.graph import Selection, UnitArrayLike, as_selection


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

    def __init__(self, target: UnitArrayLike, value: object) -> None:
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

    def __init__(self, left: UnitArrayLike, right: UnitArrayLike) -> None:
        left, right = as_selection(left), as_selection(right)
        if left.array_type != right.array_type:
            raise ValueError("equality operands must have identical array types")
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

    def __init__(self, target: UnitArrayLike) -> None:
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

    def __init__(self, target: UnitArrayLike, minimum: int = 0, maximum: int | None = None) -> None:
        target = as_selection(target)
        maximum = target.array_type.unit_count if maximum is None else maximum
        if not 0 <= minimum <= maximum <= target.array_type.unit_count:
            raise ValueError("weight bounds must satisfy 0 <= minimum <= maximum <= size")
        object.__setattr__(self, "target", target)
        object.__setattr__(self, "minimum", minimum)
        object.__setattr__(self, "maximum", maximum)


@dataclass(frozen=True, slots=True)
class _TrailRestriction:
    target: str
    kind: str
    value: int | None = None
    minimum: int = 0
    maximum: int | None = None
    positions: tuple[int, ...] | None = None


class Constraints:
    """Collect solver-independent restrictions on trail differences or masks.

    Targets are graph input names, component ids, or ``'output'``. Values are
    packed integers; bit positions count from the most significant encoded bit.
    Hamming weights count bits, including for Word and finite-field graphs.
    Constraints on masks do not fix concrete key values. Targeted key/tweak
    inputs are not implicitly fixed to zero. Existing explicit ``fixed_*``
    restrictions and the usual primary ``nonzero_input`` requirement still
    apply: select ``nonzero_input='key'`` to permit a zero plaintext mask.

    Methods append restrictions and return this collection for chaining. A search
    takes its own snapshot. Contradictory valid restrictions produce UNSAT;
    malformed targets, values, or bounds fail before solver execution.

    EXAMPLES::

        >>> c = Constraints().nonzero('key').nonzero('plaintext')
        >>> c = c.hamming_weight('key', exactly=1)
        >>> from claasp.primitives import ToySpeck
        >>> result = ToySpeck(1).analysis.find_one_xor_linear_trail(constraints=c)
        >>> masks = dict(result.input_masks)
        >>> masks['key'].bit_count(), masks['plaintext'] != 0
        (1, True)
    """

    __slots__ = ("_items",)

    def __init__(self):
        self._items: tuple[_TrailRestriction, ...] = ()

    def equal(self, target, value, *, bit_positions=None):
        """Fix a complete mask/difference or an MSB-first selection of bits.

        EXAMPLES::

            >>> c = Constraints().equal('plaintext', 3, bit_positions=(0, 2))
            >>> isinstance(c, Constraints)
            True
        """
        return self._add(target, "equal", value=value, bit_positions=bit_positions)

    def not_equal(self, target, value, *, bit_positions=None):
        """Require at least one selected bit to differ from a packed value.

        EXAMPLES::

            >>> isinstance(Constraints().not_equal('key', 0), Constraints)
            True
        """
        return self._add(target, "not_equal", value=value, bit_positions=bit_positions)

    def zero(self, target, *, bit_positions=None):
        """Set all selected difference or mask bits to zero.

        EXAMPLES::

            >>> isinstance(Constraints().zero('key'), Constraints)
            True
        """
        return self.equal(target, 0, bit_positions=bit_positions)

    def nonzero(self, target, *, bit_positions=None):
        """Require at least one selected bit to be one, independently per target.

        EXAMPLES::

            >>> isinstance(Constraints().nonzero('plaintext').nonzero('key'), Constraints)
            True
        """
        return self.not_equal(target, 0, bit_positions=bit_positions)

    def hamming_weight(self, target, *, exactly=None, minimum=0, maximum=None, bit_positions=None):
        """Bound the selected bit count inclusively, or require an exact count.

        EXAMPLES::

            >>> isinstance(Constraints().hamming_weight('output', minimum=1, maximum=3), Constraints)
            True
        """
        if exactly is not None:
            if minimum != 0 or maximum is not None:
                raise ValueError("choose exactly or minimum/maximum")
            minimum = maximum = exactly
        if (
            type(minimum) is not int
            or minimum < 0
            or (maximum is not None and (type(maximum) is not int or maximum < minimum))
        ):
            raise ValueError("weight bounds must be nonnegative integers with minimum <= maximum")
        return self._add(
            target, "weight", minimum=minimum, maximum=maximum, bit_positions=bit_positions
        )

    def _add(self, target, kind, *, value=None, minimum=0, maximum=None, bit_positions=None):
        if not isinstance(target, str) or not target:
            raise ValueError("constraint target must be a nonempty graph name")
        if kind != "weight" and (type(value) is not int or value < 0):
            raise ValueError("constraint value must be a nonnegative packed integer")
        positions = None if bit_positions is None else tuple(bit_positions)
        if positions is not None and (
            not positions
            or any(type(p) is not int or p < 0 for p in positions)
            or len(set(positions)) != len(positions)
        ):
            raise ValueError("bit positions must be distinct nonnegative integers, and nonempty")
        self._items += (_TrailRestriction(target, kind, value, minimum, maximum, positions),)
        return self

    def _snapshot(self):
        result = Constraints()
        result._items = self._items
        return result

    def _validate(self, primitive):
        widths = {
            name: array.array_type.encoded_bit_size
            for name, array in primitive.graph.input_arrays.items()
        }
        widths.update(
            {
                component.component_id: component.output_type.encoded_bit_size
                for component in primitive.graph.components
            }
        )
        widths["output"] = primitive.graph.output.array_type.encoded_bit_size
        for item in self._items:
            if item.target not in widths:
                raise ValueError(f"unknown trail constraint target {item.target!r}")
            width = widths[item.target]
            if type(width) is not int or width < 1:
                raise NotImplementedError("trail constraints require finite nonempty bit encodings")
            if item.positions is not None and any(p >= width for p in item.positions):
                raise ValueError(f"bit position outside {item.target!r} ({width} bits)")
            size = width if item.positions is None else len(item.positions)
            if item.value is not None and item.value >= 1 << size:
                raise ValueError("packed constraint value does not fit selected bits")
            if item.minimum > size or (item.maximum is not None and item.maximum > size):
                raise ValueError("Hamming-weight bound exceeds selected bit count")
        return self

    def _encode(self, arrays, output, allocate, indices, add):
        from claasp.representations.constraints.smt._cardinality import _at_most

        for number, item in enumerate(self._items):
            names = output if item.target == "output" else arrays[item.target]
            names = tuple(names[p] for p in item.positions) if item.positions is not None else names
            if item.kind in ("equal", "not_equal"):
                assert item.value is not None
                literals = tuple(
                    indices[name] if item.value & (1 << (len(names) - 1 - i)) else -indices[name]
                    for i, name in enumerate(names)
                )
                if item.kind == "equal":
                    for literal in literals:
                        add((literal,), "trail_constraint_equal")
                else:
                    add(tuple(-literal for literal in literals), "trail_constraint_not_equal")
            else:

                def local_allocate(name, prefix=f"__trail_constraint_{number}_upper"):
                    return allocate(prefix + name)

                _at_most(
                    names,
                    len(names) if item.maximum is None else item.maximum,
                    local_allocate,
                    indices,
                    add,
                )
                if item.minimum:
                    complements = tuple(
                        allocate(f"__trail_constraint_{number}_not_{i}") for i in range(len(names))
                    )
                    for source, complement in zip(names, complements):
                        add((indices[source], indices[complement]), "trail_constraint_complement")
                        add((-indices[source], -indices[complement]), "trail_constraint_complement")

                    def lower_allocate(name, prefix=f"__trail_constraint_{number}_lower"):
                        return allocate(prefix + name)

                    _at_most(complements, len(names) - item.minimum, lower_allocate, indices, add)

    def _check(self, arrays, output, values):
        for item in self._items:
            names = output if item.target == "output" else arrays[item.target]
            names = tuple(names[p] for p in item.positions) if item.positions is not None else names
            bits = tuple(int(values[name]) for name in names)
            packed = sum(bit << (len(bits) - 1 - i) for i, bit in enumerate(bits))
            if item.kind == "equal" and packed != item.value:
                return False
            if item.kind == "not_equal" and packed == item.value:
                return False
            if item.kind == "weight" and not item.minimum <= sum(bits) <= (
                len(bits) if item.maximum is None else item.maximum
            ):
                return False
        return True


def _trail_constraints(value, primitive):
    if value is None:
        return Constraints()
    if not isinstance(value, Constraints):
        raise TypeError("constraints must be a Constraints instance")
    return value._snapshot()._validate(primitive)
