"""Shared graph traversal and wiring for executable and relational semantics.

Component rules own mathematics; this module owns graph order, selections,
structural bindings, source allocation and consumer edges. A relation need not
be a deterministic function: mask fanout and weighted transitions are supported
without pretending that masks propagate like concrete values.
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, cast

from claasp.graph.binding import BindingKind
from claasp.graph.primitive import Primitive
from claasp.graph.unit_array import Selection


@dataclass(frozen=True)
class PropagationResult:
    """Retained source values and lazily resolved structural bindings.

    EXAMPLES::

        >>> result = PropagationResult({'x': (1,)}, {}, (1,))
        >>> result.values['x'] == result.output
        True
    """

    values: dict[str, tuple]
    bindings: dict[str, tuple]
    output: tuple | None


class GraphPropagation:
    """One graph schedule shared by concrete, abstract and symbolic rules.

    Logical units can contain integers, continuous vectors, polynomials or
    other abstract objects. Rules receive a component and its selected operands.
    Use :meth:`bit_wiring` when allocating relations instead of executing them.
    Plans are rebuilt for each analysis, so edits to a primitive are observed.

    EXAMPLES::

        >>> from claasp.primitives.single_component_primitives import BitwiseNot
        >>> plan = GraphPropagation(BitwiseNot(2))
        >>> result = plan.run({'input': (1,)}, lambda c, operands: (3 ^ operands[0][0],))
        >>> result.output
        (2,)
    """

    def __init__(self, primitive: Primitive):
        if not isinstance(primitive, Primitive):
            raise TypeError("propagation requires a Primitive")
        self.primitive = primitive
        self.graph = primitive.graph
        self.components = self.graph.components
        self.sources = tuple(
            (name, value.array_type) for name, value in self.graph.input_arrays.items()
        ) + tuple((cast(str, c.component_id), c.output_type) for c in self.components)
        self.round_numbers = {
            c.component_id: r.number for r in self.graph.rounds for c in r.components
        }

    def run(
        self,
        inputs: Mapping[str, Sequence],
        rule: Callable,
        *,
        validate: Callable | None = None,
        materialize_bindings: bool = False,
        select: Callable | None = None,
    ) -> PropagationResult:
        """Run a forward rule with shared ordering, wiring and output selection.

        ``validate(source_id, value, array_type)`` validates each source once.
        A representation can supply ``select(selection, values, cache)`` for
        its unit encoding; this does not change graph traversal or rule dispatch.

        EXAMPLES::

            >>> from claasp.primitives.single_component_primitives import BitwiseNot
            >>> plan = GraphPropagation(BitwiseNot(2))
            >>> plan.run({'input': (1,)}, lambda c, inputs: (inputs[0][0] ^ 3,)).output
            (2,)
        """
        expected = set(self.graph.input_arrays)
        if set(inputs) != expected:
            raise ValueError(
                f"primitive inputs do not match: missing={sorted(expected - set(inputs))}, "
                f"unexpected={sorted(set(inputs) - expected)}"
            )
        values = {name: tuple(inputs[name]) for name in self.graph.input_arrays}
        cache: dict[str, tuple] = {}
        resolve = self.graph.resolve_selection if select is None else select
        if validate is not None:
            for name, array in self.graph.input_arrays.items():
                validate(name, values[name], array.array_type)
        for component in self.components:
            operands = tuple(resolve(item, values, cache) for item in component.inputs)
            output = tuple(rule(component, operands))
            if validate is not None:
                validate(component.component_id, output, component.output_type)
            values[cast(str, component.component_id)] = output
        selected_output = (
            None if self.graph.output is None else resolve(self.graph.output, values, cache)
        )
        if materialize_bindings:
            for binding in self.graph.bindings:
                resolve(binding.output.select_all(), values, cache)
        return PropagationResult(values, cache, selected_output)

    def bit_sources(self, selection):
        """Return canonical MSB-first source bits through all structural bindings.

        EXAMPLES::

            >>> from claasp.primitives.single_component_primitives import BitwiseNot
            >>> plan = GraphPropagation(BitwiseNot(2))
            >>> plan.bit_sources(plan.graph.input('input').select_all())
            (('input', 0), ('input', 1))
        """
        return self.graph.selection_bit_sources(selection)

    def select_bits(self, selection, values):
        """Select bit-valued abstract objects, including repeated source bits.

        EXAMPLES::

            >>> from claasp.primitives.single_component_primitives import BitwiseNot
            >>> plan = GraphPropagation(BitwiseNot(2))
            >>> plan.select_bits(plan.graph.input('input').select_all(), {'input': ('a', 'b')})
            ('a', 'b')
        """
        return tuple(values[name][bit] for name, bit in self.bit_sources(selection))

    def relations(self, rule, sources, operands, *, omit=()):
        """Apply a local relation to each component using preallocated wiring.

        The same schedule serves difference and mask constraints. The rule
        receives ``(component, input_variables, output_variables)`` and owns
        transition constraints and weights; it never navigates the graph.

        EXAMPLES::

            >>> from claasp.primitives.single_component_primitives import BitwiseNot
            >>> plan = GraphPropagation(BitwiseNot(2))
            >>> sources, operands, output, _ = plan.bit_wiring(str,
            ...     source_names=lambda name, vt: (name + ':0', name + ':1'))
            >>> relations = []
            >>> plan.relations(lambda c, a, b: relations.append((a, b)), sources, operands)
            >>> len(relations), len(relations[0][0][0]), len(relations[0][1])
            (1, 2, 2)
        """
        omitted = set(omit)
        for component in self.components:
            if component.component_id not in omitted:
                rule(component, operands[component.component_id], sources[component.component_id])

    def fold(self, known, value_of):
        """Retain sources whose complete dependencies have known values.

        ``value_of(component)`` supplies the concrete or abstract folded value.
        Constants have no dependencies and are folded without a special case.

        EXAMPLES::

            >>> from claasp.primitives.single_component_primitives import BitwiseNot
            >>> plan = GraphPropagation(BitwiseNot(2))
            >>> known = plan.fold({'input': (1,)}, lambda c: (2,))
            >>> known[plan.components[0].component_id]
            (2,)
            >>> plan.fold({}, lambda c: (2,))
            {}
        """
        result = dict(known)
        for component in self.components:
            if all(
                name in result
                for selection in component.inputs
                for name, _ in self.bit_sources(selection)
            ):
                result[component.component_id] = value_of(component)
        return result

    def unit_wiring(self, sources, *, pack=None, unpack=None):
        """Select preallocated abstract logical units through shared bindings.

        Representations which cannot convert their abstract units may provide
        explicit rejecting pack/unpack rules. They still share joins, views,
        selection order and the iterative binding traversal.

        EXAMPLES::

            >>> from claasp.primitives.single_component_primitives import BitwiseNot
            >>> plan = GraphPropagation(BitwiseNot(2))
            >>> sources = {name: (name,) for name, vt in plan.sources}
            >>> operands, output = plan.unit_wiring(sources)
            >>> operands[plan.components[0].component_id]
            (('input',),)
            >>> output == sources[plan.components[0].component_id]
            True
        """
        bindings = {binding.binding_id: binding for binding in self.graph.bindings}
        cache: dict[str, tuple] = {}
        options = {}
        if pack is not None:
            options["pack"] = pack
        if unpack is not None:
            options["unpack"] = unpack

        def select(selection):
            return resolve_selection(selection, sources, bindings, cache, **options)

        operands = {
            c.component_id: tuple(select(item) for item in c.inputs) for c in self.components
        }
        output = None if self.graph.output is None else select(self.graph.output)
        return operands, output

    def bit_wiring(
        self,
        allocate,
        *,
        source_names=None,
        edge_names=None,
        omit=(),
        output_names=None,
        sources=None,
    ):
        """Allocate shared source wiring or separate consumer-edge variables.

        Direct propagation aliases selected source variables. Linear/circle
        relations can allocate independent edge variables and use ``consumers``
        to impose their own fanout rule. No probability or XOR law is assumed.
        ``omit`` identifies concretely folded components. ``sources`` can reuse
        preallocated source objects, as in coupled difference/mask models.

        EXAMPLES::

            >>> from claasp.primitives.single_component_primitives import BitwiseNot
            >>> plan = GraphPropagation(BitwiseNot(2))
            >>> sources, operands, output, consumers = plan.bit_wiring(str,
            ...     source_names=lambda name, vt: (name + ':0', name + ':1'),
            ...     edge_names=lambda c, i, s: ('edge:0', 'edge:1'),
            ...     output_names=lambda vt: ('out:0', 'out:1'))
            >>> consumers['input'], output
            ([['edge:0'], ['edge:1']], ('out:0', 'out:1'))
        """
        if sources is None:
            if source_names is None:
                raise ValueError("provide source_names or preallocated sources")
            sources = {
                name: tuple(allocate(n) for n in source_names(name, array_type))
                for name, array_type in self.sources
            }
        expected = {name for name, _ in self.sources}
        if set(sources) != expected:
            raise ValueError("bit wiring must allocate every graph source exactly once")
        for name, array_type in self.sources:
            width = array_type.encoded_bit_size
            if width is None:
                raise TypeError("bit wiring requires canonically encoded unit types")
            if len(sources[name]) != width:
                raise ValueError(f"bit wiring source {name!r} requires {width} objects")
        consumers: dict[str, list[list[Any]]] = {
            name: [[] for _ in variables] for name, variables in sources.items()
        }
        operands = {}
        omitted = set(omit)
        for component in self.components:
            groups = []
            if component.component_id not in omitted:
                for index, selection in enumerate(component.inputs):
                    refs = self.bit_sources(selection)
                    variables = (
                        self.select_bits(selection, sources)
                        if edge_names is None
                        else tuple(allocate(n) for n in edge_names(component, index, selection))
                    )
                    if len(variables) != len(refs):
                        raise ValueError("edge variables must match the selected bit width")
                    groups.append(variables)
                    for variable, (name, bit) in zip(variables, refs):
                        consumers[name][bit].append(variable)
            operands[component.component_id] = tuple(groups)
        output = ()
        if self.graph.output is not None:
            refs = self.bit_sources(self.graph.output)
            output = (
                self.select_bits(self.graph.output, sources)
                if output_names is None
                else tuple(allocate(n) for n in output_names(self.graph.output.array_type))
            )
            if len(output) != len(refs):
                raise ValueError("output variables must match the selected bit width")
            for variable, (name, bit) in zip(output, refs):
                consumers[name][bit].append(variable)
        return sources, operands, output, consumers


__all__ = ["GraphPropagation", "PropagationResult"]


def _pack_unit(group, width):
    if all(isinstance(bit, int) for bit in group):
        return sum(int(bit) << (width - 1 - index) for index, bit in enumerate(group))
    return tuple(group)


def _unpack_unit(unit, width):
    if isinstance(unit, int):
        return tuple((unit >> (width - 1 - bit)) & 1 for bit in range(width))
    return tuple(unit)


def resolve_selection(
    selection, values, bindings, cache=None, *, pack=_pack_unit, unpack=_unpack_unit
):
    """Resolve joins, views and encoding conversions for every propagation.

    Only packing/unpacking a logical unit depends on its representation.
    Sample-parallel numeric arrays override those two operations, while
    concrete, continuous and symbolic values share the defaults. The iterative
    traversal handles deeply nested bindings without recursive Python calls.
    """
    cache = {} if cache is None else cache

    def available(source_id: str) -> bool:
        return source_id in values or source_id in cache

    def selected(item: Selection) -> tuple:
        source = (
            tuple(values[item.source.source_id])
            if item.source.source_id in values
            else cache[item.source.source_id]
        )
        return tuple(source[position] for position in item.positions)

    pending = [selection.source.source_id]
    while pending:
        source_id = pending[-1]
        if available(source_id):
            pending.pop()
            continue
        try:
            binding = bindings[source_id]
        except KeyError as error:
            raise KeyError(f"graph source {source_id!r} has no available value") from error
        missing = tuple(
            item.source.source_id for item in binding.inputs if not available(item.source.source_id)
        )
        if missing:
            pending.extend(reversed(missing))
            continue
        operands = tuple(selected(item) for item in binding.inputs)
        if binding.kind is BindingKind.JOIN:
            result = tuple(unit for operand in operands for unit in operand)
        elif binding.kind is BindingKind.VIEW:
            result = operands[0]
        elif binding.kind is BindingKind.PACK_BITS:
            bits = operands[0]
            groups = tuple(
                bits[start : start + binding.word_width]
                for start in range(0, len(bits), binding.word_width)
            )
            result = tuple(pack(group, binding.word_width) for group in groups)
        elif binding.kind is BindingKind.UNPACK_BITS:
            result = tuple(bit for unit in operands[0] for bit in unpack(unit, binding.word_width))
        else:  # pragma: no cover - closed enum
            raise AssertionError("unknown graph binding")
        cache[source_id] = result
        pending.pop()

    source_id = selection.source.source_id
    source = tuple(values[source_id]) if source_id in values else cache[source_id]
    return tuple(source[position] for position in selection.positions)
