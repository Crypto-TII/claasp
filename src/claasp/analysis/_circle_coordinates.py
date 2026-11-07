"""Exact circle-coordinate graph rewriting on the shared propagation schedule.

The derived graph computes ``theta_out(E(theta_in(x), fixed_inputs))``.
Its component characteristics are distinct from endpoint probabilities and
correlations. No primitive shape, round boundary or key-schedule assumption is made.
"""

from copy import copy
from dataclasses import dataclass

from claasp.analysis._circle import _BinaryCircleAnalysis
from claasp.components import BitVectorSBox, BitwiseAnd, Constant, SBox, Xor
from claasp.graph import Primitive, Selection, UnitArray, as_selection
from claasp.graph.binding import BindingKind
from claasp.graph.propagation import GraphPropagation
from claasp.semantics.cryptanalysis.bibrace import CircleBasis
from claasp.transformations.editing import _record, prune_orphans
from claasp.unit_types import Bit


@dataclass(frozen=True)
class CircleCoordinateGraph:
    """Original and derived graphs, their endpoint bases and fixed inputs."""

    source: Primitive
    primitive: Primitive
    input_name: str
    input_basis: CircleBasis
    output_basis: CircleBasis
    fixed_inputs: tuple[tuple[str, int], ...]


def circle_coordinate_graph(
    primitive,
    *,
    bibrace=None,
    input_basis=None,
    output_basis=None,
    input_name="plaintext",
    fixed_inputs=None,
    substitute_sboxes=True,
):
    """Build a binary graph with circle coordinates and explicit fixed keys.

    Small local coordinate changes use lookup tables. Larger changes use their
    quadratic Boolean circuits, avoiding exponential table construction. Data
    S-boxes matching ``bibrace`` are conjugated as a whole; adjacent inverse
    coordinate changes cancel through structural wiring. Other components keep
    their existing implementations and solver propagation rules.

    EXAMPLES::

        >>> from claasp.primitives import BitVectorSBox
        >>> from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace
        >>> p = BitVectorSBox(4, tuple(range(16)))
        >>> op = BinaryBibrace(4, ((8, 0, 8, 5),), (5,))
        >>> g = circle_coordinate_graph(p, bibrace=op, input_name='input')
        >>> all(g.primitive.evaluate(x) == x for x in range(16))
        True
    """
    context = _BinaryCircleAnalysis(
        primitive,
        bibrace=bibrace,
        input_basis=input_basis,
        output_basis=output_basis,
        input_name=input_name,
    )
    fixed = context._fixed(fixed_inputs)
    trace = primitive.evaluate_with_trace({**fixed, input_name: 0})
    derived = Primitive(
        f"{primitive.family_name}_circle_coordinates",
        {input_name: primitive.graph.input_descriptor(input_name)},
        provenance=primitive.provenance,
    )
    builder = derived._builder
    builder.add_round()
    plan = GraphPropagation(primitive)
    theta_cache: dict[tuple, UnitArray | Selection] = {}
    remapped = {}
    unpacked = {}

    def bits_of(value):
        value = as_selection(value)
        if isinstance(value.array_type.unit_type, Bit):
            return value
        if value not in unpacked:
            unpacked[value] = builder.unpack_bits(value)
        return unpacked[value]

    def typed(bits, array_type):
        bits = as_selection(bits)
        if isinstance(array_type.unit_type, Bit):
            return derived._add_binding(BindingKind.VIEW, (bits,), array_type)
        return derived._add_binding(
            BindingKind.PACK_BITS,
            (bits,),
            array_type,
            word_width=array_type.unit_type.encoded_bit_size,
        )

    def theta_cell(value, operation):
        value = as_selection(value)
        if not operation.forms:
            return value
        refs = derived.graph.selection_bit_sources(value)
        key = (refs, operation)
        if key in theta_cache:
            return theta_cache[key]
        result: UnitArray | Selection
        if operation.width <= 8:
            result = builder.add_component(
                BitVectorSBox(value, tuple(operation.theta(x) for x in range(1 << operation.width)))
            )
        else:
            # Character polynomials are exactly the coordinate bits of theta.
            terms = {}
            output = []
            for bit in reversed(range(operation.width)):
                factors = []
                for monomial in sorted(operation.character_polynomial(1 << bit)):
                    if monomial not in terms:
                        selected = [
                            as_selection(builder.pack_bits(value[operation.width - 1 - j], 1))
                            for j in range(operation.width)
                            if monomial >> j & 1
                        ]
                        terms[monomial] = (
                            selected[0]
                            if len(selected) == 1
                            else builder.add_component(BitwiseAnd(tuple(selected)))
                        )
                    factors.append(terms[monomial])
                coordinate = (
                    factors[0] if len(factors) == 1 else builder.add_component(Xor(tuple(factors)))
                )
                output.append(bits_of(coordinate))
            result = builder.join(*output)
        theta_cache[key] = result
        theta_cache[(derived.graph.selection_bit_sources(as_selection(result)), operation)] = value
        return result

    def theta(value, basis):
        bits = bits_of(value)
        pieces, offset = [], 0
        for operation in basis.cells:
            pieces.append(
                theta_cell(bits[tuple(range(offset, offset + operation.width))], operation)
            )
            offset += operation.width
        return typed(builder.join(*pieces), as_selection(value).array_type)

    inputs = {}
    for name, array in primitive.graph.input_arrays.items():
        if name == input_name:
            inputs[name] = ((theta(derived.graph.input(name), context.input_basis), True),)
        else:
            inputs[name] = (
                (builder.add_component(Constant(array.array_type, trace.values[name])), False),
            )

    def select(selection, values, cache):
        del cache
        refs = plan.bit_sources(selection)
        key = refs, selection.array_type
        if key not in remapped:
            bits = [bits_of(values[source][0][0])[position] for source, position in refs]
            value = typed(builder.join(*bits), selection.array_type)
            dependent = any(values[source][0][1] for source, _ in refs)
            remapped[key] = ((value, dependent),)
        return remapped[key]

    current_round = 0

    def rule(component, operands):
        nonlocal current_round
        number = plan.round_numbers[component.component_id]
        while current_round < number:
            builder.add_round()
            current_round += 1
        dependent = any(operand[0][1] for operand in operands)
        if not dependent:
            return (
                (
                    builder.add_component(
                        Constant(component.output_type, trace.values[component.component_id])
                    ),
                    False,
                ),
            )
        mapped = tuple(as_selection(operand[0][0]) for operand in operands)
        clone = copy(component)
        object.__setattr__(clone, "component_id", None)
        if (
            substitute_sboxes
            and bibrace is not None
            and isinstance(component, (SBox, BitVectorSBox))
        ):
            width = (
                component.output_type.unit_type.encoded_bit_size
                if isinstance(component, SBox)
                else component.output_type.unit_count
            )
            input_width = (
                component.inputs[0].array_type.unit_type.encoded_bit_size
                if isinstance(component, SBox)
                else component.inputs[0].array_type.unit_count
            )
            if width == input_width == bibrace.width:
                total_width = component.output_type.encoded_bit_size
                assert width is not None and total_width is not None
                basis = CircleBasis((bibrace,) * (total_width // width))
                mapped = (as_selection(theta(mapped[0], basis)),)
                object.__setattr__(
                    clone,
                    "table",
                    tuple(
                        bibrace.theta(component.table[bibrace.theta(x)]) for x in range(1 << width)
                    ),
                )
                object.__setattr__(clone, "inputs", mapped)
                result = theta(builder.add_component(clone), basis)
                return ((result, True),)
        object.__setattr__(clone, "inputs", mapped)
        return ((builder.add_component(clone), True),)

    propagated = plan.run(inputs, rule, select=select)
    assert propagated.output is not None
    builder.set_output(theta(propagated.output[0][0], context.output_basis))
    # Remove inverse changes canceled by later rewrites, including their weights.
    result = prune_orphans(derived).primitive
    _record(
        result,
        primitive,
        "circle_coordinates",
        (
            ("input_name", input_name),
            ("input_basis", repr(context.input_basis)),
            ("output_basis", repr(context.output_basis)),
            ("local_operation", repr(bibrace) if substitute_sboxes else "none"),
            *((f"fixed:{name}", hex(value)) for name, value in sorted(fixed.items())),
        ),
    )
    return CircleCoordinateGraph(
        primitive,
        result,
        input_name,
        context.input_basis,
        context.output_basis,
        tuple(sorted(fixed.items())),
    )
