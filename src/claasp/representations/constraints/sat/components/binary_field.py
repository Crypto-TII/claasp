"""Exact bit circuits for binary-field arithmetic and binary linear maps."""

from claasp.components import Add, BinaryAffineMap, LinearMap, Multiply, Power, SBox
from claasp.representations.constraints import ConstraintBackend, _direct_model
from claasp.unit_types import BinaryExtensionField, Bit, Word
from claasp.utils.finite_fields import binary_field_multiply


class BinaryFieldFunctionalSATModel:
    """Encode polynomial-basis field operations without whole-component tables.

    Multiplication uses polynomial convolution and reduction. Linear maps use
    the binary images of basis vectors; lookups use one implication per entry
    and output bit. The same clauses can be lowered to SMT, CP or MILP.

    EXAMPLES::

        >>> from claasp.primitives import AES
        >>> from claasp.representations.constraints.sat import BooleanCNFModel
        >>> primitive = AES(number_of_rounds=1)
        >>> model = BooleanCNFModel(primitive)
        >>> model.cnf_formula().is_satisfied(model.witness(primitive.evaluate_with_trace(0, 0)))
        True
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "BinaryFieldFunctionalSATModel",
        "functional",
        "polynomial-basis binary-field circuits and binary linear maps",
        "XOR/AND circuits implement polynomial convolution, defining-polynomial reduction and exact basis images; lookup clauses use the supplied table.",
    )

    def __init__(self, component):
        if not isinstance(component, (Add, Multiply, Power, LinearMap, BinaryAffineMap, SBox)):
            raise TypeError("component needs binary algebraic functional semantics")
        unit = component.output_type.unit_type
        if not isinstance(unit, (Bit, BinaryExtensionField)) and not (
            isinstance(component, SBox) and isinstance(unit, Word)
        ):
            raise TypeError("binary algebraic encoding requires Bit or BinaryExtensionField")
        if isinstance(component, (BinaryAffineMap,)) and not isinstance(unit, BinaryExtensionField):
            raise TypeError("affine encoding requires BinaryExtensionField")
        self.component = component

    def encode(self, context, outputs, selected):
        """Append exact local equations and independently replayable auxiliaries."""
        component = self.component
        label = component.component_id
        width = component.output_type.unit_type.encoded_bit_size
        assert width is not None
        serial = 0
        constants: dict[int, str] = {}

        def fresh(operation, operands):
            nonlocal serial
            name = context.allocate(f"__field_{label}_{serial}")
            serial += 1
            context.auxiliary.append((operation, (name, *operands)))
            return name

        def constant(value):
            if value not in constants:
                name = fresh("one" if value else "zero", ())
                context.add_clause(
                    (context.indices[name] if value else -context.indices[name],), label
                )
                constants[value] = name
            return constants[value]

        def xor(values, target=None):
            # Repeated reads cancel over GF(2), including structural aliases.
            odd: set[str] = set()
            for value in values:
                if value in odd:
                    odd.remove(value)
                else:
                    odd.add(value)
            terms = sorted(odd)
            accumulator = terms[0] if terms else constant(0)
            for value in terms[1:]:
                result = fresh("xor", (accumulator, value))
                context.xor(result, accumulator, value, label)
                accumulator = result
            if target is not None:
                context.equal(target, accumulator, label)
            return accumulator

        def multiply(left, right):
            if not isinstance(component.output_type.unit_type, BinaryExtensionField):
                raise TypeError("field multiplication requires BinaryExtensionField")
            polynomial: list[list[str]] = [[] for _ in range(2 * width - 1)]
            for i, a in enumerate(reversed(left)):
                for j, b in enumerate(reversed(right)):
                    if a == b:
                        term = a
                    else:
                        term = fresh("and", (a, b))
                        context.and_(term, a, b, label)
                    polynomial[i + j].append(term)
            modulus = component.output_type.unit_type.modulus
            for degree in reversed(range(width, len(polynomial))):
                leading = xor(polynomial[degree])
                for bit in range(width):
                    if modulus & (1 << bit):
                        polynomial[degree - width + bit].append(leading)
            return tuple(xor(polynomial[bit]) for bit in reversed(range(width)))

        if isinstance(component, Add):
            for position, output in enumerate(outputs):
                for bit, target in enumerate(output):
                    xor((operand[position][bit] for operand in selected), target)
        elif isinstance(component, Multiply):
            for position, output in enumerate(outputs):
                accumulator = selected[0][position]
                for operand in selected[1:]:
                    accumulator = multiply(accumulator, operand[position])
                for target, source in zip(output, accumulator):
                    context.equal(target, source, label)
        elif isinstance(component, Power) and isinstance(component.output_type.unit_type, Bit):
            for output, source in zip(outputs, selected[0]):
                context.equal(output[0], source[0], label)
        elif isinstance(component, Power):
            for output, base in zip(outputs, selected[0]):
                exponent = component.exponent
                accumulator = tuple(constant(bit == width - 1) for bit in range(width))
                while exponent:
                    if exponent & 1:
                        accumulator = multiply(accumulator, base)
                    exponent >>= 1
                    if exponent:
                        base = multiply(base, base)
                for target, source in zip(output, accumulator):
                    context.equal(target, source, label)
        elif isinstance(component, LinearMap):
            unit = component.output_type.unit_type
            assert isinstance(unit, (Bit, BinaryExtensionField))
            for row, output in zip(component.matrix, outputs):
                for output_bit, target in enumerate(output):
                    terms = []
                    for coefficient, source in zip(row, selected[0]):
                        for input_bit, ref in enumerate(source):
                            image = (
                                coefficient
                                if isinstance(unit, Bit)
                                else binary_field_multiply(
                                    unit,
                                    coefficient,
                                    1 << (width - 1 - input_bit),
                                )
                            )
                            if image & (1 << (width - 1 - output_bit)):
                                terms.append(ref)
                    xor(terms, target)
        elif isinstance(component, BinaryAffineMap):
            for output, source in zip(outputs, selected[0]):
                for bit, (row, target) in enumerate(zip(component.matrix, output)):
                    terms = [ref for ref, coefficient in zip(source, row) if coefficient]
                    if component.offset & (1 << (width - 1 - bit)):
                        terms.append(constant(1))
                    xor(terms, target)
        else:
            for output, source in zip(outputs, selected[0]):
                for value, image in enumerate(component.table):
                    mismatch = tuple(
                        -context.indices[ref]
                        if value & (1 << (width - 1 - bit))
                        else context.indices[ref]
                        for bit, ref in enumerate(source)
                    )
                    for bit, target in enumerate(output):
                        literal = context.indices[target]
                        context.add_clause(
                            (*mismatch, literal if image & (1 << (width - 1 - bit)) else -literal),
                            label,
                        )


__all__ = ["BinaryFieldFunctionalSATModel"]
