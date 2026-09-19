"""Self-contained C source compilation for fixed-width typed graphs."""

from hashlib import sha256

from claasp_next.components import (
    Add,
    BitVectorSBox,
    BitwiseAnd,
    BitwiseNot,
    BitwiseOr,
    Constant,
    Identity,
    LinearMap,
    ModularAdd,
    ModularMultiply,
    ModularSubtract,
    Multiply,
    Permutation,
    Rotate,
    SBox,
    Shift,
    VariableRotate,
    VariableShift,
    Xor,
)
from claasp_next.domains import Bit, Word
from claasp_next.graph import Primitive
from claasp_next.graph.binding import BindingKind
from claasp_next.provenance import DriverIdentity, DriverKind
from claasp_next.representations.source.model import (
    SourceArtifact,
    SourceCompilationResult,
    SourceDiagnostic,
    SourceLanguage,
    SourceStatus,
)
from claasp_next.serialization import primitive_digest

C_COMPILER = DriverIdentity("claasp_c_source", DriverKind.COMPILER, "1")


def compile_c_source(primitive: Primitive) -> SourceCompilationResult:
    """Compile the registered Bit/Word subset to deterministic C11 source.

    EXAMPLES::

        >>> try:
        ...     compile_c_source()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    if not isinstance(primitive, Primitive):
        raise TypeError("C source compilation requires a Primitive")
    diagnostic = _applicability(primitive)
    if diagnostic is not None:
        return SourceCompilationResult(SourceStatus.UNSUPPORTED, diagnostic=diagnostic)
    names = {name: f"in{index}" for index, name in enumerate(primitive.input_ports)}
    names.update(
        {item.component_id: f"v{index}" for index, item in enumerate(primitive.components)}
    )
    bindings = {item.binding_id: item for item in primitive.bindings}

    def selection_expressions(selection):
        return tuple(
            source_expression(selection.source.owner_id, position, set())
            for position in selection.positions
        )

    def source_expression(source_id, position, stack):
        if source_id in names:
            return f"{names[source_id]}[{position}]"
        if source_id in stack:
            raise ValueError("cyclic structural binding")
        binding = bindings[source_id]
        selected = tuple(
            selection_expressions_with_stack(item, stack | {source_id}) for item in binding.inputs
        )
        if binding.kind is BindingKind.JOIN:
            flattened = tuple(expression for operand in selected for expression in operand)
            return flattened[position]
        if binding.kind is BindingKind.VIEW:
            return selected[0][position]
        if binding.kind is BindingKind.PACK_BITS:
            width = binding.word_width
            group = selected[0][position * width : (position + 1) * width]
            return (
                "("
                + " | ".join(
                    f"(({expression} & 1ULL) << {width - 1 - index})"
                    for index, expression in enumerate(group)
                )
                + ")"
            )
        width = binding.word_width
        unit = position // width
        bit = position % width
        return f"(({selected[0][unit]} >> {width - 1 - bit}) & 1ULL)"

    def selection_expressions_with_stack(selection, stack):
        return tuple(
            source_expression(selection.source.owner_id, position, stack)
            for position in selection.positions
        )

    lines = [
        "#include <inttypes.h>",
        "#include <stdint.h>",
        "#include <stdio.h>",
        "#include <stdlib.h>",
        "#include <string.h>",
        "",
        "static int hex_value(char c) {",
        "  if (c >= '0' && c <= '9') return c - '0';",
        "  if (c >= 'a' && c <= 'f') return c - 'a' + 10;",
        "  if (c >= 'A' && c <= 'F') return c - 'A' + 10;",
        "  return -1;",
        "}",
        "",
        "static int read_hex_units(const char *text, uint64_t *out, size_t count, unsigned width) {",
        "  if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) text += 2;",
        "  size_t digits = strlen(text);",
        "  size_t limit = (count * width + 3U) / 4U;",
        "  if (digits == 0 || digits > limit) return 0;",
        "  for (size_t i = 0; i < digits; ++i) if (hex_value(text[i]) < 0) return 0;",
        "  for (size_t unit = 0; unit < count; ++unit) {",
        "    uint64_t value = 0;",
        "    for (unsigned bit = 0; bit < width; ++bit) {",
        "      size_t from_left = unit * width + bit;",
        "      size_t from_right = count * width - 1U - from_left;",
        "      size_t digit_from_right = from_right / 4U;",
        "      unsigned bit_in_digit = (unsigned)(from_right % 4U);",
        "      int nibble = digit_from_right < digits ? hex_value(text[digits - 1U - digit_from_right]) : 0;",
        "      value = (value << 1U) | (uint64_t)((nibble >> bit_in_digit) & 1);",
        "    }",
        "    out[unit] = value;",
        "  }",
        "  return 1;",
        "}",
        "",
        "static void print_hex_units(const uint64_t *value, size_t count, unsigned width) {",
        '  static const char digits[] = "0123456789abcdef";',
        "  size_t total = count * width;",
        "  size_t hex_count = (total + 3U) / 4U;",
        "  size_t padding = hex_count * 4U - total;",
        '  fputs("0x", stdout);',
        "  for (size_t digit = 0; digit < hex_count; ++digit) {",
        "    unsigned nibble = 0;",
        "    for (unsigned offset = 0; offset < 4; ++offset) {",
        "      size_t padded = digit * 4U + offset;",
        "      nibble <<= 1U;",
        "      if (padded >= padding) {",
        "        size_t position = padded - padding;",
        "        size_t unit = position / width;",
        "        unsigned bit = (unsigned)(position % width);",
        "        nibble |= (unsigned)((value[unit] >> (width - 1U - bit)) & 1ULL);",
        "      }",
        "    }",
        "    fputc(digits[nibble], stdout);",
        "  }",
        "  fputc('\\n', stdout);",
        "}",
        "",
        "int main(int argc, char **argv) {",
        f'  if (argc != {len(primitive.input_ports) + 1}) {{ fputs("invalid input count\\n", stderr); return 2; }}',
    ]
    for index, (name, port) in enumerate(primitive.input_ports.items()):
        width = port.value_type.domain.encoded_bit_size
        count = port.value_type.unit_count
        lines.extend(
            (
                f"  uint64_t {names[name]}[{count}];",
                f'  if (!read_hex_units(argv[{index + 1}], {names[name]}, {count}, {width})) {{ fputs("invalid hex input\\n", stderr); return 2; }}',
            )
        )
    for component in primitive.components:
        output = names[component.component_id]
        count = component.output_type.unit_count
        width = component.output_type.domain.encoded_bit_size
        operands = tuple(selection_expressions(item) for item in component.inputs)
        lines.append(f"  uint64_t {output}[{count}];")
        if isinstance(component, Constant):
            for index, value in enumerate(component.values):
                lines.append(f"  {output}[{index}] = UINT64_C({value});")
        elif isinstance(component, Identity):
            _assign(lines, output, operands[0])
        elif isinstance(component, Permutation):
            _assign(lines, output, tuple(operands[0][index] for index in component.mapping))
        elif isinstance(component, (Add, Multiply)):
            operator = " ^ " if isinstance(component, Add) else " & "
            _assign(
                lines, output, tuple("(" + operator.join(items) + ")" for items in zip(*operands))
            )
        elif isinstance(component, (Xor, BitwiseAnd, BitwiseOr)):
            operator = (
                " ^ "
                if isinstance(component, Xor)
                else (" & " if isinstance(component, BitwiseAnd) else " | ")
            )
            _assign(
                lines, output, tuple("(" + operator.join(items) + ")" for items in zip(*operands))
            )
        elif isinstance(component, BitwiseNot):
            mask = _mask(width)
            _assign(lines, output, tuple(f"((~{item}) & {mask})" for item in operands[0]))
        elif isinstance(component, ModularAdd):
            mask = _mask(width)
            expressions = []
            for items in zip(*operands):
                total = "(" + " + ".join(items) + ")"
                expressions.append(
                    f"({total} & {mask})"
                    if component.modulus is None
                    else f"({total} % UINT64_C({component.modulus}))"
                )
            _assign(lines, output, tuple(expressions))
        elif isinstance(component, ModularSubtract):
            mask = _mask(width)
            _assign(
                lines,
                output,
                tuple(
                    f"(({items[0]} - " + " - ".join(items[1:]) + f") & {mask})"
                    for items in zip(*operands)
                ),
            )
        elif isinstance(component, ModularMultiply):
            _assign(
                lines,
                output,
                tuple(
                    "((" + " * ".join(items) + f") % UINT64_C({component.modulus}))"
                    for items in zip(*operands)
                ),
            )
        elif isinstance(component, (Rotate, Shift)):
            for index, item in enumerate(operands[0]):
                if isinstance(component, Rotate):
                    amount = component.amount
                    expression = (
                        item
                        if amount == 0
                        else (
                            f"((({item} << {amount}) | ({item} >> {width - amount})) & {_mask(width)})"
                            if component.direction == "left"
                            else f"((({item} >> {amount}) | ({item} << {width - amount})) & {_mask(width)})"
                        )
                    )
                elif component.amount >= width:
                    expression = "UINT64_C(0)"
                elif component.direction == "left":
                    expression = f"(({item} << {component.amount}) & {_mask(width)})"
                else:
                    expression = f"({item} >> {component.amount})"
                lines.append(f"  {output}[{index}] = {expression};")
        elif isinstance(component, (VariableRotate, VariableShift)):
            amount = f"({operands[1][0]} % {width}U)"
            for index, item in enumerate(operands[0]):
                if isinstance(component, VariableRotate):
                    if component.direction == "left":
                        expression = f"(({item} << {amount}) | ({item} >> (({width}U - {amount}) % {width}U))) & {_mask(width)}"
                    else:
                        expression = f"(({item} >> {amount}) | ({item} << (({width}U - {amount}) % {width}U))) & {_mask(width)}"
                elif component.direction == "left":
                    expression = f"(({item} << {amount}) & {_mask(width)})"
                else:
                    expression = f"({item} >> {amount})"
                lines.append(f"  {output}[{index}] = {expression};")
        elif isinstance(component, LinearMap):
            for row_index, row in enumerate(component.matrix):
                terms = [
                    operands[0][column] for column, coefficient in enumerate(row) if coefficient
                ]
                expression = "UINT64_C(0)" if not terms else "(" + " ^ ".join(terms) + ")"
                lines.append(f"  {output}[{row_index}] = {expression};")
        elif isinstance(component, BitVectorSBox):
            table = ",".join(f"UINT64_C({item})" for item in component.table)
            table_name = f"table_{output}"
            lines.append(
                f"  static const uint64_t {table_name}[{len(component.table)}] = {{{table}}};"
            )
            packed = " | ".join(
                f"(({item} & 1ULL) << {len(operands[0]) - 1 - index})"
                for index, item in enumerate(operands[0])
            )
            lines.append(f"  uint64_t packed_{output} = {table_name}[{packed}];")
            for index in range(component.output_bit_size):
                lines.append(
                    f"  {output}[{index}] = (packed_{output} >> {component.output_bit_size - 1 - index}) & 1ULL;"
                )
        elif isinstance(component, SBox):
            table = ",".join(f"UINT64_C({item})" for item in component.table)
            table_name = f"table_{output}"
            lines.append(
                f"  static const uint64_t {table_name}[{len(component.table)}] = {{{table}}};"
            )
            _assign(lines, output, tuple(f"{table_name}[{item}]" for item in operands[0]))
        else:  # pragma: no cover - guarded by applicability
            raise AssertionError(type(component).__name__)
    output_expressions = selection_expressions(primitive.output)
    lines.append(f"  uint64_t result[{len(output_expressions)}];")
    _assign(lines, "result", output_expressions)
    output_width = primitive.output.value_type.domain.encoded_bit_size
    lines.extend(
        (
            f"  print_hex_units(result, {len(output_expressions)}, {output_width});",
            "  return 0;",
            "}",
            "",
        )
    )
    source = "\n".join(lines)
    artifact = SourceArtifact(
        SourceLanguage.C,
        source,
        "primitive_evaluator.c",
        sha256(source.encode("utf-8")).hexdigest(),
        primitive_digest(primitive),
        primitive.realization_identity,
        C_COMPILER,
    )
    return SourceCompilationResult(SourceStatus.READY, artifact=artifact)


def _assign(lines, output, expressions):
    for index, expression in enumerate(expressions):
        lines.append(f"  {output}[{index}] = {expression};")


def _mask(width):
    return "UINT64_MAX" if width == 64 else f"UINT64_C({(1 << width) - 1})"


def _applicability(primitive):
    if primitive.output is None:
        return SourceDiagnostic(
            "missing_output", "C generation requires a declared primitive output"
        )
    for source_id, port in primitive.input_ports.items():
        domain = port.value_type.domain
        if not isinstance(domain, (Bit, Word)) or domain.encoded_bit_size > 64:
            return SourceDiagnostic(
                "unsupported_domain",
                f"C generation does not support {type(domain).__name__} input {source_id!r}",
            )
    supported = (
        Constant,
        Identity,
        Permutation,
        Add,
        Multiply,
        LinearMap,
        BitwiseAnd,
        BitwiseNot,
        BitwiseOr,
        ModularAdd,
        ModularMultiply,
        ModularSubtract,
        Rotate,
        Shift,
        VariableRotate,
        VariableShift,
        Xor,
        BitVectorSBox,
        SBox,
    )
    for component in primitive.components:
        domain = component.output_type.domain
        if not isinstance(domain, (Bit, Word)) or domain.encoded_bit_size > 64:
            return SourceDiagnostic(
                "unsupported_domain",
                f"C generation does not support {type(domain).__name__}",
                component.component_id,
            )
        if not isinstance(component, supported):
            return SourceDiagnostic(
                "unsupported_component",
                f"C generation does not support {type(component).__name__}",
                component.component_id,
            )
        if isinstance(component, (Add, Multiply, LinearMap)) and not isinstance(domain, Bit):
            return SourceDiagnostic(
                "unsupported_component_domain",
                f"{type(component).__name__} is supported only over Bit",
                component.component_id,
            )
    return None


__all__ = ["C_COMPILER", "compile_c_source"]
