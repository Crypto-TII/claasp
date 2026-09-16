"""Build immutable typed graphs from reviewed catalogue graph specifications.

The specifications are generated migration artifacts, not live legacy objects:
constructing or evaluating a v5 primitive never imports CLAASP v4 or Sage.
"""

from __future__ import annotations

import gzip
import json
from importlib.resources import files

from claasp_next.components import (
    BitVectorSBox, BitwiseAnd, BitwiseNot, BitwiseOr, Concatenate, Constant, Identity,
    LinearMap, ModularAdd, ModularMultiply, ModularSubtract, PackBits,
    Permutation, Rotate, Shift, UnpackBits, VariableRotate, Xor,
)
from claasp_next.domains import Bit
from claasp_next.encoding import bits_from_int
from claasp_next.graph import Primitive, ValueType, as_selection


def _bit_type(width: int) -> ValueType:
    return ValueType(Bit(), (width,))


def _join(primitive: Primitive, values, component_id=None):
    values = tuple(as_selection(value) for value in values)
    if len(values) == 1:
        return values[0]
    return primitive.add_component(Concatenate(values, component_id=component_id))


def _word_operation(
    primitive: Primitive, source, description, width: int, component_id: str,
    operand_sizes: tuple[int, ...],
):
    operation = description[0]
    if operation == "ROTATE_BY_VARIABLE_AMOUNT":
        operands = (source[:width], source[width:])
        words = (primitive.add_component(PackBits(operands[0], width)),)
    else:
        operand_count = 1 if operation in {"NOT", "ROTATE", "SHIFT"} else source.value_type.unit_count // width
        operands = tuple(source[index * width:(index + 1) * width] for index in range(operand_count))
        words = tuple(primitive.add_component(PackBits(value, width)) for value in operands)
    if operation in {"XOR", "AND", "OR"} and len(operands) == 1:
        return primitive.add_component(Identity(operands[0], component_id=component_id))
    if operation == "XOR":
        output = primitive.add_component(Xor(words, component_id=component_id))
    elif operation == "AND":
        output = primitive.add_component(BitwiseAnd(words, component_id=component_id))
    elif operation == "OR":
        output = primitive.add_component(BitwiseOr(words, component_id=component_id))
    elif operation == "NOT":
        output = primitive.add_component(BitwiseNot(words[0], component_id=component_id))
    elif operation == "MODADD":
        output = primitive.add_component(ModularAdd(words, component_id=component_id))
    elif operation == "MODSUB":
        output = primitive.add_component(ModularSubtract(words, component_id=component_id))
    elif operation == "MODMUL":
        output = primitive.add_component(ModularMultiply(words, component_id=component_id))
    elif operation in {"ROTATE", "SHIFT"}:
        amount = int(description[1])
        direction = "right" if amount >= 0 else "left"
        component = Rotate if operation == "ROTATE" else Shift
        output = primitive.add_component(component(
            words[0], abs(amount), direction, component_id=component_id
        ))
    elif operation == "ROTATE_BY_VARIABLE_AMOUNT":
        amount_width = source.value_type.unit_count - width
        amount = primitive.add_component(PackBits(operands[1], amount_width))
        direction = "right" if int(description[1]) >= 0 else "left"
        output = primitive.add_component(VariableRotate(
            words[0], amount, direction, component_id=component_id
        ))
    else:
        raise ValueError(f"unsupported catalogue word operation {operation!r}")
    return primitive.add_component(UnpackBits(output))


def _feedback_register(primitive: Primitive, source, description, component_id: str):
    registers = description[0]
    bits_inside_word = int(description[1])
    if bits_inside_word != 1:
        raise ValueError("word-oriented catalogue feedback registers require an explicit migration")
    clocks = int(description[2]) if len(description) > 2 else 1
    state = source
    register_size = sum(register[0] for register in registers)
    external = source[register_size:] if source.value_type.unit_count > register_size else None
    for clock in range(clocks):
        outputs = []
        start = 0
        for length, feedback, *clock_terms in registers:
            terms = []
            for term_index, positions in enumerate(feedback):
                selected = tuple(state[position] for position in positions)
                if len(selected) == 1:
                    term = selected[0]
                else:
                    packed = tuple(primitive.add_component(PackBits(value, 1)) for value in selected)
                    term = primitive.add_component(UnpackBits(primitive.add_component(BitwiseAnd(
                        packed, component_id=f"{component_id}_and_{clock}_{start}_{term_index}"
                    ))))
                terms.append(term)
            if len(terms) == 1:
                feedback_bit = terms[0]
            else:
                packed = tuple(primitive.add_component(PackBits(value, 1)) for value in terms)
                feedback_bit = primitive.add_component(UnpackBits(primitive.add_component(Xor(
                    packed, component_id=f"{component_id}_feedback_{clock}_{start}"
                ))))
            # Catalogue FSRs in this slice are unconditionally clocked. Keep the
            # validation explicit so a later conditional register cannot silently
            # acquire the wrong semantics.
            if clock_terms and clock_terms[0]:
                raise ValueError("conditional catalogue feedback registers require an explicit migration")
            outputs.extend((state[position] for position in range(start + 1, start + length)))
            outputs.append(feedback_bit)
            start += length
        if external is not None:
            outputs.append(external)
        state = _join(primitive, outputs, component_id=f"{component_id}_{clock}")
    return state[:register_size]


def load_catalogue_spec(category: str, name: str, variant: str = "default") -> dict:
    resource = files(f"claasp_next.primitives.{category}.data").joinpath(f"{name}.{variant}.json.gz")
    with resource.open("rb") as stream:
        return json.loads(gzip.decompress(stream.read()))


def load_catalogue_variant(category: str, name: str, args, parameters: dict) -> dict:
    """Resolve an audited positional/keyword parameter set to its frozen graph."""

    package = files(f"claasp_next.primitives.{category}.data")
    with package.joinpath(f"{name}.index.json").open("r", encoding="utf-8") as stream:
        index = json.load(stream)
    names = index["parameter_names"]
    if len(args) > len(names):
        raise TypeError(f"{name} accepts at most {len(names)} positional parameters")
    supplied = dict(zip(names, args))
    duplicates = set(supplied).intersection(parameters)
    if duplicates:
        duplicate = sorted(duplicates)[0]
        raise TypeError(f"{name} received {duplicate!r} as both positional and keyword input")
    supplied.update(parameters)
    key = json.dumps(supplied, sort_keys=True, separators=(",", ":"))
    try:
        variant = index["variants"][key]
    except KeyError as error:
        raise ValueError(
            f"unsupported {name} parameter combination; available combinations are "
            f"{tuple(json.loads(item) for item in index['variants'])}"
        ) from error
    return load_catalogue_spec(category, name, variant)


class CatalogueGraphPrimitive(Primitive):
    """Typed graph reconstructed from a frozen, reviewed catalogue specification."""

    def __init__(self, specification: dict, *, family_name: str | None = None) -> None:
        inputs = {
            name: _bit_type(width)
            for name, width in zip(specification["inputs"], specification["input_sizes"])
        }
        super().__init__(family_name or specification["family_name"], inputs,
                         provenance=tuple(map(tuple, specification.get("provenance", ()))))
        ports = {name: self.input(name).select_all() for name in inputs}
        final_output = None
        legacy_final_output = "ci" + "pher_output"
        for round_spec in specification["rounds"]:
            self.add_round()
            for component in round_spec:
                selected_inputs = tuple(
                    ports[source_id][tuple(positions)]
                    for source_id, positions in zip(
                        component["input_ids"], component["input_positions"]
                    )
                    if source_id and positions
                )
                source = _join(self, selected_inputs) if selected_inputs else None
                kind = component["type"]
                component_id = component["id"]
                width = component["output_size"]
                description = component["description"]
                if kind in {"intermediate_output", legacy_final_output}:
                    if source is None:
                        raise ValueError(f"{kind} requires an input")
                    ports[component_id] = source
                    if kind == legacy_final_output:
                        final_output = source
                    continue
                if kind == "constant":
                    value = int(description[0], 0) & ((1 << width) - 1)
                    output = self.add_component(Constant(
                        _bit_type(width), bits_from_int(value, width), component_id=component_id
                    ))
                elif kind == "word_operation":
                    output = _word_operation(
                        self, source, description, width, component_id,
                        tuple(len(positions) for positions in component["input_positions"]),
                    )
                elif kind == "sbox":
                    output = self.add_component(BitVectorSBox(
                        source, tuple(description), component_id=component_id,
                        output_bit_size=width,
                    ))
                elif kind == "linear_layer":
                    output = self.add_component(LinearMap(
                        source, tuple(zip(*description)), component_id=component_id
                    ))
                elif kind == "mix_column":
                    output = self.add_component(LinearMap(
                        source, component["binary_matrix"], component_id=component_id
                    ))
                elif kind == "permutation":
                    destinations = tuple(description[0])
                    word_size = int(description[1])
                    expanded = tuple(
                        destination * word_size + offset
                        for destination in destinations for offset in range(word_size)
                    )
                    mapping = tuple(expanded.index(index) for index in range(len(expanded)))
                    output = self.add_component(Permutation(source, mapping, component_id=component_id))
                elif kind == "fsr":
                    output = _feedback_register(self, source, description, component_id)
                else:
                    raise ValueError(f"unsupported catalogue component type {kind!r}")
                ports[component_id] = as_selection(output)
        if final_output is None:
            raise ValueError("catalogue specification has no primitive output")
        self.set_output(final_output)
