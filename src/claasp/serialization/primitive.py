"""Canonical, versioned serialization for immutable primitive graphs."""

from __future__ import annotations

import json

from claasp.components import (
    Add,
    BinaryAffineMap,
    BitVectorSBox,
    BitwiseAnd,
    BitwiseNot,
    BitwiseOr,
    Constant,
    FeedbackRegister,
    FeedbackRegisterSpec,
    FeedbackTerm,
    IDEAMultiply,
    Identity,
    LinearMap,
    ModularAdd,
    ModularMultiply,
    ModularSubtract,
    Multiply,
    Permutation,
    Power,
    Rotate,
    SBox,
    Shift,
    VariableRotate,
    VariableShift,
    Xor,
)
from claasp.domains import BinaryExtensionField, Bit, PrimeField, Word
from claasp.graph import (
    CompositeDefinition,
    CompositeInstance,
    InputVisibility,
    Port,
    Primitive,
    PrimitiveInput,
    PrimitiveKind,
    RealizationDescriptor,
    RealizationMaturity,
    Selection,
    ValueType,
)
from claasp.graph.binding import BindingKind
from claasp.provenance import TransformationRecord
from claasp.serialization.errors import SerializationError, SerializationFailure

SCHEMA_ID = "org.claasp.primitive"
SCHEMA_VERSION = 1


def serialize_primitive(primitive: Primitive) -> bytes:
    """Return canonical UTF-8 JSON for ``primitive``.

    Serialization performs no file writes and embeds no timestamps, paths, or
    executable Python objects.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> data = serialize_primitive(Speck(number_of_rounds=1))
        >>> data == serialize_primitive(Speck(number_of_rounds=1))
        True
        >>> data.endswith(b"\\n")
        True
    """

    if not isinstance(primitive, Primitive):
        raise TypeError("serialize_primitive requires a Primitive")
    envelope = {
        "artifact": "primitive",
        "payload": _encode_primitive(primitive),
        "schema": SCHEMA_ID,
        "version": SCHEMA_VERSION,
    }
    return (
        json.dumps(
            envelope,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def deserialize_primitive(data: bytes | str) -> Primitive:
    """Strictly decode a supported canonical primitive envelope.

    Unknown versions, fields, domains, components, duplicate keys, invalid
    references, and graph invariant failures are rejected with
    :class:`SerializationError`.

    EXAMPLES::

        >>> from claasp.primitives import Present
        >>> original = Present(number_of_rounds=1)
        >>> restored = deserialize_primitive(serialize_primitive(original))
        >>> restored.evaluate(0, 0) == original.evaluate(0, 0)
        True
    """

    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise SerializationError(
                SerializationFailure.INVALID_JSON,
                "input is not valid UTF-8",
            ) from error
    elif isinstance(data, str):
        text = data
    else:
        raise TypeError("serialized primitive must be bytes or str")
    try:
        envelope = json.loads(text, object_pairs_hook=_unique_object)
    except SerializationError:
        raise
    except (json.JSONDecodeError, UnicodeError) as error:
        raise SerializationError(SerializationFailure.INVALID_JSON, str(error)) from error
    _object(envelope, {"artifact", "payload", "schema", "version"}, path="$")
    if envelope["schema"] != SCHEMA_ID:
        raise SerializationError(
            SerializationFailure.UNKNOWN_SCHEMA,
            f"unsupported schema {envelope['schema']!r}",
            path="$.schema",
        )
    if envelope["version"] != SCHEMA_VERSION:
        raise SerializationError(
            SerializationFailure.UNKNOWN_VERSION,
            f"unsupported version {envelope['version']!r}",
            path="$.version",
        )
    if envelope["artifact"] != "primitive":
        raise SerializationError(
            SerializationFailure.UNKNOWN_ARTIFACT,
            f"expected primitive, got {envelope['artifact']!r}",
            path="$.artifact",
        )
    return _decode_primitive(envelope["payload"], "$.payload")


def primitive_digest(primitive: Primitive) -> str:
    """Return the SHA-256 identity of canonical primitive bytes.

    EXAMPLES::

        >>> from claasp import primitive_digest
        >>> from claasp.primitives import Speck
        >>> digest = primitive_digest(Speck(number_of_rounds=1))
        >>> (len(digest), digest == primitive_digest(Speck(number_of_rounds=1)))
        (64, True)
    """

    from hashlib import sha256

    return sha256(serialize_primitive(primitive)).hexdigest()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SerializationError(
                SerializationFailure.DUPLICATE_FIELD,
                f"duplicate object field {key!r}",
            )
        result[key] = value
    return result


def _object(value, required, optional=(), *, path):
    if not isinstance(value, dict):
        raise SerializationError(SerializationFailure.MALFORMED_VALUE, "expected object", path=path)
    allowed = set(required) | set(optional)
    missing = set(required) - set(value)
    unknown = set(value) - allowed
    if missing:
        raise SerializationError(
            SerializationFailure.MALFORMED_VALUE,
            f"missing fields {sorted(missing)}",
            path=path,
        )
    if unknown:
        raise SerializationError(
            SerializationFailure.MALFORMED_VALUE,
            f"unknown fields {sorted(unknown)}",
            path=path,
        )
    return value


def _integer(value, *, path, minimum=None):
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or (minimum is not None and value < minimum)
    ):
        raise SerializationError(
            SerializationFailure.MALFORMED_VALUE, "expected canonical integer", path=path
        )
    return value


def _string(value, *, path):
    if not isinstance(value, str) or not value:
        raise SerializationError(
            SerializationFailure.MALFORMED_VALUE, "expected non-empty string", path=path
        )
    return value


def _array(value, *, path):
    if not isinstance(value, list):
        raise SerializationError(SerializationFailure.MALFORMED_VALUE, "expected array", path=path)
    return value


def _encode_domain(domain):
    if isinstance(domain, Bit):
        return {"kind": "bit"}
    if isinstance(domain, Word):
        return {"kind": "word", "width": domain.width}
    if isinstance(domain, PrimeField):
        return {"kind": "prime_field", "modulus": domain.modulus}
    if isinstance(domain, BinaryExtensionField):
        return {
            "basis": domain.basis,
            "degree": domain.degree,
            "kind": "binary_extension_field",
            "modulus": domain.modulus,
        }
    raise SerializationError(
        SerializationFailure.UNKNOWN_DOMAIN,
        f"unsupported domain {type(domain).__name__}",
    )


def _decode_domain(value, path):
    if not isinstance(value, dict) or not isinstance(value.get("kind"), str):
        raise SerializationError(SerializationFailure.MALFORMED_VALUE, "invalid domain", path=path)
    kind = value["kind"]
    try:
        if kind == "bit":
            _object(value, {"kind"}, path=path)
            return Bit()
        if kind == "word":
            _object(value, {"kind", "width"}, path=path)
            return Word(_integer(value["width"], path=f"{path}.width", minimum=1))
        if kind == "prime_field":
            _object(value, {"kind", "modulus"}, path=path)
            return PrimeField(_integer(value["modulus"], path=f"{path}.modulus", minimum=2))
        if kind == "binary_extension_field":
            _object(value, {"basis", "degree", "kind", "modulus"}, path=path)
            basis = _string(value["basis"], path=f"{path}.basis")
            return BinaryExtensionField(
                _integer(value["degree"], path=f"{path}.degree", minimum=1),
                _integer(value["modulus"], path=f"{path}.modulus", minimum=1),
                basis,
            )
    except (TypeError, ValueError) as error:
        raise SerializationError(
            SerializationFailure.MALFORMED_VALUE, str(error), path=path
        ) from error
    raise SerializationError(
        SerializationFailure.UNKNOWN_DOMAIN, f"unknown domain kind {kind!r}", path=path
    )


def _encode_type(value_type):
    return {"domain": _encode_domain(value_type.domain), "shape": list(value_type.shape)}


def _decode_type(value, path):
    _object(value, {"domain", "shape"}, path=path)
    shape = tuple(
        _integer(item, path=f"{path}.shape[{index}]", minimum=1)
        for index, item in enumerate(_array(value["shape"], path=f"{path}.shape"))
    )
    try:
        return ValueType(_decode_domain(value["domain"], f"{path}.domain"), shape)
    except (TypeError, ValueError) as error:
        raise SerializationError(
            SerializationFailure.MALFORMED_VALUE, str(error), path=path
        ) from error


def _encode_selection(selection):
    return {"positions": list(selection.positions), "source": selection.source.owner_id}


def _decode_selection(value, sources, path):
    _object(value, {"positions", "source"}, path=path)
    source_id = _string(value["source"], path=f"{path}.source")
    try:
        port = sources[source_id]
    except KeyError as error:
        raise SerializationError(
            SerializationFailure.INVALID_REFERENCE,
            f"unknown graph source {source_id!r}",
            path=f"{path}.source",
        ) from error
    positions = tuple(
        _integer(item, path=f"{path}.positions[{index}]", minimum=0)
        for index, item in enumerate(_array(value["positions"], path=f"{path}.positions"))
    )
    try:
        return Selection(port, positions)
    except (TypeError, ValueError) as error:
        raise SerializationError(
            SerializationFailure.INVALID_REFERENCE, str(error), path=path
        ) from error


def _encode_term(term):
    return {"coefficient": term.coefficient, "positions": list(term.positions)}


def _decode_term(value, path):
    _object(value, {"coefficient", "positions"}, path=path)
    return FeedbackTerm(
        tuple(
            _integer(item, path=f"{path}.positions[{index}]", minimum=0)
            for index, item in enumerate(_array(value["positions"], path=f"{path}.positions"))
        ),
        _integer(value["coefficient"], path=f"{path}.coefficient", minimum=0),
    )


def _encode_register(register):
    return {
        "clock": None
        if register.clock is None
        else [_encode_term(item) for item in register.clock],
        "feedback": [_encode_term(item) for item in register.feedback],
        "length": register.length,
    }


def _decode_register(value, path):
    _object(value, {"clock", "feedback", "length"}, path=path)
    clock = value["clock"]
    return FeedbackRegisterSpec(
        _integer(value["length"], path=f"{path}.length", minimum=1),
        tuple(
            _decode_term(item, f"{path}.feedback[{index}]")
            for index, item in enumerate(_array(value["feedback"], path=f"{path}.feedback"))
        ),
        None
        if clock is None
        else tuple(
            _decode_term(item, f"{path}.clock[{index}]")
            for index, item in enumerate(_array(clock, path=f"{path}.clock"))
        ),
    )


def _encode_component(component):
    parameters = {}
    for name in (
        "values",
        "mapping",
        "table",
        "output_bit_size",
        "modulus",
        "inverse_inputs",
        "amount",
        "direction",
        "matrix",
        "offset",
        "exponent",
        "clocks",
    ):
        if hasattr(component, name):
            value = getattr(component, name)
            parameters[name] = _json_value(value)
    if isinstance(component, FeedbackRegister):
        parameters["registers"] = [_encode_register(item) for item in component.registers]
    return {
        "id": component.component_id,
        "inputs": [_encode_selection(item) for item in component.inputs],
        "kind": type(component).__name__,
        "output_type": _encode_type(component.output_type),
        "parameters": parameters,
    }


def _json_value(value):
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if value is None or (isinstance(value, (str, int)) and not isinstance(value, bool)):
        return value
    raise SerializationError(
        SerializationFailure.MALFORMED_VALUE, f"unsupported parameter {value!r}"
    )


def _decode_component(value, sources, path):
    _object(value, {"id", "inputs", "kind", "output_type", "parameters"}, path=path)
    component_id = _string(value["id"], path=f"{path}.id")
    kind = _string(value["kind"], path=f"{path}.kind")
    parameters = value["parameters"]
    if not isinstance(parameters, dict):
        raise SerializationError(
            SerializationFailure.MALFORMED_VALUE,
            "parameters must be an object",
            path=f"{path}.parameters",
        )
    inputs = tuple(
        _decode_selection(item, sources, f"{path}.inputs[{index}]")
        for index, item in enumerate(_array(value["inputs"], path=f"{path}.inputs"))
    )
    constructors = {
        "Constant": lambda: Constant(
            _decode_type(value["output_type"], f"{path}.output_type"),
            parameters["values"],
            component_id,
        ),
        "Identity": lambda: Identity(inputs[0], component_id),
        "Permutation": lambda: Permutation(inputs[0], parameters["mapping"], component_id),
        "Add": lambda: Add(inputs, component_id),
        "Multiply": lambda: Multiply(inputs, component_id),
        "Power": lambda: Power(inputs[0], parameters["exponent"], component_id),
        "LinearMap": lambda: LinearMap(inputs[0], parameters["matrix"], component_id),
        "BinaryAffineMap": lambda: BinaryAffineMap(
            inputs[0], parameters["matrix"], parameters["offset"], component_id
        ),
        "BitwiseAnd": lambda: BitwiseAnd(inputs, component_id),
        "BitwiseNot": lambda: BitwiseNot(inputs[0], component_id),
        "BitwiseOr": lambda: BitwiseOr(inputs, component_id),
        "IDEAMultiply": lambda: IDEAMultiply(
            inputs, component_id, inverse_inputs=parameters["inverse_inputs"]
        ),
        "ModularAdd": lambda: ModularAdd(inputs, component_id, modulus=parameters["modulus"]),
        "ModularMultiply": lambda: ModularMultiply(inputs, parameters["modulus"], component_id),
        "ModularSubtract": lambda: ModularSubtract(inputs, component_id),
        "Rotate": lambda: Rotate(
            inputs[0], parameters["amount"], parameters["direction"], component_id
        ),
        "Shift": lambda: Shift(
            inputs[0], parameters["amount"], parameters["direction"], component_id
        ),
        "VariableRotate": lambda: VariableRotate(
            inputs[0], inputs[1], parameters["direction"], component_id
        ),
        "VariableShift": lambda: VariableShift(
            inputs[0], inputs[1], parameters["direction"], component_id
        ),
        "Xor": lambda: Xor(inputs, component_id),
        "SBox": lambda: SBox(inputs[0], parameters["table"], component_id),
        "BitVectorSBox": lambda: BitVectorSBox(
            inputs[0], parameters["table"], component_id, parameters["output_bit_size"]
        ),
        "FeedbackRegister": lambda: FeedbackRegister(
            inputs[0],
            tuple(
                _decode_register(item, f"{path}.parameters.registers[{index}]")
                for index, item in enumerate(parameters["registers"])
            ),
            parameters["clocks"],
            component_id,
            direction=parameters["direction"],
        ),
    }
    try:
        constructor = constructors[kind]
    except KeyError as error:
        raise SerializationError(
            SerializationFailure.UNKNOWN_COMPONENT,
            f"unknown component kind {kind!r}",
            path=f"{path}.kind",
        ) from error
    try:
        component = constructor()
    except KeyError as error:
        raise SerializationError(
            SerializationFailure.MALFORMED_VALUE,
            f"missing component parameter {error.args[0]!r}",
            path=f"{path}.parameters",
        ) from error
    except (IndexError, TypeError, ValueError) as error:
        raise SerializationError(
            SerializationFailure.MALFORMED_VALUE, str(error), path=path
        ) from error
    declared = _decode_type(value["output_type"], f"{path}.output_type")
    if component.output_type != declared:
        raise SerializationError(
            SerializationFailure.TYPE_MISMATCH,
            "component output type is inconsistent with its semantics",
            path=f"{path}.output_type",
        )
    expected_parameters = set(_encode_component(component)["parameters"])
    if set(parameters) != expected_parameters:
        raise SerializationError(
            SerializationFailure.MALFORMED_VALUE,
            "component parameter fields do not match its kind",
            path=f"{path}.parameters",
        )
    return component


def _encode_realization(value):
    return {
        "capabilities": sorted(value.capabilities),
        "description": value.description,
        "maturity": value.maturity.value,
        "name": value.name,
        "priority": value.priority,
        "provenance": list(value.provenance),
        "structure": sorted(value.structure),
    }


def _decode_realization(value, path):
    _object(
        value,
        {"capabilities", "description", "maturity", "name", "priority", "provenance", "structure"},
        path=path,
    )
    try:
        return RealizationDescriptor(
            _string(value["name"], path=f"{path}.name"),
            frozenset(
                _string(item, path=f"{path}.capabilities[{index}]")
                for index, item in enumerate(
                    _array(value["capabilities"], path=f"{path}.capabilities")
                )
            ),
            frozenset(
                _string(item, path=f"{path}.structure[{index}]")
                for index, item in enumerate(_array(value["structure"], path=f"{path}.structure"))
            ),
            _string(value["description"], path=f"{path}.description"),
            RealizationMaturity(value["maturity"]),
            tuple(
                _string(item, path=f"{path}.provenance[{index}]")
                for index, item in enumerate(_array(value["provenance"], path=f"{path}.provenance"))
            ),
            _integer(value["priority"], path=f"{path}.priority"),
        )
    except (TypeError, ValueError) as error:
        raise SerializationError(
            SerializationFailure.MALFORMED_VALUE, str(error), path=path
        ) from error


def _encode_definition(definition):
    return {
        "bindings": [_encode_binding(item) for item in definition.bindings],
        "inputs": [
            {"name": name, "type": _encode_type(value_type)}
            for name, value_type in definition.input_types
        ],
        "name": definition.name,
        "outputs": [
            {"name": name, "selection": _encode_selection(selection)}
            for name, selection in definition.outputs
        ],
        "provenance": [list(item) for item in definition.provenance],
        "rounds": [
            [_encode_component(item) for item in components] for components in definition.rounds
        ],
    }


def _encode_scope(scope, primitive):
    round_number = next(group.number for group in primitive.graph.rounds if scope in group.scopes)
    return {
        "component_ids": list(scope.component_ids),
        "definition": _encode_definition(scope.definition),
        "inputs": [
            {"name": name, "selection": _encode_selection(selection)}
            for name, selection in scope.input_bindings
        ],
        "outputs": [
            {"name": name, "selection": _encode_selection(selection)}
            for name, selection in scope.output_bindings
        ],
        "path": scope.path,
        "round": round_number,
    }


def _encode_binding(binding):
    return {
        "id": binding.binding_id,
        "inputs": [_encode_selection(item) for item in binding.inputs],
        "kind": binding.kind.value,
        "output_type": _encode_type(binding.output_type),
        "word_width": binding.word_width,
    }


def _encode_primitive(primitive):
    return {
        "bindings": [_encode_binding(item) for item in primitive.graph.bindings],
        "family_name": primitive.family_name,
        "inputs": [
            {
                "name": name,
                "role": descriptor.role,
                "type": _encode_type(descriptor.value_type),
                "visibility": descriptor.visibility.value,
            }
            for name, descriptor in primitive.graph.input_descriptors.items()
        ],
        "kind": primitive.kind.value,
        "output": None
        if primitive.graph.output is None
        else _encode_selection(primitive.graph.output),
        "provenance": [list(item) for item in primitive.provenance],
        "realization": _encode_realization(primitive.realization),
        "rounds": [
            {
                "components": [_encode_component(item) for item in group.components],
                "number": group.number,
            }
            for group in primitive.graph.rounds
        ],
        "scopes": [_encode_scope(item, primitive) for item in primitive.graph.scopes],
        "transformations": [
            {
                "operation": item.operation,
                "parameters": [list(pair) for pair in item.parameters],
                "source_identity": item.source_identity,
            }
            for item in primitive.transformation_provenance
        ],
    }


def _pairs(value, path):
    result = []
    for index, pair in enumerate(_array(value, path=path)):
        if (
            not isinstance(pair, list)
            or len(pair) != 2
            or not all(isinstance(item, str) for item in pair)
        ):
            raise SerializationError(
                SerializationFailure.MALFORMED_VALUE,
                "expected string pair",
                path=f"{path}[{index}]",
            )
        result.append(tuple(pair))
    return tuple(result)


def _collect_sources(inputs, bindings, rounds, path):
    sources = {}
    for name, value_type in inputs:
        if name in sources:
            raise SerializationError(
                SerializationFailure.DUPLICATE_IDENTITY, f"duplicate source {name!r}", path=path
            )
        sources[name] = Port(name, value_type)
    for record in list(bindings) + [component for group in rounds for component in group]:
        source_id = record["id"]
        if source_id in sources:
            raise SerializationError(
                SerializationFailure.DUPLICATE_IDENTITY,
                f"duplicate source {source_id!r}",
                path=path,
            )
        sources[source_id] = Port(
            source_id, _decode_type(record["output_type"], f"{path}.{source_id}.output_type")
        )
    return sources


def _decode_binding(value, sources, path):
    _object(value, {"id", "inputs", "kind", "output_type", "word_width"}, path=path)
    try:
        kind = BindingKind(value["kind"])
    except (TypeError, ValueError) as error:
        raise SerializationError(
            SerializationFailure.MALFORMED_VALUE, "unknown binding kind", path=f"{path}.kind"
        ) from error
    word_width = value["word_width"]
    if word_width is not None:
        word_width = _integer(word_width, path=f"{path}.word_width", minimum=1)
    return (
        _string(value["id"], path=f"{path}.id"),
        kind,
        tuple(
            _decode_selection(item, sources, f"{path}.inputs[{index}]")
            for index, item in enumerate(_array(value["inputs"], path=f"{path}.inputs"))
        ),
        _decode_type(value["output_type"], f"{path}.output_type"),
        word_width,
    )


def _validate_binding(identifier, kind, inputs, output_type, word_width, path):
    from claasp.domains import BinaryExtensionField

    try:
        if not inputs:
            raise ValueError("binding requires at least one input")
        if kind is BindingKind.JOIN:
            if word_width is not None:
                raise ValueError("join binding must not declare word_width")
            if any(item.value_type.domain != inputs[0].value_type.domain for item in inputs):
                raise ValueError("join binding inputs must share one domain")
            expected = ValueType(
                inputs[0].value_type.domain,
                (sum(item.value_type.unit_count for item in inputs),),
            )
        elif kind is BindingKind.VIEW:
            if len(inputs) != 1 or word_width is not None:
                raise ValueError("view binding requires one input and no word_width")
            expected = inputs[0].value_type
        elif kind is BindingKind.PACK_BITS:
            if (
                len(inputs) != 1
                or word_width is None
                or not isinstance(inputs[0].value_type.domain, Bit)
            ):
                raise ValueError("pack_bits binding requires one Bit input and word_width")
            if inputs[0].value_type.unit_count % word_width:
                raise ValueError("pack_bits input width must be divisible by word_width")
            if isinstance(output_type.domain, Word):
                if output_type.domain.width != word_width:
                    raise ValueError("packed Word width is inconsistent")
            elif isinstance(output_type.domain, BinaryExtensionField):
                if output_type.domain.degree != word_width:
                    raise ValueError("packed field degree is inconsistent")
            else:
                raise ValueError("pack_bits output must use Word or binary-extension-field units")
            expected = ValueType(
                output_type.domain, (inputs[0].value_type.unit_count // word_width,)
            )
        else:
            if len(inputs) != 1 or word_width is None:
                raise ValueError("unpack_bits binding requires one input and word_width")
            domain = inputs[0].value_type.domain
            actual_width = (
                domain.width
                if isinstance(domain, Word)
                else (domain.degree if isinstance(domain, BinaryExtensionField) else None)
            )
            if actual_width != word_width:
                raise ValueError("unpack_bits word_width is inconsistent with its input")
            expected = ValueType(Bit(), (inputs[0].value_type.unit_count * word_width,))
        if expected != output_type:
            raise ValueError("binding output type is inconsistent with its operation")
    except (TypeError, ValueError) as error:
        raise SerializationError(
            SerializationFailure.INCONSISTENT_WIDTH, str(error), path=path
        ) from error


def _validate_dependency_order(primitive, path):
    bindings = {item.binding_id: item for item in primitive.graph.bindings}
    available = set(primitive.graph.input_ports)

    def resolvable(source_id, stack):
        if source_id in available:
            return True
        binding = bindings.get(source_id)
        if binding is None:
            return False
        if source_id in stack:
            raise SerializationError(
                SerializationFailure.INVALID_REFERENCE,
                f"cyclic structural binding at {source_id!r}",
                path=path,
            )
        return all(
            resolvable(selected.source.owner_id, stack | {source_id}) for selected in binding.inputs
        )

    for component in primitive.graph.components:
        if not all(resolvable(selected.source.owner_id, set()) for selected in component.inputs):
            raise SerializationError(
                SerializationFailure.INVALID_REFERENCE,
                f"component {component.component_id!r} has a forward or dangling dependency",
                path=path,
            )
        available.add(component.component_id)
    if primitive.graph.output is not None and not resolvable(
        primitive.graph.output.source.owner_id, set()
    ):
        raise SerializationError(
            SerializationFailure.INVALID_REFERENCE,
            "primitive output is not reachable",
            path=path,
        )
    for binding in primitive.graph.bindings:
        if not resolvable(binding.binding_id, set()):
            raise SerializationError(
                SerializationFailure.INVALID_REFERENCE,
                f"binding {binding.binding_id!r} has a dangling dependency",
                path=path,
            )


def _decode_definition(value, path):
    _object(value, {"bindings", "inputs", "name", "outputs", "provenance", "rounds"}, path=path)
    input_records = _array(value["inputs"], path=f"{path}.inputs")
    inputs = []
    for index, item in enumerate(input_records):
        item_path = f"{path}.inputs[{index}]"
        _object(item, {"name", "type"}, path=item_path)
        inputs.append(
            (
                _string(item["name"], path=f"{item_path}.name"),
                _decode_type(item["type"], f"{item_path}.type"),
            )
        )
    bindings = _array(value["bindings"], path=f"{path}.bindings")
    rounds = _array(value["rounds"], path=f"{path}.rounds")
    for index, group in enumerate(rounds):
        _array(group, path=f"{path}.rounds[{index}]")
    sources = _collect_sources(inputs, bindings, rounds, path)
    decoded_bindings = tuple(
        _decode_binding(item, sources, f"{path}.bindings[{index}]")
        for index, item in enumerate(bindings)
    )
    decoded_rounds = tuple(
        tuple(
            _decode_component(item, sources, f"{path}.rounds[{ri}][{ci}]")
            for ci, item in enumerate(group)
        )
        for ri, group in enumerate(rounds)
    )
    outputs = []
    for index, item in enumerate(_array(value["outputs"], path=f"{path}.outputs")):
        item_path = f"{path}.outputs[{index}]"
        _object(item, {"name", "selection"}, path=item_path)
        outputs.append(
            (
                _string(item["name"], path=f"{item_path}.name"),
                _decode_selection(item["selection"], sources, f"{item_path}.selection"),
            )
        )
    from claasp.graph.binding import ValueBinding

    return CompositeDefinition(
        _string(value["name"], path=f"{path}.name"),
        tuple(inputs),
        decoded_rounds,
        tuple(
            ValueBinding(identifier, kind, selected, output_type, width)
            for identifier, kind, selected, output_type, width in decoded_bindings
        ),
        tuple(outputs),
        _pairs(value["provenance"], f"{path}.provenance"),
    )


def _decode_primitive(value, path):
    _object(
        value,
        {
            "bindings",
            "family_name",
            "inputs",
            "kind",
            "output",
            "provenance",
            "realization",
            "rounds",
            "scopes",
            "transformations",
        },
        path=path,
    )
    input_descriptors = []
    for index, item in enumerate(_array(value["inputs"], path=f"{path}.inputs")):
        item_path = f"{path}.inputs[{index}]"
        _object(item, {"name", "role", "type", "visibility"}, path=item_path)
        name = _string(item["name"], path=f"{item_path}.name")
        try:
            descriptor = PrimitiveInput(
                _decode_type(item["type"], f"{item_path}.type"),
                _string(item["role"], path=f"{item_path}.role"),
                InputVisibility(item["visibility"]),
            )
        except (TypeError, ValueError) as error:
            raise SerializationError(
                SerializationFailure.MALFORMED_VALUE, str(error), path=item_path
            ) from error
        input_descriptors.append((name, descriptor))
    if len(dict(input_descriptors)) != len(input_descriptors):
        raise SerializationError(
            SerializationFailure.DUPLICATE_IDENTITY,
            "duplicate primitive input",
            path=f"{path}.inputs",
        )
    round_records = _array(value["rounds"], path=f"{path}.rounds")
    component_groups = []
    for index, group in enumerate(round_records):
        group_path = f"{path}.rounds[{index}]"
        _object(group, {"components", "number"}, path=group_path)
        if _integer(group["number"], path=f"{group_path}.number", minimum=0) != index:
            raise SerializationError(
                SerializationFailure.MALFORMED_VALUE,
                "round numbers must be consecutive from zero",
                path=f"{group_path}.number",
            )
        component_groups.append(_array(group["components"], path=f"{group_path}.components"))
    binding_records = _array(value["bindings"], path=f"{path}.bindings")
    source_types = _collect_sources(
        tuple((name, item.value_type) for name, item in input_descriptors),
        binding_records,
        component_groups,
        path,
    )
    try:
        primitive = Primitive(
            _string(value["family_name"], path=f"{path}.family_name"),
            dict(input_descriptors),
            kind=PrimitiveKind(value["kind"]),
            provenance=_pairs(value["provenance"], f"{path}.provenance"),
        )
    except (TypeError, ValueError) as error:
        raise SerializationError(
            SerializationFailure.MALFORMED_VALUE, str(error), path=path
        ) from error
    primitive.realization = _decode_realization(value["realization"], f"{path}.realization")
    decoded_bindings = tuple(
        _decode_binding(item, source_types, f"{path}.bindings[{index}]")
        for index, item in enumerate(binding_records)
    )
    for index, (identifier, binding_kind, selected, output_type, word_width) in enumerate(
        decoded_bindings
    ):
        _validate_binding(
            identifier,
            binding_kind,
            selected,
            output_type,
            word_width,
            f"{path}.bindings[{index}]",
        )
    try:
        for identifier, kind, inputs, output_type, word_width in decoded_bindings:
            primitive._add_binding(
                kind,
                inputs,
                output_type,
                word_width=word_width,
                binding_id=identifier,
                _validate_inputs=False,
            )
        for round_index, group in enumerate(component_groups):
            primitive._builder.add_round()
            for component_index, item in enumerate(group):
                primitive._builder.add_component(
                    _decode_component(
                        item,
                        source_types,
                        f"{path}.rounds[{round_index}].components[{component_index}]",
                    )
                )
    except SerializationError:
        raise
    except (TypeError, ValueError) as error:
        raise SerializationError(
            SerializationFailure.INVALID_REFERENCE, str(error), path=path
        ) from error
    for binding in primitive.graph.bindings:
        for selected in binding.inputs:
            actual = primitive.graph.port(selected.source.owner_id)
            if actual != selected.source:
                raise SerializationError(
                    SerializationFailure.TYPE_MISMATCH,
                    "binding source type does not match graph source",
                    path=f"{path}.bindings",
                )
    if value["output"] is not None:
        try:
            primitive._builder.set_output(
                _decode_selection(value["output"], source_types, f"{path}.output")
            )
        except (TypeError, ValueError) as error:
            raise SerializationError(
                SerializationFailure.INVALID_REFERENCE, str(error), path=f"{path}.output"
            ) from error
    transformations = []
    for index, item in enumerate(_array(value["transformations"], path=f"{path}.transformations")):
        item_path = f"{path}.transformations[{index}]"
        _object(item, {"operation", "parameters", "source_identity"}, path=item_path)
        source_identity = item["source_identity"]
        if source_identity is not None:
            source_identity = _string(source_identity, path=f"{item_path}.source_identity")
        try:
            transformations.append(
                TransformationRecord(
                    _string(item["operation"], path=f"{item_path}.operation"),
                    _pairs(item["parameters"], f"{item_path}.parameters"),
                    source_identity,
                )
            )
        except (TypeError, ValueError) as error:
            raise SerializationError(
                SerializationFailure.MALFORMED_VALUE, str(error), path=item_path
            ) from error
    primitive._transformation_provenance = tuple(transformations)
    for index, item in enumerate(_array(value["scopes"], path=f"{path}.scopes")):
        scope_path = f"{path}.scopes[{index}]"
        _object(
            item,
            {"component_ids", "definition", "inputs", "outputs", "path", "round"},
            path=scope_path,
        )
        instance_path = _string(item["path"], path=f"{scope_path}.path")
        if instance_path in primitive._scopes:
            raise SerializationError(
                SerializationFailure.DUPLICATE_IDENTITY,
                f"duplicate scope {instance_path!r}",
                path=scope_path,
            )
        round_number = _integer(item["round"], path=f"{scope_path}.round", minimum=0)
        if round_number >= len(primitive.graph.rounds):
            raise SerializationError(
                SerializationFailure.INVALID_REFERENCE,
                "scope round is outside the graph",
                path=f"{scope_path}.round",
            )
        definition = _decode_definition(item["definition"], f"{scope_path}.definition")

        def named_selections(records, label, scope_path=scope_path):
            values = []
            for item_index, record in enumerate(_array(records, path=f"{scope_path}.{label}")):
                record_path = f"{scope_path}.{label}[{item_index}]"
                _object(record, {"name", "selection"}, path=record_path)
                values.append(
                    (
                        _string(record["name"], path=f"{record_path}.name"),
                        _decode_selection(
                            record["selection"], source_types, f"{record_path}.selection"
                        ),
                    )
                )
            return tuple(values)

        component_ids = tuple(
            _string(component_id, path=f"{scope_path}.component_ids[{item_index}]")
            for item_index, component_id in enumerate(
                _array(item["component_ids"], path=f"{scope_path}.component_ids")
            )
        )
        if any(component_id not in primitive._components for component_id in component_ids):
            raise SerializationError(
                SerializationFailure.INVALID_REFERENCE,
                "scope references an unknown component",
                path=f"{scope_path}.component_ids",
            )
        instance = CompositeInstance(
            instance_path,
            definition,
            named_selections(item["inputs"], "inputs"),
            named_selections(item["outputs"], "outputs"),
            component_ids,
            primitive,
        )
        primitive._scopes[instance_path] = instance
        primitive._rounds[round_number]._append_scope(instance)
    _validate_dependency_order(primitive, path)
    return primitive


__all__ = [
    "SCHEMA_ID",
    "SCHEMA_VERSION",
    "deserialize_primitive",
    "primitive_digest",
    "serialize_primitive",
]
