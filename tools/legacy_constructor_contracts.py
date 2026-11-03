"""Reviewable constructor mappings; names alone do not prove numerical parity."""

import argparse
import ast
import inspect
import json
from pathlib import Path

from claasp.primitives._catalogue_exports import load_export

snapshot = json.load(open("tools/data/legacy_current_snapshot.json"))
modules = {item["path"]: item for item in snapshot["python_files"]}
records = (
    json.load(open("tools/data/legacy_inventory.json"))["records"]
    + json.load(open("tools/data/legacy_inventory_delta.json"))["records"]
)
contracts = {
    "cipher_family": "Primitive(family_name=...) and immutable graph metadata replace constructor string labels.",
    "cipher_type": "Primitive(kind=...) replaces the legacy type label.",
    "inputs": "Explicit PrimitiveInput descriptors and CompositeBuilder ports replace implicit input-name lists.",
    "cipher_inputs_bit_size": "Explicit UnitArrayType input descriptors replace parallel bit-size lists; Forro calls this primitive_inputs_bit_size.",
    "state_of_components": "CompositeBuilder and graph bindings compose existing state; constructors no longer accept mutable legacy ComponentState objects.",
    "description": "FeedbackRegisterParameters or LinearMap(matrix, unit_type) expresses the operation in typed form.",
    "register_size": "FeedbackRegisterParameters carries typed register specifications and output taps.",
    "block_bit_size": "Identity(bit_size=...) is the corresponding renamed constructor parameter.",
    "bit_size": "BitVectorSBox(input_bit_size=...), or matrix/mapping dimensions for LinearMap and Permutation, express the same boundary width.",
    "irreducible_polynomial": "LinearMap(matrix=..., unit_type=BinaryExtensionField(degree, modulus)) specifies the field explicitly.",
    "word_size": "LinearMap unit_type specifies the binary field and degree; Permutation(word_size=...) specifies packed word width.",
    "permutation_description": "Permutation(mapping=...) uses an explicit mapping.",
    "rotation_amount": "Rotate(amount=abs(value), direction=left if value<0 else right) makes the signed convention explicit.",
    "shift_amount": "Shift(amount=abs(value), direction=left if value<0 else right) makes the signed convention explicit.",
    "number_of_words": "Permutation mapping length and word_size determine the word boundary; shift_rows provides the typed row transform.",
    "word_bit_size": "shift_rows and an explicit typed Permutation mapping determine each word width.",
    "rotation_amounts_parameter": "claasp.components.sigma or gaston_theta builds a typed LinearMap from the rotation list.",
    "key_bit_size": "Trivium fixes the standardized key to 80 bits; the legacy initialization and taps also hard-code that layout.",
    "iv_bit_size": "Trivium fixes the standardized IV to 80 bits; the legacy initialization and taps also hard-code that layout.",
    "state_bit_size": "Trivium fixes its three-register state to 288 bits; nonstandard sizes are not valid legacy Trivium layouts.",
    "keystream_bit_len": "TriviumKeystreamFunction(keystream_bit_size=...) is an explicit parameter rename.",
}


def generate():
    rows = []
    for r in records:
        metadata = r.get("primitive")
        if (
            r["kind"] != "source"
            or not metadata
            or not metadata.get("proposed_class")
            or r["path"] not in modules
        ):
            continue
        try:
            cls = load_export(metadata["proposed_class"])
        except (KeyError, ImportError, AttributeError):
            continue
        source = modules[r["path"]]
        init = next((s for s in source["symbols"] if s["name"].endswith(".__init__")), None)
        if init is None:
            continue
        tree = ast.parse("def f(" + init["signature"] + "):\n pass").body[0]
        assert isinstance(tree, ast.FunctionDef)
        legacy = [arg.arg for arg in tree.args.args + tree.args.kwonlyargs if arg.arg != "self"]
        signature = inspect.signature(cls)
        replaced = []
        for name in legacy:
            if name in signature.parameters:
                continue
            if name not in contracts:
                raise RuntimeError((r["path"], name))
            replaced.append({"legacy_parameter": name, "replacement_contract": contracts[name]})
        rows.append(
            {
                "path": r["path"],
                "legacy_constructor": init["name"],
                "legacy_signature": init["signature"],
                "v5_class": metadata["proposed_class"],
                "v5_signature": str(signature),
                "same_named_parameters": sorted(set(legacy) & set(signature.parameters)),
                "explicit_replacements": replaced,
                "scope": "Constructor contract review only. Same spelling is not numerical parity; executable paired vectors, nondefault options and backend witnesses are recorded separately.",
            }
        )
    return {"schema_version": 1, "source_commit": snapshot["source_commit"], "records": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = Path("tools/data/legacy_constructor_contracts.json")
    rendered = json.dumps(generate(), indent=2, sort_keys=True) + "\n"
    if args.check:
        if path.read_text() != rendered:
            raise SystemExit(
                "constructor contracts changed; review the parameter mappings and numerical witnesses"
            )
    else:
        path.write_text(rendered)


if __name__ == "__main__":
    main()
