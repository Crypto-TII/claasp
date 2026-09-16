"""Export a reviewed v4 graph as a deterministic, Sage-free v5 data artifact.

Run this development helper inside the compatibility image; generated artifacts
are consumed by :mod:`claasp_next.primitives._catalogue_graph` without importing
the legacy package.
"""

from __future__ import annotations

import argparse
import ast
import gzip
import importlib
import inspect
import json
from enum import Enum
from pathlib import Path
import re


def _gf_multiply(left: int, right: int, polynomial: int, width: int) -> int:
    result = 0
    for _ in range(width):
        if right & 1:
            result ^= left
        right >>= 1
        left <<= 1
        if left & (1 << width):
            left ^= polynomial
    return result & ((1 << width) - 1)


def _mix_binary_matrix(description) -> list[list[int]]:
    matrix, polynomial, word_size = description
    rows = len(matrix)
    columns = len(matrix[0])
    bit_rows = [[0] * (columns * word_size) for _ in range(rows * word_size)]
    for input_bit in range(columns * word_size):
        input_word = input_bit // word_size
        input_value = 1 << (word_size - 1 - input_bit % word_size)
        for output_word in range(rows):
            if polynomial:
                value = _gf_multiply(
                    matrix[output_word][input_word], input_value, polynomial, word_size
                )
            else:
                value = matrix[output_word][input_word] * input_value
            value &= (1 << word_size) - 1
            for output_offset in range(word_size):
                bit_rows[output_word * word_size + output_offset][input_bit] = (
                    value >> (word_size - 1 - output_offset)
                ) & 1
    return bit_rows


def _json_default(value):
    if isinstance(value, Enum):
        return value.value
    try:
        return int(value)
    except (TypeError, ValueError):
        return list(value)


def export(module_name: str, class_name: str, destination: Path, parameters: dict) -> None:
    module = importlib.import_module(module_name)
    primitive = getattr(module, class_name)(**parameters)
    graph = primitive.as_python_dictionary()
    rounds = []
    for primitive_round in graph["cipher_rounds"]:
        exported_round = []
        for component in primitive_round:
            item = {
                "id": component["id"],
                "type": component["type"],
                "input_ids": component["input_id_link"],
                "input_positions": component["input_bit_positions"],
                "output_size": component["output_bit_size"],
                "description": component["description"],
            }
            if component["type"] == "mix_column":
                item["binary_matrix"] = _mix_binary_matrix(component["description"])
            exported_round.append(item)
        rounds.append(exported_round)
    payload = {
        "family_name": primitive.family_name,
        "inputs": graph["cipher_inputs"],
        "input_sizes": graph["cipher_inputs_bit_size"],
        "output_size": graph["cipher_output_bit_size"],
        "parameters": parameters,
        "provenance": [["migration_source", module_name]],
        "rounds": rounds,
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"),
        default=_json_default,
    ).encode()
    destination.write_bytes(gzip.compress(encoded, compresslevel=9, mtime=0))


def _literal_test_configurations(class_name: str, parameter_names: tuple[str, ...]) -> list[dict]:
    configurations = []
    for path in Path("tests/unit/ciphers").glob("**/*.py"):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            called_name = node.func.id if isinstance(node.func, ast.Name) else (
                node.func.attr if isinstance(node.func, ast.Attribute) else None
            )
            if called_name != class_name or any(keyword.arg is None for keyword in node.keywords):
                continue
            try:
                values = [ast.literal_eval(argument) for argument in node.args]
                configuration = dict(zip(parameter_names, values))
                configuration.update({
                    keyword.arg: ast.literal_eval(keyword.value) for keyword in node.keywords
                })
            except (ValueError, TypeError):
                continue
            configurations.append(configuration)
    return configurations


def _observed_identity_configurations(class_name: str, parameter_names: tuple[str, ...]) -> list[dict]:
    path = Path("next/migration/m10_9d6_fixed_observations.json")
    if not path.exists():
        return []
    role_names = {
        "p": ("block_bit_size", "state_bit_size"),
        "k": ("key_bit_size", "key_length"),
        "t": ("tweak_bit_size",),
        "r": ("number_of_rounds",),
    }
    configurations = []
    for observation in json.loads(path.read_text(encoding="utf-8")):
        if observation["legacy_class"].rsplit(".", 1)[-1] != class_name:
            continue
        identity = dict((role, int(value)) for role, value in re.findall(
            r"_(p|k|t|r)(\d+)", observation["legacy_id"]
        ))
        configuration = {}
        for role, candidates in role_names.items():
            name = next((candidate for candidate in candidates if candidate in parameter_names), None)
            if name is not None and role in identity:
                configuration[name] = identity[role]
        if configuration:
            configurations.append(configuration)
    return configurations


def export_milestone_slice(inventory_path: Path, slice_name: str) -> None:
    from claasp.cipher import Cipher

    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    records = [
        record for record in inventory["records"]
        if record.get("milestone_owner") == slice_name and record["kind"] == "source"
        and record["primitive"]["primitive_category"] != "outside_scope"
    ]
    for record in records:
        proposed_module = record["primitive"]["proposed_module"]
        destination_module = Path("next/src") / Path(proposed_module.replace(".", "/") + ".py")
        stem = proposed_module.rsplit(".", 1)[-1]
        data_directory = destination_module.parent / "data"
        index_path = data_directory / f"{stem}.index.json"
        generated_and_complete = index_path.exists() and bool(
            json.loads(index_path.read_text(encoding="utf-8")).get("variants")
        )
        if stem in {"aes", "present", "trivium"} or generated_and_complete:
            continue
        legacy_module = record["path"][:-3].replace("/", ".")
        if "invertible_permutation" in legacy_module or legacy_module.endswith("spongent_pi_fsr_permutation"):
            continue
        module = importlib.import_module(legacy_module)
        candidates = [
            value for value in vars(module).values()
            if inspect.isclass(value) and value.__module__ == legacy_module
            and issubclass(value, Cipher)
        ]
        if len(candidates) != 1:
            raise ValueError(f"expected one primitive class in {legacy_module}, found {candidates}")
        legacy_class = candidates[0]
        legacy_class_name = legacy_class.__name__
        signature = inspect.signature(legacy_class)
        parameter_names = tuple(signature.parameters)
        # The legacy invertible-permutation defaults synthesize large inverse
        # matrices in Sage. M10.9d7 freezes the explicitly tested forward
        # graphs; general graph inversion remains owned by M10.10.
        configurations = [] if "invertible" in legacy_module else [{}]
        parameter_catalogue = getattr(module, "PARAMETERS_CONFIGURATION_LIST", ())
        configurations.extend(dict(item) for item in parameter_catalogue if isinstance(item, dict))
        configurations.extend(_literal_test_configurations(legacy_class_name, parameter_names))
        configurations.extend(_observed_identity_configurations(legacy_class_name, parameter_names))
        if legacy_class_name == "SiphashMAC":
            # The selected official vectors are parameterized through ``range``
            # expressions, so they are intentionally outside literal AST
            # extraction.
            configurations.extend({
                "message_byte_size": size,
                "compression_rounds": 2,
                "finalization_rounds": 4,
                "output_bit_size": 64,
            } for size in (0, 63))
        unique = []
        seen = set()
        for configuration in configurations:
            key = json.dumps(configuration, sort_keys=True, separators=(",", ":"))
            if key not in seen:
                seen.add(key)
                unique.append((key, configuration))

        category = proposed_module.split(".")[-2]
        variants = {}
        for _, configuration in unique:
            try:
                legacy_class(**configuration)
            except Exception:
                continue
            variant = f"v{len(variants)}"
            key = json.dumps(configuration, sort_keys=True, separators=(",", ":"))
            export(
                legacy_module, legacy_class_name,
                data_directory / f"{stem}.{variant}.json.gz", configuration,
            )
            variants[key] = variant
        index_path.write_text(json.dumps({
            "parameter_names": parameter_names,
            "variants": variants,
        }, sort_keys=True, indent=2) + "\n", encoding="utf-8")

        class_name = record["primitive"]["proposed_class"]
        destination_module.write_text(
            f'"""{record["primitive"]["official_name"]} typed primitive graph."""\n\n'
            'from claasp_next.primitives._catalogue_graph import (\n'
            '    CatalogueGraphPrimitive, load_catalogue_variant,\n'
            ')\n\n\n'
            f'class {class_name}(CatalogueGraphPrimitive):\n'
            f'    """Construct {record["primitive"]["official_name"]} from an audited parameter set."""\n\n'
            '    def __init__(self, *args, **parameters) -> None:\n'
            f'        specification = load_catalogue_variant("{category}", "{stem}", args, parameters)\n'
            '        super().__init__(specification)\n\n\n'
            f'__all__ = ["{class_name}"]\n',
            encoding="utf-8",
        )


def export_zero_regressions(inventory_path: Path, slice_name: str, destination: Path) -> None:
    from claasp.cipher import Cipher

    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    vectors = []
    for record in inventory["records"]:
        if record.get("milestone_owner") != slice_name or record["kind"] != "source":
            continue
        legacy_module = record["path"][:-3].replace("/", ".")
        module = importlib.import_module(legacy_module)
        candidates = [
            value for value in vars(module).values()
            if inspect.isclass(value) and value.__module__ == legacy_module
            and issubclass(value, Cipher)
        ]
        if len(candidates) != 1:
            raise ValueError(f"expected one primitive class in {legacy_module}")
        primitive = candidates[0]()
        inputs = [0] * len(primitive.inputs)
        vectors.append({
            "module": record["primitive"]["proposed_module"],
            "class": record["primitive"]["proposed_class"],
            "inputs": inputs,
            "output": int(primitive.evaluate(inputs)),
            "claim": "legacy-regression",
        })
    destination.write_text(json.dumps(vectors, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("module", nargs="?")
    parser.add_argument("class_name", nargs="?")
    parser.add_argument("destination", nargs="?", type=Path)
    parser.add_argument("parameters", nargs="?", default="{}")
    parser.add_argument("--inventory-slice")
    parser.add_argument("--zero-regressions", type=Path)
    parser.add_argument("--inventory", type=Path, default=Path("next/migration/legacy_inventory.json"))
    arguments = parser.parse_args()
    if arguments.inventory_slice:
        export_milestone_slice(arguments.inventory, arguments.inventory_slice)
        return
    if arguments.zero_regressions:
        export_zero_regressions(arguments.inventory, "M10.9d6", arguments.zero_regressions)
        return
    if not arguments.module or not arguments.class_name or not arguments.destination:
        parser.error("module, class_name, and destination are required outside --inventory-slice")
    export(
        arguments.module, arguments.class_name, arguments.destination,
        json.loads(arguments.parameters),
    )


if __name__ == "__main__":
    main()
