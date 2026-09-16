"""Bind captured legacy fixed vectors to deterministic v5 parameter sets."""

from __future__ import annotations

import argparse
import gzip
import importlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).parents[2]


def _identity_rounds(identity: str) -> int | None:
    match = re.search(r"_r(\d+)$", identity)
    return int(match.group(1)) if match else None


def _load_candidates(module_name: str, class_name: str):
    category, stem = module_name.split(".primitives.", 1)[1].split(".", 1)
    data = ROOT / "next/src/claasp_next/primitives" / category / stem / "data"
    index_path = data / "index.json"
    primitive_class = getattr(importlib.import_module(module_name), class_name)
    if not index_path.exists():
        return primitive_class, []
    index = json.loads(index_path.read_text(encoding="utf-8"))
    candidates = []
    for key, variant in index["variants"].items():
        parameters = json.loads(key)
        spec = json.loads(gzip.decompress((data / f"{variant}.json.gz").read_bytes()))
        candidates.append((parameters, spec))
    return primitive_class, candidates


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--slice", default="M10.9d6")
    parser.add_argument("--observations", type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    suffix = arguments.slice.lower().replace(".", "_")
    observations_path = arguments.observations or ROOT / f"next/migration/{suffix}_fixed_observations.json"
    destination = arguments.output or ROOT / f"next/migration/{suffix}_fixed_vectors.json"
    inventory = json.loads((ROOT / "next/migration/legacy_inventory.json").read_text(encoding="utf-8"))
    observations = json.loads(observations_path.read_text(encoding="utf-8"))
    records = {
        record["path"][:-3].replace("/", "."): record
        for record in inventory["records"]
        if record.get("milestone_owner") == arguments.slice and record["kind"] == "source"
    }
    grouped = {}
    for observation in observations:
        legacy_module = observation["legacy_class"].rsplit(".", 1)[0]
        grouped.setdefault((legacy_module, observation["legacy_id"]), []).append(observation)

    bound = []
    unresolved = []
    for (legacy_module, identity), vectors in grouped.items():
        record = records[legacy_module]
        module_name = record["primitive"]["proposed_module"]
        class_name = record["primitive"]["proposed_class"]
        primitive_class, candidates = _load_candidates(module_name, class_name)
        rounds = _identity_rounds(identity)
        if not candidates and class_name == "AES":
            key_size = int(re.search(r"_k(\d+)_", identity).group(1))
            candidates = [({"key_bit_size": key_size}, None)]
        elif not candidates and class_name == "Present":
            key_size = int(re.search(r"_k(\d+)_", identity).group(1))
            candidates = [({"key_bit_size": key_size}, None)]
        elif class_name == "Subterranean":
            version = getattr(importlib.import_module(module_name), "Version")
            candidates = [({
                "number_of_rounds": rounds,
                "version": version.V1 if len(vectors[0]["inputs"]) == 2 else version.V2,
            }, None)]
        elif class_name in {"KeccakInvertible", "XoodooInvertible"}:
            candidates = [({"number_of_rounds": rounds}, None)]
        elif class_name == "Trivium":
            output_size = int(re.search(r"_o(\d+)_", identity).group(1))
            candidates = [({"keystream_bit_size": output_size}, None)]
        round_candidates = [
            candidate for candidate in candidates
            if candidate[1] is not None and rounds is not None
            and len(candidate[1]["rounds"]) == rounds
        ]
        if round_candidates:
            candidates = round_candidates
        matches = []
        for parameters, spec in candidates:
            if spec is not None:
                if len(spec["inputs"]) != len(vectors[0]["inputs"]):
                    continue
            try:
                primitive = primitive_class(**parameters)
                def v5_inputs(vector):
                    values = vector["inputs"]
                    return values[::-1] if class_name == "AES" else values
                if all(primitive.evaluate(*v5_inputs(vector)) == vector["output"] for vector in vectors):
                    matches.append(parameters)
            except (TypeError, ValueError):
                continue
        if not matches:
            unresolved.append((legacy_module, identity, len(vectors)))
            continue
        def serializable(value):
            return {key: getattr(item, "name", item) for key, item in value.items()}
        parameters = min(matches, key=lambda value: (
            len(value), json.dumps(serializable(value), sort_keys=True)
        ))
        bound.append({
            "module": module_name,
            "class": class_name,
            "parameters": serializable(parameters),
            "legacy_id": identity,
            "claim": "legacy-fixed-vector",
            "vectors": [{
                "inputs": item["inputs"][::-1] if class_name == "AES" else item["inputs"],
                "output": item["output"],
            } for item in vectors],
        })
    destination.write_text(json.dumps(bound, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"bound_groups": len(bound), "vectors": sum(len(x["vectors"]) for x in bound),
                      "unresolved": unresolved}, indent=2))


if __name__ == "__main__":
    main()
