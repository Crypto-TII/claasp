#!/usr/bin/env python3
"""Machine-check the M10.9e realization audit against the shipped API."""

import argparse
import importlib
import json
from pathlib import Path


ROOT = Path(__file__).parents[1]
CATALOGUE = ROOT / "migration/realization_catalogue.json"


def check() -> tuple[int, int]:
    catalogue = json.loads(CATALOGUE.read_text(encoding="utf-8"))
    records = catalogue["families"]
    interchangeable = 0
    realizations = 0
    for record in records:
        module_name, class_name = record["canonical"].split(":", 1)
        primitive_class = getattr(importlib.import_module(module_name), class_name)
        descriptors = primitive_class.available_realizations()
        names = tuple(item.name for item in descriptors)
        expected = tuple(record["equivalent"])
        if len(expected) > 1:
            assert names == expected, (record["family"], names, expected)
            graphs = tuple(primitive_class.realize(name) for name in names)
            reference = graphs[0]
            contract = (
                tuple(reference.input_descriptors.items()), reference.output.value_type,
                reference.kind,
            )
            assert all((
                tuple(graph.input_descriptors.items()), graph.output.value_type, graph.kind,
            ) == contract for graph in graphs)
            interchangeable += 1
            realizations += len(graphs)
        for descriptor in descriptors:
            assert descriptor.capabilities
            assert descriptor.structure
            assert descriptor.description
            assert descriptor.provenance
        for exclusion in record["excluded"]:
            assert exclusion["module"] and exclusion["reason"]
    closure = catalogue["closure"]
    assert closure["status"] == "achieved-in-m10.9e5"
    assert closure["interchangeable_families"] == interchangeable
    assert closure["realization_graphs"] == realizations
    for evidence in closure["fixed_evidence"]:
        assert (ROOT / evidence).is_file(), evidence
    assert (ROOT / closure["equivalence_test"]).is_file()
    return interchangeable, realizations


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="validate the committed catalogue")
    arguments = parser.parse_args()
    if not arguments.check:
        parser.error("pass --check")
    families, realizations = check()
    print(f"realization closure: {families} interchangeable families, {realizations} graphs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
