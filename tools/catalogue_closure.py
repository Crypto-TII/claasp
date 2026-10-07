#!/usr/bin/env python3
"""Machine-check M10.9f catalogue coverage and committed metadata freshness."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
CATALOGUE = ROOT / "src/claasp/catalogue/data/catalogue.json"
INVENTORY = ROOT / "migration/legacy_inventory.json"
REALIZATIONS = ROOT / "migration/realization_catalogue.json"
SINGLE_COMPONENTS = ROOT / "migration/single_component_catalogue.json"


def check() -> tuple[int, int, int, int, int]:
    catalogue = json.loads(CATALOGUE.read_text(encoding="utf-8"))
    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    realization_audit = json.loads(REALIZATIONS.read_text(encoding="utf-8"))
    single_components = json.loads(SINGLE_COMPONENTS.read_text(encoding="utf-8"))
    from claasp.primitives._catalogue_exports import ALL_EXPORTS

    primitives = catalogue["primitives"]
    by_name = {item["name"]: item for item in primitives}
    assert catalogue["schema_version"] == 2
    assert len(by_name) == len(primitives) == len(ALL_EXPORTS) == 142
    assert {name: item["module"] for name, item in by_name.items()} == ALL_EXPORTS
    assert {item["name"]: item["module"] for item in catalogue["components"]} == single_components
    assert len(catalogue["components"]) == 23
    assert len({item["name"] for item in catalogue["drivers"]}) == len(catalogue["drivers"]) == 26
    representations = catalogue["representations"]
    analyses = catalogue["analyses"]
    representation_names = {item["name"] for item in representations}
    driver_names = {item["name"] for item in catalogue["drivers"]}
    component_names = {item["name"] for item in catalogue["components"]}
    assert len(representation_names) == len(representations) == 19
    assert len({item["name"] for item in analyses}) == len(analyses) == 11
    for item in representations:
        assert set(item["components"]) <= component_names
        assert set(item["drivers"]) <= driver_names
    for item in analyses:
        assert set(item["representations"]) <= representation_names
        assert set(item["drivers"]) <= driver_names
        assert set(item["required_components"]) <= component_names
        assert set(item["primitives"]) <= set(by_name)
        assert set(item["drivers"]) <= {
            driver
            for representation in representations
            if representation["name"] in item["representations"]
            for driver in representation["drivers"]
        }
    for driver in catalogue["drivers"]:
        assert set(driver["representations"]) == {
            item["name"] for item in representations if driver["name"] in item["drivers"]
        }

    classified = {
        item["primitive"]["proposed_class"]: item
        for item in inventory["records"]
        if item.get("kind") == "source"
        and "primitive" in item
        and item["primitive"]["primitive_category"] != "outside_scope"
    }
    for name, record in by_name.items():
        assert record["official_name"] == name
        assert record["classification_basis"]
        assert record["components"] and record["parameter_sets"] and record["realizations"]
        assert record["fixed_evidence"]
        assert all((ROOT / path).is_file() for path in record["fixed_evidence"])
        if record["legacy_source"] is not None:
            source = classified[name]
            assert record["legacy_source"] == source["path"]
            assert record["input_roles"] == source["primitive"]["input_roles"]
            assert record["bijectivity_obligation"] == source["primitive"]["bijectivity_obligation"]

    for item in realization_audit["families"]:
        class_name = item["canonical"].split(":", 1)[1]
        if len(item["equivalent"]) > 1:
            assert [record["name"] for record in by_name[class_name]["realizations"]] == item[
                "equivalent"
            ]
    for name in ("GimliSbox", "SimeckSbox", "SimonSbox"):
        assert by_name[name]["authenticity"] == "noncanonical_legacy_regression"
        assert "noncanonical_legacy_regression" in by_name[name]["labels"]

    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = str(ROOT / "src")
    subprocess.run(
        [sys.executable, str(ROOT / "tools/generate_catalogue_metadata.py"), "--check"],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    return (
        len(primitives),
        len(catalogue["components"]),
        len(representations),
        len(analyses),
        len(catalogue["drivers"]),
    )


def main() -> int:
    if sys.argv[1:] != ["--check"]:
        raise SystemExit("usage: catalogue_closure.py --check")
    primitives, components, representations, analyses, drivers = check()
    print(
        f"catalogue closure: {primitives} primitives, {components} components, "
        f"{representations} representations, {analyses} analyses, {drivers} drivers"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
