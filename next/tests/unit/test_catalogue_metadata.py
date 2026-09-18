import importlib
import inspect
import json
from pathlib import Path
import subprocess
import sys

from claasp_next.primitives._catalogue_exports import ALL_EXPORTS


ROOT = Path(__file__).parents[2]
CATALOGUE = ROOT / "src/claasp_next/catalogue/data/catalogue.json"


def _catalogue():
    return json.loads(CATALOGUE.read_text(encoding="utf-8"))


def test_committed_catalogue_covers_public_primitives_components_and_drivers():
    catalogue = _catalogue()
    primitives = catalogue["primitives"]
    assert catalogue["schema_version"] == 2
    assert {item["name"] for item in primitives} == set(ALL_EXPORTS)
    assert len(primitives) == len(ALL_EXPORTS) == 142
    assert len(catalogue["components"]) == 23
    assert len(catalogue["representations"]) == 13
    assert len(catalogue["analyses"]) == 9
    assert len(catalogue["drivers"]) == 14
    assert len({item["name"] for item in catalogue["drivers"]}) == 14


def test_every_primitive_has_classification_contract_and_evidence():
    for item in _catalogue()["primitives"]:
        assert item["official_name"] == item["name"]
        assert item["module"] == ALL_EXPORTS[item["name"]]
        assert item["classification_basis"]
        assert item["kind"]
        assert all(input_["role"] for input_ in item["inputs"])
        assert item["components"]
        assert item["parameter_sets"]
        assert item["realizations"]
        assert item["fixed_evidence"]
        assert all((ROOT.parent / path).is_file() for path in item["fixed_evidence"])


def test_every_catalogue_parameter_set_matches_its_public_constructor():
    for item in _catalogue()["primitives"]:
        primitive_class = getattr(importlib.import_module(item["module"]), item["name"])
        signature = inspect.signature(primitive_class)
        if any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in signature.parameters.values()
        ):
            continue
        accepted = set(signature.parameters)
        for parameter_set in item["parameter_sets"]:
            assert set(parameter_set["values"]) <= accepted, (
                item["name"], parameter_set["name"], set(parameter_set["values"]) - accepted,
            )


def test_legacy_sbox_forms_are_explicitly_noncanonical():
    by_name = {item["name"]: item for item in _catalogue()["primitives"]}
    for name in ("GimliSbox", "SimeckSbox", "SimonSbox"):
        assert by_name[name]["authenticity"] == "noncanonical_legacy_regression"
        assert "noncanonical_legacy_regression" in by_name[name]["labels"]
    assert by_name["Gimli"]["authenticity"] == "canonical"
    assert by_name["Simeck"]["authenticity"] == "canonical"
    assert by_name["Simon"]["authenticity"] == "canonical"


def test_catalogue_closure_gate_passes():
    completed = subprocess.run(
        [sys.executable, str(ROOT / "tools/catalogue_closure.py"), "--check"],
        check=True, capture_output=True, text=True,
    )
    assert (
        "142 primitives, 23 components, 13 representations, 9 analyses, 14 drivers"
        in completed.stdout
    )
