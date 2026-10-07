import importlib
import inspect
import json
import subprocess
import sys
from pathlib import Path

from claasp.primitives._catalogue_exports import ALL_EXPORTS

ROOT = next(
    parent for parent in Path(__file__).resolve().parents if (parent / "pyproject.toml").is_file()
)
CATALOGUE = ROOT / "src/claasp/catalogue/data/catalogue.json"


def _catalogue():
    return json.loads(CATALOGUE.read_text(encoding="utf-8"))


def test_committed_catalogue_covers_public_primitives_components_and_drivers():
    catalogue = _catalogue()
    primitives = catalogue["primitives"]
    assert catalogue["schema_version"] == 2
    assert {item["name"] for item in primitives} == set(ALL_EXPORTS)
    assert len(primitives) == len(ALL_EXPORTS) == 142
    assert len(catalogue["components"]) == 23
    assert len(catalogue["representations"]) == 19
    assert len(catalogue["analyses"]) == 11
    assert len(catalogue["drivers"]) == 26
    assert len({item["name"] for item in catalogue["drivers"]}) == 26


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
        assert all((ROOT / path).is_file() for path in item["fixed_evidence"])


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
                item["name"],
                parameter_set["name"],
                set(parameter_set["values"]) - accepted,
            )


def test_reviewed_retained_input_bijectivity_obligations():
    by_name = {item["name"]: item for item in _catalogue()["primitives"]}
    expected_components = {
        "Add",
        "BinaryAffineMap",
        "BitVectorSBox",
        "BitwiseNot",
        "FeedbackRegister",
        "IDEAMultiply",
        "Identity",
        "LinearMap",
        "ModularAdd",
        "ModularSubtract",
        "Permutation",
        "Power",
        "Rotate",
        "SBox",
        "VariableRotate",
        "Xor",
    }
    observed_components = {
        item["name"]
        for item in by_name.values()
        if item["category"] == "single_component_primitives" and item["bijectivity_obligation"]
    }
    assert observed_components == expected_components

    expected_toys = {
        "CipherFour",
        "Heys",
        "ToyAES",
        "ToyFeistel",
        "ToySPN1",
        "ToySPN2",
    }
    observed_toys = {
        item["name"]
        for item in by_name.values()
        if item["category"] == "toy_primitives" and item["bijectivity_obligation"]
    }
    assert observed_toys == expected_toys
    assert not by_name["Fancy"]["bijectivity_obligation"]
    assert by_name["ChaChaKeystreamBlock"]["bijectivity_obligation"]


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
        check=True,
        capture_output=True,
        text=True,
    )
    assert (
        "142 primitives, 23 components, 19 representations, 11 analyses, 26 drivers"
        in completed.stdout
    )


def test_component_property_capability_is_conservative_and_queryable():
    from claasp.catalogue import catalogue

    representation = catalogue.representation("component_properties")
    assert "LinearMap" in representation.components
    assert "Constant" not in representation.components
    assert {item.name for item in catalogue.drivers(representation="component_properties")} == {
        "component_minizinc",
        "component_bounded",
    }
    assert "component_property" in {item.name for item in catalogue.analyses(primitive="AES")}
