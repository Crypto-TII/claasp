"""Catalogue changes follow implementation registrations, not parallel lists."""

import copy
import importlib
import inspect
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from claasp._catalogue_metadata import _entry
from claasp.catalogue import catalogue

ROOT = next(
    parent for parent in Path(__file__).resolve().parents if (parent / "pyproject.toml").exists()
)


class _OwnerModule(ModuleType):
    __catalogue__: tuple


@pytest.fixture
def discovery(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "tools"))
    return importlib.import_module("catalogue_discovery")


@pytest.fixture
def entries(discovery):
    return discovery.discover()


def test_static_discovery_does_not_import_unrelated_modules(tmp_path, discovery):
    package = tmp_path / "example"
    package.mkdir()
    (package / "unrelated.py").write_text("raise AssertionError('must not import')\n")
    (package / "owner.py").write_text("__catalogue__: tuple = ()\n")
    (package / "mentions.py").write_text("# __catalogue__ = ()\n")
    assert tuple(discovery.declared_modules(package)) == ("example.owner",)


def test_registration_uses_real_bindings_and_constructor_defaults(discovery, monkeypatch):
    module = _OwnerModule("catalogue_fixture")
    exec(
        "class Solver:\n    def __init__(self, executable='first'):\n        pass\n",
        module.__dict__,
    )
    module.__catalogue__ = (
        _entry(
            "driver",
            module.Solver,
            name="example",
            kind="solver",
            availability="executable",
            target_parameter="executable",
        ),
    )
    monkeypatch.setitem(sys.modules, module.__name__, module)
    found = discovery.discover([module.__name__])
    assert discovery.driver_records(found)[0]["implementation"] == "catalogue_fixture:Solver"
    assert discovery.driver_records(found)[0]["target"] == "first"
    module.Solver.__init__.__defaults__ = ("second",)
    assert discovery.driver_records(found)[0]["target"] == "second"
    module.__catalogue__ = ()
    assert discovery.discover([module.__name__]) == ()


def test_new_owner_is_discovered_without_editing_a_central_list(tmp_path, monkeypatch, discovery):
    package = tmp_path / "extra_catalogue"
    package.mkdir()
    (package / "__init__.py").write_text("")
    source = package / "new.py"
    source.write_text(
        "from claasp._catalogue_metadata import _entry\n"
        "class Fresh:\n    pass\n"
        "__catalogue__ = (_entry('primitive', Fresh),)\n"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    modules = tuple(discovery.declared_modules(package))
    assert modules == ("extra_catalogue.new",)
    assert discovery.discover(modules)[0].implementation == "extra_catalogue.new:Fresh"
    source.unlink()
    assert tuple(discovery.declared_modules(package)) == ()


def test_duplicate_and_stale_bindings_fail_generation(discovery, monkeypatch):
    module = _OwnerModule("catalogue_bad_binding")
    exec("class Real:\n    pass\n", module.__dict__)
    declaration = _entry("primitive", module.Real)
    module.__catalogue__ = (declaration, declaration)
    monkeypatch.setitem(sys.modules, module.__name__, module)
    with pytest.raises(ValueError, match="duplicate catalogue identity"):
        discovery.discover([module.__name__])
    module.__catalogue__ = (_entry("primitive", module.Real, name="Missing"),)
    with pytest.raises(AttributeError, match="Missing"):
        discovery.discover([module.__name__])
    module.__catalogue__ = ({"implementation": "invented.path"},)
    with pytest.raises(TypeError, match="invalid catalogue declaration"):
        discovery.discover([module.__name__])


@pytest.mark.parametrize(
    "category,metadata",
    [("invented", {}), ("primitive", {"typo": True}), ("driver", {"availability": "invented"})],
)
def test_invalid_declarations_fail_early(category, metadata):
    with pytest.raises(ValueError):
        _entry(category, object, **metadata)
    with pytest.raises(TypeError, match="classes or functions"):
        _entry("primitive", "invented.path")


def test_generation_and_queries_never_probe_solver_installations(discovery, entries, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("generation must not probe installations")

    import shutil

    monkeypatch.setattr(shutil, "which", forbidden)
    monkeypatch.setattr(importlib.util, "find_spec", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    discovery.driver_records(entries)
    discovery.validate_public_api(entries)
    assert catalogue.solvers().entries


@pytest.mark.parametrize(
    "section", ["primitives", "components", "drivers", "representations", "analyses"]
)
def test_missing_extra_and_duplicate_entries_are_rejected(discovery, entries, section):
    payload = json.loads((ROOT / "src/claasp/catalogue/data/catalogue.json").read_text())
    for replacement in (
        payload[section][1:],
        payload[section] + [payload[section][0]],
        payload[section] + [dict(payload[section][0], name="unknown")],
    ):
        altered = dict(payload, **{section: replacement})
        with pytest.raises(ValueError, match="membership differs"):
            discovery.validate_payload(altered, entries)


@pytest.mark.parametrize(
    "section,field",
    [
        ("analyses", "representations"),
        ("analyses", "drivers"),
        ("representations", "components"),
        ("representations", "drivers"),
    ],
)
def test_unknown_compatibility_references_are_rejected(discovery, entries, section, field):
    payload = json.loads((ROOT / "src/claasp/catalogue/data/catalogue.json").read_text())
    payload[section][0][field] = ["missing"]
    with pytest.raises(ValueError, match="unknown"):
        discovery.validate_payload(payload, entries)


def test_unregistered_public_primitive_is_rejected(discovery, entries, monkeypatch):
    import claasp.primitives as public
    from claasp.graph import Primitive

    monkeypatch.setattr(public, "Missing", type("Missing", (Primitive,), {}), raising=False)
    monkeypatch.setattr(public, "__all__", [*public.__all__, "Missing"])
    with pytest.raises(ValueError, match="public primitive lacks"):
        discovery.validate_public_api(entries)


def test_all_public_analysis_methods_are_discoverable_and_unclassified_are_explicit():
    from claasp.analysis.facade import Analysis

    public = {
        name
        for name, _ in inspect.getmembers(Analysis, inspect.isfunction)
        if not name.startswith("_")
    }
    rows = {row.name: row for row in catalogue.analyses()}
    assert public <= rows.keys()
    assert (
        rows["find_lowest_weight_xor_linear_trail"].entry_point
        == "Primitive.analysis.find_lowest_weight_xor_linear_trail"
    )
    unknown = rows["search_impossible_differentials"]
    assert unknown.evidence == "unspecified" and unknown.restriction
    assert unknown not in catalogue.analyses(primitive="AES")


def test_parameterized_primitive_examples_are_runnable_and_match_fixed_values():
    mimc = catalogue.parameter_sets(primitive="MiMC")[0]
    poseidon = catalogue.parameter_sets(primitive="Poseidon")[0]
    assert mimc.name == poseidon.name == "teaching-example"
    mimc_class = importlib.import_module(catalogue.primitive("MiMC").module).MiMC
    poseidon_class = importlib.import_module(catalogue.primitive("Poseidon").module).Poseidon
    assert mimc_class(**mimc.values).evaluate(5) == 5
    assert poseidon_class(**poseidon.values).evaluate((0, 1)) == (4, 15)
    aes128 = catalogue.parameter_sets(primitive="AES128")[0]
    assert "key_bit_size" not in aes128.values


def test_invalid_constructor_parameters_and_missing_evidence_are_rejected(discovery, entries):
    payload = json.loads((ROOT / "src/claasp/catalogue/data/catalogue.json").read_text())
    altered = copy.deepcopy(payload)
    altered["primitives"][0]["parameter_sets"][0]["values"]["invented"] = 1
    with pytest.raises(TypeError, match="unexpected keyword"):
        discovery.validate_payload(altered, entries)
    altered = copy.deepcopy(payload)
    altered["primitives"][0]["fixed_evidence"] = ["tests/missing_test.py"]
    with pytest.raises(ValueError, match="missing evidence"):
        discovery.validate_payload(altered, entries)


def test_component_entries_point_to_actual_operations():
    from claasp.graph import Component

    for row in catalogue.components():
        cls = getattr(importlib.import_module(row.module), row.name)
        assert issubclass(cls, Component)


def test_unknown_dependency_parameter_and_incomplete_declarations_fail(discovery):
    class Adapter:
        def __init__(self, executable="program"):
            pass

    declaration = _entry(
        "driver",
        Adapter,
        name="test",
        kind="solver",
        availability="executable",
        target_parameter="typo",
    )
    row = discovery.DiscoveredEntry(__name__, declaration)
    with pytest.raises(ValueError, match="unknown dependency parameter"):
        discovery.driver_records((row,))
    with pytest.raises(ValueError, match="missing driver metadata"):
        _entry("driver", Adapter)


def test_component_without_a_teaching_wrapper_is_still_discovered(discovery, entries, monkeypatch):
    import claasp.components as public
    from claasp.graph import Component

    cls = type("NewOperation", (Component,), {})
    monkeypatch.setattr(public, "NewOperation", cls, raising=False)
    monkeypatch.setattr(public, "__all__", [*public.__all__, "NewOperation"])
    row = next(row for row in discovery.component_records(entries) if row["name"] == "NewOperation")
    assert row["primitive_wrapper"] is None
    assert row["module"] == cls.__module__


def test_one_command_generates_and_checks_both_catalogue_and_exports(
    discovery, tmp_path, monkeypatch
):
    generator = importlib.import_module("generate_catalogue_metadata")
    exports = importlib.import_module("generate_primitive_exports")
    metadata_path = tmp_path / "catalogue.json"
    exports_path = tmp_path / "exports.py"
    monkeypatch.setattr(generator, "DESTINATION", metadata_path)
    monkeypatch.setattr(exports, "DESTINATION", exports_path)
    monkeypatch.setattr(generator, "ROOT", tmp_path)
    monkeypatch.setattr(sys, "argv", ["generate_catalogue_metadata.py"])
    generator.main()
    assert json.loads(metadata_path.read_text())["primitives"]
    assert "CATEGORY_EXPORTS" in exports_path.read_text()
    monkeypatch.setattr(sys, "argv", ["generate_catalogue_metadata.py", "--check"])
    generator.main()
    exports_path.unlink()
    with pytest.raises(SystemExit, match="stale"):
        generator.main()


def test_non_solver_driver_cannot_be_silently_omitted(discovery, entries):
    without_tensorflow = tuple(row for row in entries if row.name != "tensorflow_distinguisher")
    with pytest.raises(ValueError, match="driver lacks.*TensorFlowDistinguisherDriver"):
        discovery.validate_public_api(without_tensorflow)


@pytest.mark.parametrize("field,value", [("domains", ["misspelled"]), ("scope", "misspelled")])
def test_invalid_domains_and_scope_are_rejected(discovery, entries, field, value):
    payload = json.loads((ROOT / "src/claasp/catalogue/data/catalogue.json").read_text())
    payload["representations"][0][field] = value
    with pytest.raises(ValueError, match=f"unknown {field}"):
        discovery.validate_payload(payload, entries)


def test_new_native_primitive_cannot_inherit_unrelated_test_evidence(discovery, entries):
    from dataclasses import replace

    generator = importlib.import_module("generate_catalogue_metadata")
    altered = tuple(
        replace(row, declaration=_entry("primitive", row.declaration.implementation))
        if row.name == "ToySpeck"
        else row
        for row in entries
    )
    with pytest.raises(ValueError, match="ToySpeck:.*explicit test evidence"):
        generator.build_catalogue(altered)


def test_misspelled_driver_kind_is_rejected():
    with pytest.raises(ValueError, match="unknown driver kind"):
        _entry("driver", object, name="example", kind="sovler", availability="builtin")


def test_convenience_classes_reuse_their_official_family_and_studies_have_none():
    from claasp.primitives import AES, AES128, CustomAES, Present, Present80, ToySpeck

    assert AES128().instances == AES().instances
    assert Present80().instances == Present().instances
    assert catalogue.primitive("AES128").official_instances_from == "AES"
    assert catalogue.primitive("Present80").official_instances_from == "Present"
    assert CustomAES().instances == ()
    assert ToySpeck().instances == ()
    for name in ("MiMC", "Poseidon"):
        row = catalogue.primitive(name)
        cls = getattr(importlib.import_module(row.module), name)
        assert cls(**row.parameter_sets[0].values).instances == ()


def test_unknown_and_cyclic_official_families_are_rejected(discovery, entries):
    payload = json.loads((ROOT / "src/claasp/catalogue/data/catalogue.json").read_text())
    rows = {row["name"]: row for row in payload["primitives"]}
    rows["AES128"]["official_instances_from"] = "Missing"
    with pytest.raises(ValueError, match="unknown official instance family"):
        discovery.validate_payload(payload, entries)
    rows["AES128"]["official_instances_from"] = "AES"
    rows["AES"]["official_instances_from"] = "AES128"
    with pytest.raises(ValueError, match="cyclic official instance family"):
        discovery.validate_payload(payload, entries)
