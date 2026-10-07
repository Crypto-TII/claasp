import importlib
from dataclasses import FrozenInstanceError

import pytest

from claasp.catalogue import Catalogue, PrimitiveRecord, RepresentationRecord, catalogue


def test_catalogue_returns_sorted_immutable_records():
    records = catalogue.primitives()
    assert len(records) == 142
    assert isinstance(records, tuple)
    assert records == tuple(sorted(records, key=lambda item: (item.category, item.name)))
    assert isinstance(records[0], PrimitiveRecord)
    with pytest.raises(FrozenInstanceError):
        records[0].name = "changed"


def test_primitive_lookup_preserves_classification_and_typed_contract():
    aes = Catalogue().primitive("AES")
    assert aes.official_name == "AES"
    assert aes.qualified_name == "claasp.primitives.block_ciphers.aes.AES"
    assert aes.category == "block_ciphers"
    assert aes.kind == "block_cipher"
    assert aes.classified_input_roles == ("key", "plaintext")
    assert tuple(item.name for item in aes.inputs) == ("plaintext", "key")
    assert aes.bijectivity_obligation
    assert aes.fixed_evidence


@pytest.mark.parametrize(
    ("filter_name", "included", "excluded"),
    (
        ("arx", "Speck", "Zuc"),
        ("pure-arx", "ChaCha", "Speck"),
        ("andrx", "Simon", "AES"),
        ("sbox-based", "AES", "Speck"),
        ("fsr-based", "A51", "AES"),
        ("tweakable_block_cipher", "Mantis", "AES"),
    ),
)
def test_design_filters_preserve_legacy_discovery_intent(filter_name, included, excluded):
    names = {item.name for item in catalogue.primitives(filters=filter_name)}
    assert included in names
    assert excluded not in names


def test_category_and_component_filters_compose():
    records = catalogue.primitives(category="block_cipher", components=("sbox", "xor"))
    assert records
    assert all(item.category == "block_ciphers" for item in records)
    assert all(item.components & {"BitVectorSBox", "SBox"} for item in records)
    assert all("Xor" in item.components for item in records)


@pytest.mark.parametrize(
    ("legacy_category", "category"),
    (
        ("hash_functions", "functions"),
        ("stream_ciphers", "block_functions"),
        ("toys", "toy_primitives"),
    ),
)
def test_legacy_category_aliases_map_to_v5_semantics(legacy_category, category):
    records = catalogue.primitives(category=legacy_category)
    assert records
    assert all(item.category == category for item in records)


def test_unknown_filter_has_a_clear_error():
    with pytest.raises(ValueError, match="unknown primitive filters"):
        catalogue.primitives(filters="not-a-design")


def test_pure_andrx_filter_does_not_promote_constant_bearing_graphs():
    assert catalogue.primitives(filters="pure-andrx") == ()


def test_component_records_are_one_to_one_with_teaching_wrappers():
    components = catalogue.components()
    assert len(components) == 23
    assert {item.name for item in catalogue.components(names=("SBox", "LinearMap"))} == {
        "SBox",
        "LinearMap",
    }


def test_representation_component_queries_are_bidirectional():
    representations = catalogue.representations(component="Power")
    assert all(isinstance(item, RepresentationRecord) for item in representations)
    assert tuple(item.name for item in representations) == (
        "concrete_execution",
        "primitive_serialization",
        "python_generated_source",
        "msolve_input",
        "prime_field_polynomial",
        "primitive_diagram",
        "singular_program",
    )
    assert {item.name for item in catalogue.components(representation="boolean_cnf")} == {
        "Add",
        "BitVectorSBox",
        "BitwiseAnd",
        "Constant",
        "Identity",
        "ModularAdd",
        "Permutation",
        "Rotate",
        "Xor",
    }
    with pytest.raises(KeyError, match="unknown component"):
        catalogue.representations(component="Missing")


def test_representation_driver_queries_are_bidirectional():
    assert tuple(item.name for item in catalogue.drivers(representation="boolean_cnf")) == (
        "minizinc",
        "kissat",
        "cryptominisat",
        "minisat",
        "z3",
        "glpk",
    )
    assert catalogue.driver("z3").representations == frozenset(
        {
            "boolean_cnf",
            "boolean_smt",
            "word_differential_smt",
            "word_linear_smt",
        }
    )
    assert tuple(item.name for item in catalogue.representations(driver="singular")) == (
        "singular_program",
    )


def test_analysis_queries_apply_representation_requirements_conservatively():
    speck = {item.name: item for item in catalogue.analyses(primitive="Speck")}
    assert "avalanche" in speck
    assert "enumerate_xor_differential_trails" in speck
    assert speck["find_lowest_weight_xor_differential_trail"].restriction
    aes = {item.name for item in catalogue.analyses(primitive="AES")}
    assert "avalanche" in aes
    assert "solve" not in aes  # its current CNF lowering has no LinearMap semantics
    assert "is_xor_differential_transition_possible" in {
        item.name for item in catalogue.analyses(primitive="Present")
    }


def test_unknown_primitive_has_clear_error():
    with pytest.raises(KeyError, match="unknown primitive 'Missing'"):
        catalogue.primitive("Missing")


def test_realization_queries_filter_capabilities_and_maturity():
    records = catalogue.realizations(primitive="AES", capabilities="algebraic_semantics")
    assert tuple(item.identity for item in records) == ("AES:algebraic",)
    assert catalogue.realizations(primitive="AES", structure="lookup_sbox")[0].name == "lookup"
    assert all(item.maturity == "stable" for item in catalogue.realizations(maturity="stable"))


def test_parameter_queries_return_read_only_structured_values():
    records = catalogue.parameter_sets(
        primitive="Speck",
        parameters={"block_bit_size": 32, "key_bit_size": 64},
    )
    assert len(records) == 1
    assert records[0].name == "standard-1"
    assert records[0].values["number_of_rounds"] == 22
    with pytest.raises(TypeError):
        records[0].values["number_of_rounds"] = 1


def test_driver_queries_are_lazy_and_availability_is_structured(monkeypatch):
    assert {item.name for item in catalogue.drivers(kind="execution_engine")} == {
        "python_scalar",
        "python_batch",
        "python_transposed_batch",
        "python_generated_source",
        "native_generated_c",
    }
    assert catalogue.driver_availability("python_scalar").available
    module = importlib.import_module("claasp.catalogue.catalogue")
    monkeypatch.setattr(module.shutil, "which", lambda name: None)
    unavailable = catalogue.driver_availability("z3")
    assert not unavailable.available
    assert unavailable.driver.name == "z3"
    with pytest.raises(KeyError, match="unknown driver"):
        catalogue.driver("missing")


def test_minizinc_solver_probe_checks_the_requested_solver(monkeypatch):
    class Completed:
        returncode = 0
        stdout = "Chuffed 0.13"

    module = importlib.import_module("claasp.catalogue.catalogue")
    monkeypatch.setattr(module.shutil, "which", lambda name: "/bin/minizinc")
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: Completed())
    probe = catalogue.driver_availability("minizinc_chuffed")
    assert probe.available
    assert probe.resolved == "/bin/minizinc"


def test_catalogue_exposes_presentation_capabilities_separately():
    representations = catalogue.representations(driver="text_presentation")
    assert [item.name for item in representations] == ["report_presentation"]
    assert [item.name for item in catalogue.drivers(representation="report_presentation")] == [
        "text_presentation",
        "matplotlib_presentation",
    ]
    presentation = next(item for item in catalogue.analyses() if item.name == "present")
    assert presentation.kind == "result_presentation"
    assert "never executes" in presentation.restriction


def test_catalogue_exposes_serialization_source_and_diagram_capabilities():
    assert catalogue.representation("primitive_serialization").scope == "generic_graph"
    assert catalogue.representation("execution_artifact_serialization").scope == "result"
    assert {item.name for item in catalogue.drivers(representation="python_generated_source")} == {
        "python_source_compiler",
        "python_generated_source",
    }
    assert {item.name for item in catalogue.drivers(representation="c_generated_source")} == {
        "c_source_compiler",
        "native_generated_c",
    }
    assert {item.name for item in catalogue.drivers(representation="primitive_diagram")} == {
        "ascii_diagram",
        "tikz_diagram",
        "latex",
    }
