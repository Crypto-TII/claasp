import importlib
import inspect
import pkgutil
from typing import cast

import pytest

from claasp.presentation import trail_section
from claasp.primitives import Simon, Speck, ToySpeck
from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    ConstraintModelProvenance,
    ConstraintReferenceStatus,
)
from claasp.representations.constraints.cp import components as cp_components
from claasp.representations.constraints.cp.components import (
    ProbabilisticTruncatedModularAddCPModel,
    SBoxBoomerangCPModel,
    SBoxXorDifferentialCPModel,
)
from claasp.representations.constraints.cp.lowering import BooleanMiniZincLowerer
from claasp.representations.constraints.milp import components as milp_components
from claasp.representations.constraints.milp.components import (
    ModularAddLinearMILPModel,
    MonomialTransitionMILPModel,
    SBoxXorDifferentialMILPModel,
    SBoxXorLinearMILPModel,
)
from claasp.representations.constraints.milp.lowering import (
    BooleanMonomialGraphMILPModel,
    cnf_to_milp,
)
from claasp.representations.constraints.milp.trails import PresentMonomialTrailMILPModel
from claasp.representations.constraints.sat import BooleanCNFModel
from claasp.representations.constraints.sat import components as sat_components
from claasp.representations.constraints.sat.components import (
    ModularAddFunctionalSATModel,
    SBoxFunctionalSATModel,
    WiringFunctionalSATModel,
)
from claasp.representations.constraints.smt import components as smt_components
from claasp.representations.constraints.smt.components import (
    ModularAddDifferentialSMTModel,
    ModularAddLinearSMTModel,
    SBoxXorDifferentialSMTModel,
    SBoxXorLinearSMTModel,
)
from claasp.representations.constraints.smt.model import SMTFormula
from claasp.representations.constraints.smt.trails import WordDifferentialSMTModel
from claasp.semantics.cryptanalysis import (
    Trail,
    TrailKind,
    TrailSearchMetadata,
    TrailSearchResult,
    TrailStep,
    Transition,
    XorDifference,
)

COMPONENT_PACKAGES = (sat_components, smt_components, milp_components, cp_components)


def _component_model_classes():
    for package in COMPONENT_PACKAGES:
        for module_info in pkgutil.iter_modules(package.__path__, package.__name__ + "."):
            module = importlib.import_module(module_info.name)
            yield from (
                value
                for _, value in inspect.getmembers(module, inspect.isclass)
                if value.__module__ == module.__name__ and value.__name__.endswith("Model")
            )


def test_every_component_model_declares_an_explicit_reference_status():
    records: list[ConstraintModelProvenance] = []
    for model in _component_model_classes():
        if "model_provenance" in model.__dict__:
            declarations = (model.model_provenance,)
        else:
            declarations = tuple(model.model_provenance_by_kind.values())
        assert declarations, f"{model.__name__} has no provenance declaration"
        records.extend(declarations)

    assert all(isinstance(record, ConstraintModelProvenance) for record in records)
    assert all(isinstance(record.reference_status, ConstraintReferenceStatus) for record in records)
    assert {record.backend for record in records} == set(ConstraintBackend)
    assert ConstraintReferenceStatus.VERIFIED in {record.reference_status for record in records}


def test_direct_and_audited_modular_add_models_declare_their_reference_status():
    assert SBoxFunctionalSATModel.model_provenance.reference_status is (
        ConstraintReferenceStatus.NOT_APPLICABLE
    )
    for model in (
        ModularAddDifferentialSMTModel,
        ModularAddLinearSMTModel,
        ModularAddLinearMILPModel,
    ):
        assert model.model_provenance.reference_status is ConstraintReferenceStatus.VERIFIED
    assert ProbabilisticTruncatedModularAddCPModel.model_provenance.reference_status is (
        ConstraintReferenceStatus.TO_BE_DETERMINED
    )


def test_audited_modular_add_models_name_the_verified_primary_source_and_locator():
    differential = ModularAddDifferentialSMTModel.model_provenance
    assert differential.reference_identifier == "https://eprint.iacr.org/2001/001"
    assert differential.source_locator == "section 4, Algorithm 2 and Theorem 1"

    for model in (ModularAddLinearSMTModel, ModularAddLinearMILPModel):
        provenance = model.model_provenance
        assert provenance.reference_identifier == "10.1007/978-3-319-39555-5_26"
        assert provenance.source_locator == "section 3.1, Proposition 1 and equation (1)"


def test_audited_boomerang_model_names_the_bct_definition():
    provenance = SBoxBoomerangCPModel.model_provenance

    assert provenance.reference_status is ConstraintReferenceStatus.VERIFIED
    assert provenance.reference_identifier == "10.1007/978-3-319-78375-8_22"
    assert provenance.source_locator == "section 3.1, Definition 3.1"


def test_audited_monomial_models_name_the_monomial_prediction_construction():
    models = (
        MonomialTransitionMILPModel,
        BooleanMonomialGraphMILPModel,
        PresentMonomialTrailMILPModel,
    )

    for model in models:
        provenance = model.model_provenance
        assert provenance.reference_status is ConstraintReferenceStatus.VERIFIED
        assert provenance.reference_identifier == "https://eprint.iacr.org/2020/1048"
        assert provenance.source_locator in {
            "section 3, Definition 1",
            "section 3, Definition 1; section 4.2",
            "section 4.2, MILP model for the monomial trail of f^(i)",
        }


def test_exhaustive_sbox_tables_and_direct_linear_wiring_remain_not_applicable():
    for model in (
        SBoxXorDifferentialCPModel,
        SBoxXorDifferentialMILPModel,
        SBoxXorLinearMILPModel,
        SBoxXorDifferentialSMTModel,
        SBoxXorLinearSMTModel,
        WiringFunctionalSATModel,
    ):
        assert model.model_provenance.reference_status is (ConstraintReferenceStatus.NOT_APPLICABLE)


def test_monomial_graph_lowering_propagates_its_verified_model_declaration():
    primitive = Simon(number_of_rounds=1)
    model = BooleanMonomialGraphMILPModel(primitive, 0, "plaintext").milp_model()

    assert model.constraint_models == (
        ConstraintModelApplication(
            BooleanMonomialGraphMILPModel.model_provenance,
            tuple(cast(str, component.component_id) for component in primitive.components),
        ),
    )


def test_verified_reference_requires_a_stable_identifier_and_precise_locator():
    with pytest.raises(ValueError, match="identifier, title, and locator"):
        ConstraintModelProvenance(
            ConstraintBackend.SAT,
            "ExampleModel",
            "functional",
            "example",
            ConstraintReferenceStatus.VERIFIED,
        )
    with pytest.raises(ValueError, match="URL or DOI"):
        ConstraintModelProvenance(
            ConstraintBackend.SAT,
            "ExampleModel",
            "functional",
            "example",
            ConstraintReferenceStatus.VERIFIED,
            "citation-key",
            "Primary source",
            "section 3",
        )


def test_lowering_propagates_component_model_and_component_ids():
    formula = BooleanCNFModel(Speck(number_of_rounds=1)).cnf_formula()

    assert formula.constraint_models
    assert all(application.component_ids for application in formula.constraint_models)
    assert any(
        application.model is ModularAddFunctionalSATModel.model_provenance
        for application in formula.constraint_models
    )
    assert SMTFormula.from_cnf(formula).constraint_models == formula.constraint_models
    assert cnf_to_milp(formula).constraint_models == formula.constraint_models
    assert BooleanMiniZincLowerer().lower(formula).constraint_models == formula.constraint_models


def test_complete_trail_lowering_retains_the_modular_add_model_declaration():
    formula = WordDifferentialSMTModel(
        ToySpeck(), maximum_weight=2, nonzero_input="plaintext"
    ).smt_formula()

    modular_add = next(
        application
        for application in formula.constraint_models
        if application.model is ModularAddDifferentialSMTModel.model_provenance
    )
    assert modular_add.component_ids
    assert modular_add.model.reference_status is ConstraintReferenceStatus.VERIFIED
    assert modular_add.model.reference_identifier == "https://eprint.iacr.org/2001/001"


def test_trail_report_maps_references_and_deduplicates_verified_citations():
    provenance = ConstraintModelProvenance(
        ConstraintBackend.SMT,
        "ExampleDifferentialSMTModel",
        "xor_differential",
        "example clauses",
        ConstraintReferenceStatus.VERIFIED,
        "https://example.test/primary-source",
        "Primary source",
        "section 3, equation 7",
    )
    second_model = ConstraintModelProvenance(
        ConstraintBackend.MILP,
        "ExampleDifferentialMILPModel",
        "xor_differential",
        "example inequalities",
        ConstraintReferenceStatus.VERIFIED,
        "https://example.test/primary-source",
        "Primary source",
        "section 3, equation 7",
    )
    transition = Transition(
        TrailKind.XOR_DIFFERENTIAL,
        XorDifference(1, 1),
        XorDifference(1, 1),
        1,
        2,
    )
    trail = Trail(
        TrailKind.XOR_DIFFERENTIAL,
        XorDifference(1, 1),
        XorDifference(1, 1),
        (TrailStep("sbox_0", transition), TrailStep("sbox_1", transition)),
    )
    result = TrailSearchResult(
        trail,
        2.0,
        TrailSearchMetadata("fixture"),
        constraint_models=(
            ConstraintModelApplication(provenance, ("sbox_0",)),
            ConstraintModelApplication(second_model, ("sbox_1",)),
        ),
    )

    section = trail_section(result)

    assert section.tables[1].columns[-1].heading == "Constraint model reference"
    assert all("section 3, equation 7" in row.cells[-1].text for row in section.tables[1].rows)
    assert len(section.citations) == 1
