from claasp_next.analysis import (
    ComponentProperty, ComponentPropertyResult, NeuralExperiment, NeuralExperimentResult,
    PropertyClaim, PropertyDiagnostic, PropertyDomain, PropertyRequest,
)
from claasp_next.analysis.component_properties import ComponentAnalysisProvenance, DiagnosticCode as PropertyDiagnosticCode
from claasp_next.analysis.avalanche import AvalancheResult
from claasp_next.analysis.neural import NeuralDataset
from claasp_next.analysis.neural_experiments import (
    NeuralRun, NeuralRunProvenance, deterministic_partition,
)
from claasp_next.analysis.statistical_results import (
    DieharderObservation, DieharderReport, NISTFinalReport, NISTSummaryRow,
    StatisticalAssessment, StatisticalTestRun,
)
from claasp_next.presentation import (
    DiagnosticCode, EvidenceClass, PresentationDiagnostic, adapt_result,
    avalanche_section, component_property_section, dieharder_section, neural_section, nist_section,
    trail_section,
)
from claasp_next.semantics.cryptanalysis import (
    Trail, TrailKind, TrailSearchResult, TrailStep, Transition, XorDifference,
)


def fixed_trail():
    transition = Transition(
        TrailKind.XOR_DIFFERENTIAL, XorDifference(1, 4), XorDifference(3, 4), 4, 16
    )
    return Trail(
        TrailKind.XOR_DIFFERENTIAL, XorDifference(1, 4), XorDifference(3, 4),
        (TrailStep("sbox_0_0", transition),),
    )


def test_trail_adapter_preserves_weight_order_and_graph_reference():
    section = trail_section(TrailSearchResult(fixed_trail(), 2.0, "fixed PRESENT evidence; z3 4.14"))
    summary, steps = section.tables
    assert summary.rows[3].cells[1].text == "2"
    assert summary.rows[4].cells[1].text == "2"
    assert steps.rows[0].cells[-1].text == "sbox_0_0"
    assert steps.notes == ("Graph locations are evidence references, not semantic report identity.",)


def test_component_results_keep_exact_bound_and_unavailable_distinct():
    provenance = ComponentAnalysisProvenance("AES MixColumns", "field enumeration", graph_locations=("linear_map_1_0",))
    request = PropertyRequest(ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER, PropertyDomain.WORD_LINEAR)
    exact = ComponentPropertyResult(request, PropertyClaim.EXACT, 5, True, provenance)
    bounded = ComponentPropertyResult(request, PropertyClaim.PROVED_UPPER_BOUND, 5, False, provenance)
    unavailable = ComponentPropertyResult(
        PropertyRequest(ComponentProperty.BOOMERANG_UNIFORMITY, PropertyDomain.WORD_LINEAR),
        PropertyClaim.UNAVAILABLE, None, False, provenance,
        PropertyDiagnostic(PropertyDiagnosticCode.INAPPLICABLE_DOMAIN, "not a lookup table"),
    )
    rows = component_property_section((exact, bounded, unavailable)).tables[0].rows
    assert rows[0].cells[3].text == "5"
    assert rows[1].cells[3].text == "≤5"
    assert rows[2].cells[4].text == "unavailable"
    assert rows[2].cells[5].text == "inapplicable"


def test_avalanche_adapter_labels_fixed_matrix_empirical():
    result = AvalancheResult("speck", "plaintext", 4, 9, ((0.0, 0.5), (1.0, 0.25)))
    summary, matrix = avalanche_section(result).tables
    assert summary.rows[2].cells[1].evidence.classification is EvidenceClass.EMPIRICAL
    assert matrix.rows[1].cells[1].text == "1"
    assert matrix.rows[1].cells[2].text == "0.25"


def test_statistical_adapters_preserve_rows_unavailable_state_and_run_metadata():
    dieharder = DieharderReport((
        DieharderObservation(1, "birthdays", 0, 100, 100, 0.5, StatisticalAssessment.PASSED),
        DieharderObservation(2, "rank", 32, 100, 100, 0.01, StatisticalAssessment.WEAK),
    ))
    run = StatisticalTestRun("dieharder", "3.31.1", "a" * 64, ("dieharder", "-a"), 0.2, dieharder, "", "")
    table = dieharder_section(run).tables[0]
    assert [row.cells[-1].text for row in table.rows] == ["passed", "weak"]
    assert table.notes[0] == "dataset sha256: " + "a" * 64

    nist = NISTFinalReport((
        NISTSummaryRow("Frequency", "frequency", (1,) * 10, 0.5, 9, 10),
        NISTSummaryRow("RandomExcursions", "random_excursions", (0,) * 10, None, 0, 0),
    ))
    rows = nist_section(nist).tables[0].rows
    assert rows[0].cells[4].text == "0.5"
    assert rows[1].cells[4].diagnostic.code is DiagnosticCode.MISSING_EVIDENCE
    assert rows[1].cells[-1].text == "unavailable"


def test_neural_adapter_preserves_digest_seeds_version_metrics_and_failed_state():
    dataset = NeuralDataset(((0, 1), (1, 0)), (0, 1), "black_box", 7, ("a", "b"))
    experiment = NeuralExperiment("mlp", epochs=2, batch_size=1, validation_fraction=0.5, seed=3)
    partition = deterministic_partition(dataset, validation_fraction=0.0, testing_fraction=0.0, seed=19)
    provenance = NeuralRunProvenance.create(
        dataset, primitive="speck", partition_seed=19, driver="sklearn-mlp",
        driver_version="1.5", options={"hidden": 32},
    )
    run = NeuralRun(experiment, partition, provenance)
    rows = neural_section(NeuralExperimentResult((0.5, 0.75), "sklearn-mlp", True), run).tables[0].rows
    assert any(row.cells[0].text == "dataset digest" and row.cells[1].text == provenance.dataset_digest for row in rows)
    assert rows[-1].cells[1].text == "0.75"

    failed = PresentationDiagnostic(DiagnosticCode.RENDER_FAILED, "training process failed")
    failed_rows = neural_section(None, run, state=EvidenceClass.FAILED, diagnostic=failed).tables[0].rows
    assert failed_rows[-2].cells[1].text == "failed"
    assert failed_rows[-1].cells[1].text.startswith("render_failed:")


def test_unsupported_result_returns_typed_diagnostic():
    adapted = adapt_result(object())
    assert adapted.section is None
    assert adapted.diagnostic.code is DiagnosticCode.UNSUPPORTED_RESULT
