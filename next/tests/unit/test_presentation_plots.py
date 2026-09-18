import os
import subprocess
import sys

import pytest

matplotlib = pytest.importorskip("matplotlib")
matplotlib.use("Agg")
from matplotlib import pyplot

from claasp_next.analysis import (
    ComponentProperty, ComponentPropertyResult, PropertyClaim, PropertyDomain, PropertyRequest,
)
from claasp_next.analysis.avalanche import AvalancheResult
from claasp_next.analysis.component_properties import ComponentAnalysisProvenance
from claasp_next.analysis.component_properties import DiagnosticCode, PropertyDiagnostic
from claasp_next.analysis.statistical_results import (
    DieharderObservation, DieharderReport, NISTFinalReport, NISTSummaryRow, StatisticalAssessment,
)
from claasp_next.drivers.renderers import (
    MatplotlibPresentationDriver, NormalizationDirection, RadarScale,
)


def property_result(prop, value, claim=PropertyClaim.EXACT):
    return ComponentPropertyResult(
        PropertyRequest(prop, PropertyDomain.LOOKUP_TABLE), claim, value,
        claim is PropertyClaim.EXACT,
        ComponentAnalysisProvenance("AES S-box", "fixed lookup evidence"),
    )


def test_component_radar_has_explicit_scales_evidence_and_omits_incomparable():
    results = (
        property_result(ComponentProperty.DIFFERENTIAL_UNIFORMITY, 4),
        property_result(ComponentProperty.NONLINEARITY, 112),
        property_result(ComponentProperty.ALGEBRAIC_DEGREE, 7),
        property_result(ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER, 5, PropertyClaim.PROVED_UPPER_BOUND),
        ComponentPropertyResult(
            PropertyRequest(ComponentProperty.BOOMERANG_UNIFORMITY, PropertyDomain.LOOKUP_TABLE),
            PropertyClaim.UNAVAILABLE, None, False,
            ComponentAnalysisProvenance("rectangular lookup", "applicability check"),
            PropertyDiagnostic(DiagnosticCode.INAPPLICABLE_DOMAIN, "requires a square bijection"),
        ),
    )
    scales = (
        RadarScale("differential_uniformity", PropertyDomain.LOOKUP_TABLE, 2, 16, NormalizationDirection.LOWER_IS_BETTER, "Differential uniformity"),
        RadarScale("nonlinearity", PropertyDomain.LOOKUP_TABLE, 0, 120, NormalizationDirection.HIGHER_IS_BETTER, "Nonlinearity"),
        RadarScale("algebraic_degree", PropertyDomain.LOOKUP_TABLE, 1, 8, NormalizationDirection.HIGHER_IS_BETTER, "Algebraic degree"),
    )
    artifact = MatplotlibPresentationDriver().component_radar("AES S-box", results, scales)
    axis = artifact.figure.axes[0]
    assert len(axis.lines) == 1
    assert tuple(axis.lines[0].get_ydata()) == artifact.series[0][1] + artifact.series[0][1][:1]
    assert any("exact" in label.get_text() for label in axis.get_xticklabels())
    assert artifact.omitted == (
        "differential_branch_number:no_normalization", "boomerang_uniformity:unavailable"
    )
    pyplot.close(artifact.figure)


def test_mixcolumns_radar_can_show_a_bound_without_claiming_exactness():
    provenance = ComponentAnalysisProvenance("AES MixColumns", "fixed field evidence")
    results = (
        ComponentPropertyResult(PropertyRequest(ComponentProperty.RANK, PropertyDomain.WORD_LINEAR), PropertyClaim.EXACT, 4, True, provenance),
        ComponentPropertyResult(PropertyRequest(ComponentProperty.MDS, PropertyDomain.WORD_LINEAR), PropertyClaim.EXACT, True, True, provenance),
        ComponentPropertyResult(PropertyRequest(ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER, PropertyDomain.WORD_LINEAR), PropertyClaim.PROVED_UPPER_BOUND, 5, False, provenance),
    )
    scales = (
        RadarScale("rank", PropertyDomain.WORD_LINEAR, 0, 4, NormalizationDirection.HIGHER_IS_BETTER, "Rank"),
        RadarScale("mds", PropertyDomain.WORD_LINEAR, 0, 1, NormalizationDirection.HIGHER_IS_BETTER, "MDS"),
        RadarScale("differential_branch_number", PropertyDomain.WORD_LINEAR, 1, 5, NormalizationDirection.HIGHER_IS_BETTER, "Differential branch"),
    )
    artifact = MatplotlibPresentationDriver().component_radar("AES MixColumns", results, scales)
    assert artifact.series[0][1] == (1.0, 1.0, 1.0)
    assert "proved_bound" in artifact.figure.axes[0].get_xticklabels()[2].get_text()
    pyplot.close(artifact.figure)


def test_avalanche_heatmap_structure_and_deterministic_series():
    result = AvalancheResult("speck", "plaintext", 4, 9, ((0.0, 0.5), (1.0, 0.25)))
    artifact = MatplotlibPresentationDriver().avalanche_matrix(result)
    axis = artifact.figure.axes[0]
    assert axis.get_xlabel() == "output bit (MSB first)"
    assert "empirical" in axis.get_title()
    assert artifact.series == (("input_bit_0", (0.0, 0.5)), ("input_bit_1", (1.0, 0.25)))
    pyplot.close(artifact.figure)


def test_statistical_figures_preserve_weak_and_unavailable_cases():
    dieharder = DieharderReport((
        DieharderObservation(1, "a", 0, 1, 1, 0.5, StatisticalAssessment.PASSED),
        DieharderObservation(2, "b", 0, 1, 1, 0.2, StatisticalAssessment.WEAK),
        DieharderObservation(3, "c", 0, 1, 1, 0.0, StatisticalAssessment.FAILED),
    ))
    driver = MatplotlibPresentationDriver()
    dieharder_artifact = driver.dieharder_assessments(dieharder)
    assert dieharder_artifact.series[0][1] == (1.0, 0.0, -1.0)
    pyplot.close(dieharder_artifact.figure)

    nist = NISTFinalReport((
        NISTSummaryRow("Frequency", "frequency", (1,) * 10, 0.5, 9, 10),
        NISTSummaryRow("Excursion", "excursion", (0,) * 10, None, 0, 0),
    ))
    nist_artifact = driver.nist_proportions(nist)
    assert nist_artifact.series[0][1] == (0.9,)
    assert nist_artifact.omitted == ("Excursion",)
    pyplot.close(nist_artifact.figure)


def test_renderer_module_import_is_lazy_about_matplotlib():
    code = "import sys; import claasp_next.drivers.renderers.presentation; print('matplotlib' in sys.modules)"
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    completed = subprocess.run(
        [sys.executable, "-c", code], text=True, capture_output=True, check=True, env=environment
    )
    assert completed.stdout.strip() == "False"
