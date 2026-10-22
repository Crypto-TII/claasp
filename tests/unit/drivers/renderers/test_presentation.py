import os
import subprocess
import sys

import pytest

matplotlib = pytest.importorskip("matplotlib")
matplotlib.use("Agg")
from matplotlib import pyplot

from claasp.analysis import (
    ComponentProperty,
    ComponentPropertyResult,
    PropertyClaim,
    PropertyDomain,
    PropertyRequest,
)
from claasp.analysis.avalanche import AvalancheResult
from claasp.analysis.component_properties import (
    ComponentAnalysisProvenance,
    DiagnosticCode,
    PropertyDiagnostic,
)
from claasp.analysis.statistical_results import (
    DieharderObservation,
    DieharderReport,
    NISTFinalReport,
    NISTSummaryRow,
    StatisticalAssessment,
)
from claasp.drivers.renderers import (
    MatplotlibPresentationDriver,
    NormalizationDirection,
    RadarScale,
)


def property_result(prop, value, claim=PropertyClaim.EXACT):
    return ComponentPropertyResult(
        PropertyRequest(prop, PropertyDomain.LOOKUP_TABLE),
        claim,
        value,
        claim is PropertyClaim.EXACT,
        ComponentAnalysisProvenance("AES S-box", "fixed lookup evidence"),
    )


def test_component_radar_has_explicit_scales_evidence_and_omits_incomparable():
    results = (
        property_result(ComponentProperty.DIFFERENTIAL_UNIFORMITY, 4),
        property_result(ComponentProperty.NONLINEARITY, 112),
        property_result(ComponentProperty.ALGEBRAIC_DEGREE, 7),
        property_result(
            ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER, 5, PropertyClaim.PROVED_UPPER_BOUND
        ),
        ComponentPropertyResult(
            PropertyRequest(ComponentProperty.BOOMERANG_UNIFORMITY, PropertyDomain.LOOKUP_TABLE),
            PropertyClaim.UNAVAILABLE,
            None,
            False,
            ComponentAnalysisProvenance("rectangular lookup", "applicability check"),
            PropertyDiagnostic(DiagnosticCode.INAPPLICABLE_DOMAIN, "requires a square bijection"),
        ),
    )
    scales = (
        RadarScale(
            "differential_uniformity",
            PropertyDomain.LOOKUP_TABLE,
            2,
            16,
            NormalizationDirection.LOWER_IS_BETTER,
            "Differential uniformity",
        ),
        RadarScale(
            "nonlinearity",
            PropertyDomain.LOOKUP_TABLE,
            0,
            120,
            NormalizationDirection.HIGHER_IS_BETTER,
            "Nonlinearity",
        ),
        RadarScale(
            "algebraic_degree",
            PropertyDomain.LOOKUP_TABLE,
            1,
            8,
            NormalizationDirection.HIGHER_IS_BETTER,
            "Algebraic degree",
        ),
    )
    artifact = MatplotlibPresentationDriver().component_radar("AES S-box", results, scales)
    axis = artifact.figure.axes[0]
    assert len(axis.lines) == 1
    assert tuple(axis.lines[0].get_ydata()) == artifact.series[0][1] + artifact.series[0][1][:1]
    assert any("exact" in label.get_text() for label in axis.get_xticklabels())
    assert artifact.omitted == (
        "differential_branch_number:no_normalization",
        "boomerang_uniformity:unavailable",
    )
    pyplot.close(artifact.figure)


def test_mixcolumns_radar_can_show_a_bound_without_claiming_exactness():
    provenance = ComponentAnalysisProvenance("AES MixColumns", "fixed field evidence")
    results = (
        ComponentPropertyResult(
            PropertyRequest(ComponentProperty.RANK, PropertyDomain.WORD_LINEAR),
            PropertyClaim.EXACT,
            4,
            True,
            provenance,
        ),
        ComponentPropertyResult(
            PropertyRequest(ComponentProperty.MDS, PropertyDomain.WORD_LINEAR),
            PropertyClaim.EXACT,
            True,
            True,
            provenance,
        ),
        ComponentPropertyResult(
            PropertyRequest(
                ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER, PropertyDomain.WORD_LINEAR
            ),
            PropertyClaim.PROVED_UPPER_BOUND,
            5,
            False,
            provenance,
        ),
    )
    scales = (
        RadarScale(
            "rank",
            PropertyDomain.WORD_LINEAR,
            0,
            4,
            NormalizationDirection.HIGHER_IS_BETTER,
            "Rank",
        ),
        RadarScale(
            "mds", PropertyDomain.WORD_LINEAR, 0, 1, NormalizationDirection.HIGHER_IS_BETTER, "MDS"
        ),
        RadarScale(
            "differential_branch_number",
            PropertyDomain.WORD_LINEAR,
            1,
            5,
            NormalizationDirection.HIGHER_IS_BETTER,
            "Differential branch",
        ),
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
    dieharder = DieharderReport(
        (
            DieharderObservation(1, "a", 0, 1, 1, 0.5, StatisticalAssessment.PASSED),
            DieharderObservation(2, "b", 0, 1, 1, 0.2, StatisticalAssessment.WEAK),
            DieharderObservation(3, "c", 0, 1, 1, 0.0, StatisticalAssessment.FAILED),
        )
    )
    driver = MatplotlibPresentationDriver()
    dieharder_artifact = driver.dieharder_assessments(dieharder)
    assert dieharder_artifact.series[0][1] == (1.0, 0.0, -1.0)
    pyplot.close(dieharder_artifact.figure)

    nist = NISTFinalReport(
        (
            NISTSummaryRow("Frequency", "frequency", (1,) * 10, 0.5, 9, 10),
            NISTSummaryRow("Excursion", "excursion", (0,) * 10, None, 0, 0),
        )
    )
    nist_artifact = driver.nist_proportions(nist)
    assert nist_artifact.series[0][1] == (0.9,)
    assert nist_artifact.omitted == ("Excursion",)
    pyplot.close(nist_artifact.figure)


def test_renderer_module_import_is_lazy_about_matplotlib():
    code = "import sys; import claasp.drivers.renderers.presentation; print('matplotlib' in sys.modules)"
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    completed = subprocess.run(
        [sys.executable, "-c", code], text=True, capture_output=True, check=True, env=environment
    )
    assert completed.stdout.strip() == "False"


def test_avalanche_plot_defaults_to_display_and_can_save_headlessly(monkeypatch, tmp_path):
    result = AvalancheResult("fixture", "plaintext", 2, 9, ((0.0, 0.5), (1.0, 0.5)))
    calls = []
    monkeypatch.setattr(pyplot, "show", lambda: calls.append("display"))
    try:
        artifact = result.plot()
        assert calls == ["display"]
        assert artifact.kind == "avalanche_summary"
        assert artifact.series == (
            ("minimum", (0.0,)),
            ("maximum", (1.0,)),
            ("average", (0.5,)),
            ("lower_threshold", (0.49,)),
            ("upper_threshold", (0.51,)),
        )
        assert pyplot.gcf() is artifact.figure
        assert pyplot.gcf().axes[0].get_xlabel() == "Rounds"
        path = tmp_path / "avalanche.png"
        saved = result.plot(show=False, save_to=path)
        assert calls == ["display"]
        assert path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
        assert saved.series == artifact.series
        result.plot(save_to=tmp_path / "displayed.png")
        assert calls == ["display", "display"]
    finally:
        pyplot.close("all")


def test_avalanche_plot_explains_missing_optional_dependency(monkeypatch):
    import builtins

    original_import = builtins.__import__

    def without_matplotlib(name, *args, **kwargs):
        if name == "matplotlib":
            raise ImportError("not installed")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_matplotlib)
    result = AvalancheResult("fixture", "plaintext", 2, 9, ((0.5,),))
    with pytest.raises(ImportError, match="presentation"):
        result.plot(show=False)


@pytest.mark.parametrize("metric", ["probability", "entropy", "weight"])
@pytest.mark.parametrize("view", ["summary", "heatmap", "3d"])
def test_avalanche_round_views_preserve_values_colors_and_opaque_planes(view, metric):
    from claasp.analysis.avalanche import _round_profiles

    first = ((0.0, 0.5), (1.0, 0.5))
    final = ((0.25, 0.5), (0.75, 0.5))
    result = AvalancheResult(
        "fixture",
        "plaintext",
        4,
        9,
        final,
        round_probabilities=(first, final),
        round_numbers=(1, 2),
    )
    try:
        artifact = result.plot(view=view, metric=metric, show=False)
        axis = pyplot.gcf().axes[0]
        assert artifact.kind == f"avalanche_{view}"
        if view == "summary":
            expected_minimum = (
                (0.0, 0.25) if metric != "entropy" else (0.0, pytest.approx(0.8112781244591328))
            )
            assert artifact.series[0][1] == expected_minimum
            assert artifact.series[-2][0] == "lower_threshold"
        else:
            profiles = _round_profiles(result, metric)
            assert artifact.series == (("round_1", profiles[0]), ("round_2", profiles[1]))
            if view == "heatmap":
                image = axis.images[0]
                assert image.get_clim() == (0, 1)
                assert image.to_rgba(1.0 if metric == "entropy" else 0.5) == pyplot.get_cmap(
                    "RdYlGn"
                )(1.0)
            else:
                planes = [
                    item for item in axis.collections if type(item).__name__ == "Poly3DCollection"
                ]
                assert len(planes) == 2
                assert all(item.get_alpha() == 1 for item in planes)
                assert all(color[-1] == 1 for item in planes for color in item.get_facecolors())
                for plane, profile in zip(planes, profiles, strict=True):
                    expected_colors = sorted(
                        tuple(
                            pyplot.get_cmap("RdYlGn")(
                                value if metric == "entropy" else 1 - abs(2 * value - 1)
                            )
                        )
                        for value in profile
                    )
                    assert (
                        sorted(tuple(color) for color in plane.get_facecolors()) == expected_colors
                    )

                points = [
                    item for item in axis.collections if type(item).__name__ == "Path3DCollection"
                ]
                assert len(points) == 2
                assert points[0].to_rgba(1.0 if metric == "entropy" else 0.5) == pyplot.get_cmap(
                    "RdYlGn"
                )(1.0)
                if metric != "entropy":
                    for probability in (0, 0.125, 0.25, 0.375, 0.5, 0.75, 1.0):
                        assert points[0].to_rgba(float(probability)) == pyplot.get_cmap("RdYlGn")(
                            1 - abs(2 * probability - 1)
                        )
    finally:
        pyplot.close("all")


def test_avalanche_plot_rejects_unknown_views_and_metrics():
    result = AvalancheResult("fixture", "plaintext", 2, 9, ((0.5,),))
    with pytest.raises(ValueError, match="view"):
        result.plot(view="unknown", show=False)
    with pytest.raises(ValueError, match="metric"):
        result.plot(metric="unknown", show=False)


@pytest.mark.parametrize("style", ["dots", "planes"])
def test_3d_round_order_and_heights_survive_camera_rotation(style):
    matrices = tuple(((value, value),) for value in (0.1, 0.3, 0.4, 0.5))
    result = AvalancheResult(
        "fixture",
        "plaintext",
        10,
        9,
        matrices[-1],
        round_probabilities=matrices,
        round_numbers=(1, 2, 3, 4),
    )
    try:
        artifact = result.plot(view="3d", style=style, show=False)
        figure = pyplot.gcf()
        axis = figure.axes[0]
        assert artifact.series == tuple(
            (f"round_{i}", (value, value)) for i, value in enumerate((0.1, 0.3, 0.4, 0.5), 1)
        )
        assert axis.get_zlim() == (0, 1)
        points = [item for item in axis.collections if type(item).__name__ == "Path3DCollection"]
        assert len(points) == 4
        assert all(tuple(item.get_sizes()) == (3,) for item in points)
        if style == "dots":
            assert len(axis.lines) == 4
            assert all(tuple(line.get_data_3d()[2]) == (0, 0) for line in axis.lines)
        figure.canvas.draw()
        # At the default camera, round 1 is nearest, so it must draw last.
        bases = [entry[1] for entry in axis._round_artists]
        orders = [item.get_zorder() for item in bases]
        assert orders == sorted(orders, reverse=True)
        assert all(
            dot.get_zorder() == base.get_zorder() + 1
            for base, dot in zip(bases, points, strict=True)
        )
        axis.view_init(azim=60)
        figure.canvas.draw()
        # Looking from the opposite side reverses the exact plane order.
        orders = [item.get_zorder() for item in bases]
        assert orders == sorted(orders)
        axis.view_init(elev=150, azim=-60)
        figure.canvas.draw()
        orders = [item.get_zorder() for item in bases]
        assert orders == sorted(orders)
    finally:
        pyplot.close("all")


def test_avalanche_plot_rejects_unknown_3d_style():
    result = AvalancheResult("fixture", "plaintext", 2, 9, ((0.5,),))
    with pytest.raises(ValueError, match="style"):
        result.plot(view="3d", style="unknown", show=False)
