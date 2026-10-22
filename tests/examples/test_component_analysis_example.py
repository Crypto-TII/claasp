"""Execute both downloadable component-analysis examples in CI."""

import importlib.util
from io import StringIO
from pathlib import Path

import pytest

from claasp.analysis import PropertyClaim

ROOT = Path(__file__).resolve().parents[2] / "docs" / "examples"


def _script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_basic_script_groups_repeated_sboxes_and_reports_evidence():
    result = _script("basic_component_analysis").run_example()
    output = StringIO()
    result.to_terminal(file=output)
    sbox_index = next(
        index
        for index, group in enumerate(result.groups)
        if type(group.representative).__name__ == "BitVectorSBox"
    )
    assert result.groups[sbox_index].count == 34
    assert [item.value for item in result.properties[sbox_index]] == [4, 4, 3, True]
    assert "no default requests" in output.getvalue()
    assert "64 bits; mapping=" in output.getvalue()
    assert "80 bits; mapping=" in output.getvalue()
    assert "5 bits; value=0x1" in output.getvalue()
    assert "5 bits; value=0x2" in output.getvalue()
    assert "4 bits; table=" in output.getvalue()
    assert "exact" in output.getvalue()
    assert "round[" not in output.getvalue()
    detailed = StringIO()
    result.to_terminal(details=True, file=detailed)
    assert "round[" in detailed.getvalue()
    assert "Output position | Input position" in detailed.getvalue()
    assert "Group 2: BitVectorSBox — table" in detailed.getvalue()
    assert "Group 5: Constant — values" in detailed.getvalue()


def test_advanced_script_exact_ddt_bounded_search_and_composite_leaf(tmp_path):
    pytest.importorskip("matplotlib").use("Agg")
    pyplot = pytest.importorskip("matplotlib.pyplot")
    example = _script("component_analysis")
    selected, sbox, linear, bounded, column, ddt = example.run_example()
    assert selected.count == 34
    assert [item.value for item in sbox] == [4, 4, 3, True, 3, 2, 16]
    assert all(sum(row) == 16 for row in ddt.counts)
    assert max(max(row) for row in ddt.counts[1:]) == sbox[0].value
    assert [item.value for item in linear] == [16, True, None]
    assert linear[-1].diagnostic.code.value == "budget_exhausted"
    assert bounded[0].value == 5
    assert bounded[0].claim is PropertyClaim.PROVED_UPPER_BOUND
    assert not bounded[0].complete
    assert [item.value for item in column] == [4, True, True, 5, 5]
    assert all(item.claim is PropertyClaim.EXACT and item.complete for item in column)
    output = StringIO()
    bounded.to_terminal(file=output)
    assert "≤5" in output.getvalue()
    try:
        artifact = ddt.plot(show=False, save_to=tmp_path / "ddt.png")
        figure = pyplot.figure(artifact.figure)
        assert figure.axes[0].images[0].get_array().tolist() == [
            list(row) for row in ddt.counts[1:]
        ]
        assert (tmp_path / "ddt.png").read_bytes().startswith(b"\x89PNG")
    finally:
        pyplot.close("all")
