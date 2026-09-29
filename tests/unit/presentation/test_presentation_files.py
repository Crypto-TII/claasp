import builtins
import json

import pytest

from claasp.analysis.avalanche import AvalancheResult
from claasp.presentation import (
    Citation,
    MathematicalProvenance,
    PresentationProvenance,
    PrimitiveProvenance,
    ReportSection,
    Table,
    TableColumn,
    TableRow,
    compose_report,
    present,
    render_report,
    to_dataframe,
    write_report,
)


def fixed_report():
    table = Table((TableColumn("name", "Name"),), (TableRow.of("café"),), "Values")
    section = ReportSection(
        "Summary", tables=(table,), citations=(Citation("spec", "Fixed specification", "§1"),)
    )
    provenance = PresentationProvenance(
        MathematicalProvenance("fixed evidence", ("publication",), ("fixture-1",)),
        primitive=PrimitiveProvenance("present", "lookup"),
        citations=(Citation("paper", "Trail paper", "Table 2"),),
    )
    return compose_report("Résumé", (section,), provenance)


def test_present_only_adapts_an_existing_result():
    source = AvalancheResult("demo", "input", 2, 7, ((0.0, 1.0),))
    report = present(source)
    assert report.sections[0].tables[0].rows[2].cells[1].text == "2"
    assert report.provenance.mathematical.method == "empirical_paired_evaluation"
    with pytest.raises(TypeError, match="unsupported_result"):
        present(object())


def test_human_report_contains_citations_and_separate_provenance():
    markdown = render_report(fixed_report(), format="markdown")
    assert "[spec] Fixed specification (§1)" in markdown
    assert "method: fixed evidence" in markdown
    assert "primitive: present" in markdown
    assert "realization: lookup" in markdown
    assert "citation [paper]: Trail paper (Table 2)" in markdown


def test_safe_writes_validate_extensions_utf8_newlines_and_overwrite(tmp_path):
    report = fixed_report()
    destination = tmp_path / "report.md"
    written = write_report(report, destination, format="markdown")
    raw = destination.read_bytes()
    assert written.path == destination
    assert written.byte_count == len(raw)
    assert "Résumé" in raw.decode("utf-8")
    assert b"\r\n" not in raw
    with pytest.raises(FileExistsError):
        write_report(report, destination, format="markdown")
    write_report(report, destination, format="markdown", overwrite=True)
    with pytest.raises(ValueError, match=".json extension"):
        write_report(report, tmp_path / "wrong.txt", format="json")
    with pytest.raises(ValueError, match="must not contain"):
        write_report(report, tmp_path / ".." / "escape.json", format="json")


def test_json_and_csv_files_are_explicit_report_exports(tmp_path):
    report = fixed_report()
    json_path = tmp_path / "report.json"
    csv_path = tmp_path / "report.csv"
    write_report(report, json_path, format="json")
    write_report(report, csv_path, format="csv")
    assert json.loads(json_path.read_text(encoding="utf-8"))["title"] == "Résumé"
    assert csv_path.read_text(encoding="utf-8") == "Name\ncafé\n"


def test_parent_creation_is_opt_in_and_uses_the_explicit_path(tmp_path):
    destination = tmp_path / "explicit" / "nested" / "report.txt"
    with pytest.raises(FileNotFoundError):
        write_report(fixed_report(), destination, format="terminal")
    written = write_report(fixed_report(), destination, format="terminal", create_parents=True)
    assert written.path == destination


def test_optional_dataframe_matches_display_text_or_reports_missing_dependency(monkeypatch):
    table = fixed_report().sections[0].tables[0]
    try:
        frame = to_dataframe(table)
    except ImportError:
        frame = None
    if frame is not None:
        assert frame.to_dict(orient="records") == [{"Name": "café"}]
    original_import = builtins.__import__

    # The replacement mirrors the built-in import hook's required signature.
    def missing_pandas(
        name,
        globals=None,  # noqa: A002 - built-in import hook signature
        locals=None,  # noqa: A002 - built-in import hook signature
        fromlist=(),
        level=0,
    ):
        if name == "pandas":
            raise ImportError("missing")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", missing_pandas)
    with pytest.raises(ImportError, match="optional pandas"):
        to_dataframe(table)
