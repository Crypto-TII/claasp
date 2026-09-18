import json
import os
import subprocess
import sys

import pytest

from claasp_next.presentation import (
    Alignment,
    DiagnosticCode,
    EvidenceClass,
    FormatSpec,
    PresentationDiagnostic,
    PresentationEvidence,
    Table,
    TableCell,
    TableColumn,
    TableRow,
    ValueKind,
    format_value,
)


def test_deterministic_scalar_and_vector_formatting():
    assert format_value(42, FormatSpec(ValueKind.INTEGER)) == "42"
    assert format_value(10, FormatSpec(ValueKind.HEXADECIMAL, bit_width=8)) == "0x0a"
    assert format_value((1, 0, 1, 1), FormatSpec(ValueKind.BIT_VECTOR)) == "0b1011"
    assert format_value((1, 15), FormatSpec(ValueKind.WORD_VECTOR, word_width=4)) == "[0x1, 0xf]"
    assert format_value(1 / 8, FormatSpec(ValueKind.PROBABILITY)) == "0.125"
    assert format_value(-0.25, FormatSpec(ValueKind.CORRELATION)) == "-0.25"
    assert format_value(0.25, FormatSpec(ValueKind.CORRELATION)) == "+0.25"
    assert format_value(float("inf"), FormatSpec(ValueKind.WEIGHT)) == "infinity"
    assert format_value(True, FormatSpec(ValueKind.BOOLEAN)) == "true"
    assert format_value(None) == "—"


def test_bounds_and_multiline_diagnostics_remain_typed():
    upper = PresentationEvidence(
        EvidenceClass.PROVED_BOUND, complete=False, bound_direction="upper"
    )
    assert TableCell(5, FormatSpec(ValueKind.INTEGER), upper).text == "≤5"
    diagnostic = PresentationDiagnostic(
        DiagnosticCode.OPTIONAL_DEPENDENCY_UNAVAILABLE,
        "Matplotlib missing\ninstall the plot extra",
    )
    assert TableCell(diagnostic=diagnostic).text.endswith("missing\ninstall the plot extra")


def test_tables_validate_shape_and_preserve_declared_order():
    columns = (
        TableColumn("property", "Property"),
        TableColumn("value", "Value", Alignment.RIGHT),
    )
    table = Table(columns, (TableRow.of("rank", "8"), TableRow.of("mds", "true")))
    assert [column.key for column in table.columns] == ["property", "value"]
    assert [row.cells[0].text for row in table.rows] == ["rank", "mds"]
    with pytest.raises(ValueError, match="one cell per column"):
        Table(columns, (TableRow.of("rank"),))


def test_invalid_format_values_fail_instead_of_using_object_repr():
    with pytest.raises(TypeError, match="text cells"):
        format_value(object())
    with pytest.raises(ValueError, match="fit bit_width"):
        format_value(256, FormatSpec(ValueKind.HEXADECIMAL, bit_width=8))
    with pytest.raises(ValueError, match="between -1 and 1"):
        format_value(1.1, FormatSpec(ValueKind.PROBABILITY))


def test_core_presentation_import_does_not_load_optional_packages():
    code = """
import json, sys
before = set(sys.modules)
import claasp_next.presentation
print(json.dumps(sorted(name for name in set(sys.modules) - before if name.split('.')[0] in {
    'matplotlib', 'pandas', 'numpy', 'sklearn', 'sage'
})))
"""
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [sys.executable, "-c", code], check=True, text=True, capture_output=True, env=environment
    )
    assert json.loads(completed.stdout) == []
