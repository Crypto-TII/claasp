"""The committed public-catalogue capability matrix is executable evidence."""

import json
import os
import subprocess
import sys
from pathlib import Path

from claasp.primitives._catalogue_exports import ALL_EXPORTS

OUTPUT = Path("tests/fixtures/analysis/trail_search_capability_matrix.json")


def test_trail_search_capability_matrix_is_complete_and_current():
    committed = json.loads(Path(OUTPUT).read_text(encoding="utf-8"))
    environment = dict(os.environ, PYTHONPATH="src:.")
    subprocess.run(
        [sys.executable, "tools/trail_search_capability_matrix.py", "--check"],
        check=True,
        env=environment,
    )
    assert {row["primitive"] for row in committed["rows"]} == set(ALL_EXPORTS)
    assert all(
        row[kind] in {"model_constructed", "unsupported"}
        for row in committed["rows"]
        for kind in ("xor_differential", "xor_linear")
    )
    assert all(
        (row[f"{kind}_reason"] is None) == (row[kind] == "model_constructed")
        and (row[f"{kind}_limitation"] is None) == (row[kind] == "model_constructed")
        for row in committed["rows"]
        for kind in ("xor_differential", "xor_linear")
    )


def test_construction_evidence_does_not_claim_a_solver_run():
    committed = json.loads(OUTPUT.read_text())
    for row in committed["rows"]:
        for kind in ("xor_differential", "xor_linear"):
            if row[kind] == "model_constructed":
                evidence = row[f"{kind}_evidence"]
                assert evidence["model_constructed"]
                assert not evidence["formula_materialized"]
                assert not evidence["solver_executed"]
                assert not evidence["witness_independently_checked"]
