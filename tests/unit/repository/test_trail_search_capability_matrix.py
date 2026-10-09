"""The committed public-catalogue capability matrix is executable evidence."""

import json
import os
import subprocess
import sys
from pathlib import Path

from claasp.primitives._catalogue_exports import ALL_EXPORTS

OUTPUT = Path("docs/architecture/audits/data/trail-search-capability-matrix.json")


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
        row[kind] in {"supported_and_tested", "unsupported"}
        for row in committed["rows"]
        for kind in ("xor_differential", "xor_linear")
    )
    assert all(
        (row[f"{kind}_reason"] is None) == (row[kind] == "supported_and_tested")
        and (row[f"{kind}_limitation"] is None) == (row[kind] == "supported_and_tested")
        for row in committed["rows"]
        for kind in ("xor_differential", "xor_linear")
    )
