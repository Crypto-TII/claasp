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
        row[kind] in {"supported_and_tested", "unsupported", "intentionally_out_of_scope"}
        for row in committed["rows"]
        for kind in ("xor_differential", "xor_linear")
    )
