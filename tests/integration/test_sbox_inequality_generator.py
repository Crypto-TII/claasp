"""External parity for the Sage-free S-box inequality orchestrator."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.external

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "tools" / "generate_sbox_milp_inequalities.py"
BUNDLE = (
    ROOT
    / "src"
    / "claasp"
    / "representations"
    / "constraints"
    / "milp"
    / "data"
    / "present_sbox_milp_inequalities.json"
)
PRESENT = "12,5,6,11,9,0,10,13,3,14,15,8,4,7,1,2"


def test_cddlib_glpk_generator_reproduces_present_bundle(tmp_path):
    assert shutil.which("cddexec_gmp") is not None, (
        "the external test job must install libcdd-tools"
    )
    assert shutil.which("glpsol") is not None, "the external test job must install GLPK"
    generated = tmp_path / "present.json"
    subprocess.run(
        [
            sys.executable,
            str(GENERATOR),
            "--name",
            "present",
            "--table",
            PRESENT,
            "--output",
            str(generated),
        ],
        check=True,
    )

    payload = json.loads(generated.read_text(encoding="utf-8"))
    assert payload == json.loads(BUNDLE.read_text(encoding="utf-8"))
    counts = {
        system["kind"]: {
            strategy: sum(len(group["inequalities"][strategy]) for group in system["groups"])
            for strategy in ("convex_hull", "greedy", "minimum")
        }
        for system in payload["systems"]
    }
    assert counts == {
        "xor_differential": {"convex_hull": 498, "greedy": 30, "minimum": 25},
        "xor_linear": {"convex_hull": 1057, "greedy": 47, "minimum": 39},
    }
