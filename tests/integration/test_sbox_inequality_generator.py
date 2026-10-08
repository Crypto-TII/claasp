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
UNDISTURBED_GENERATOR = ROOT / "tools" / "generate_undisturbed_sbox_milp_inequalities.py"
WORDWISE_GENERATOR = ROOT / "tools" / "generate_wordwise_milp_inequalities.py"
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
UNDISTURBED_BUNDLE = (
    ROOT
    / "src"
    / "claasp"
    / "representations"
    / "constraints"
    / "milp"
    / "data"
    / "present_sbox_undisturbed_inequalities.json"
)
WORDWISE_BUNDLE = (
    ROOT
    / "src"
    / "claasp"
    / "representations"
    / "constraints"
    / "milp"
    / "data"
    / "wordwise_4bit_xor2_mds4x4_inequalities.json"
)


def _satisfies(inequalities, point):
    return all(
        inequality[0]
        + sum(coefficient * value for coefficient, value in zip(inequality[1:], point, strict=True))
        >= 0
        for inequality in inequalities
    )


def test_cddlib_glpk_generator_reproduces_present_facets_and_minimum_sizes(tmp_path):
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
    expected = json.loads(BUNDLE.read_text(encoding="utf-8"))
    assert {key: value for key, value in payload.items() if key != "systems"} == {
        key: value for key, value in expected.items() if key != "systems"
    }
    for generated_system, expected_system in zip(
        payload["systems"], expected["systems"], strict=True
    ):
        assert generated_system["kind"] == expected_system["kind"]
        for generated_group, expected_group in zip(
            generated_system["groups"], expected_system["groups"], strict=True
        ):
            assert generated_group["transition_count"] == expected_group["transition_count"]
            assert generated_group["point_count"] == expected_group["point_count"]
            generated_inequalities = generated_group["inequalities"]
            expected_inequalities = expected_group["inequalities"]
            assert generated_inequalities["convex_hull"] == expected_inequalities["convex_hull"]
            assert generated_inequalities["greedy"] == expected_inequalities["greedy"]
            assert len(generated_inequalities["minimum"]) == len(expected_inequalities["minimum"])
            assert all(
                inequality in generated_inequalities["convex_hull"]
                for inequality in generated_inequalities["minimum"]
            )
            points = (
                tuple((value >> bit) & 1 for bit in reversed(range(8))) for value in range(1 << 8)
            )
            assert all(
                _satisfies(generated_inequalities["minimum"], point)
                == _satisfies(generated_inequalities["convex_hull"], point)
                for point in points
            )
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


def test_espresso_generator_reproduces_present_undisturbed_bundle(tmp_path):
    assert shutil.which("espresso") is not None, "the external toolchain must install Espresso"
    generated = tmp_path / "present-undisturbed.json"
    subprocess.run(
        [
            sys.executable,
            str(UNDISTURBED_GENERATOR),
            "--name",
            "present",
            "--table",
            PRESENT,
            "--output",
            str(generated),
        ],
        check=True,
    )

    assert json.loads(generated.read_text(encoding="utf-8")) == json.loads(
        UNDISTURBED_BUNDLE.read_text(encoding="utf-8")
    )


def test_espresso_generator_reproduces_wordwise_bundle(tmp_path):
    assert shutil.which("espresso") is not None, "the external toolchain must install Espresso"
    generated = tmp_path / "wordwise.json"
    subprocess.run(
        [sys.executable, str(WORDWISE_GENERATOR), "--output", str(generated)], check=True
    )
    assert json.loads(generated.read_text(encoding="utf-8")) == json.loads(
        WORDWISE_BUNDLE.read_text(encoding="utf-8")
    )
