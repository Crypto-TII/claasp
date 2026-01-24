#!/usr/bin/env python3
"""Run NIST STS assess on fixed datasets and parse results.

This script:
- Runs sts-2.1.2-modified/assess over datasets
- Copies AlgorithmTesting output into statistical_tests_results/<dataset>
- Writes inputs.json and parsed results.json (no raw txt)
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
TEST_DATA_DIR = SCRIPT_DIR.parent
DATASETS_DIR = TEST_DATA_DIR / "datasets"
RESULTS_DIR = TEST_DATA_DIR / "statistical_tests_results"
CONFIG_PATH = SCRIPT_DIR / "assess_config.json"


def _find_sts_dir() -> Path:
    candidates = [
        Path.home() / "sts-2.1.2-modified",
        Path("/usr/local/sts-2.1.2-modified"),
        TEST_DATA_DIR.parent.parent.parent.parent.parent / "sts-2.1.2-modified",
    ]
    for path in candidates:
        if (path / "assess").exists():
            return path
    raise FileNotFoundError("Could not find sts-2.1.2-modified with assess binary")


def _run_assess(sts_dir: Path, dataset_path: Path, params: dict) -> None:
    cmd = [
        "./assess",
        "-l", str(params["bit_length"]),
        "-n", str(params["num_sequences"]),
        "-i", str(params["input_format"]),
        "-f", str(dataset_path.resolve()),
        "-g", "0",
        "-t", params["tests"],
        "--nonoverlap", str(params.get("nonoverlap", 9)),
        "--overlap", str(params.get("overlap", 9)),
    ]

    subprocess.run(cmd, cwd=sts_dir, check=True, capture_output=True, text=True)


def _parse_final_report(report_text: str) -> dict:
    lines = report_text.strip().split("\n")
    tests = []
    nonoverlap_idx = 0

    table_start = None
    for i, line in enumerate(lines):
        if "C1  C2  C3  C4  C5  C6  C7  C8  C9 C10  P-VALUE  PROPORTION  STATISTICAL TEST" in line:
            table_start = i + 2
            break

    if table_start is None:
        return {"tests": []}

    for line in lines[table_start:]:
        if line.startswith("-") or not line.strip():
            break
        parts = line.split()
        if len(parts) < 14:
            continue
        try:
            bin_counts = [int(parts[i]) for i in range(10)]
            p_value = float(parts[10].replace("*", ""))
            proportion_parts = parts[11].replace("*", "").split("/")
            passed_sequences = int(proportion_parts[0])
            total_sequences = int(proportion_parts[1])
            test_name = " ".join(parts[12:]).lstrip("*").strip()

            if test_name in {"NonOverlappingTemplate", "Non Overlapping Template"}:
                test_name = f"{test_name}_{nonoverlap_idx}"
                nonoverlap_idx += 1

            tests.append({
                "test_name": test_name,
                "bin_counts": bin_counts,
                "uniformity_p_value": p_value,
                "passed_sequences": passed_sequences,
                "total_sequences": total_sequences,
                "proportion": passed_sequences / total_sequences if total_sequences else 0.0,
            })
        except (ValueError, IndexError):
            continue

    return {"tests": tests}


def _parse_results_txt(results_text: str) -> list[float]:
    p_values: list[float] = []
    lines = [line.strip() for line in results_text.splitlines() if line.strip()]
    if not lines:
        return p_values

    in_table = False
    for line in lines:
        if "P-VALUES FOR EACH SEQUENCE" in line:
            in_table = True
            continue
        if in_table and line.startswith("---"):
            continue
        if in_table:
            parts = line.split()
            if len(parts) >= 2:
                try:
                    p_values.append(float(parts[1]))
                except ValueError:
                    pass
        else:
            # try numeric line or second token numeric
            parts = line.split()
            for token in parts:
                try:
                    p_values.append(float(token))
                    break
                except ValueError:
                    continue
    return p_values


def _extract_parameters(stats_text: str) -> dict:
    params = {}
    for line in stats_text.splitlines():
        for match in re.finditer(r"([A-Za-z][A-Za-z0-9_]+)\s*=\s*([-+]?[0-9]*\.?[0-9]+)", line):
            key, val = match.group(1), match.group(2)
            if "." in val:
                params[key] = float(val)
            else:
                params[key] = int(val)
    return params


def _parse_nonoverlap_stats(stats_text: str) -> dict:
    sequences = []
    current = None
    in_table = False

    for line in stats_text.splitlines():
        if "NONPERIODIC TEMPLATES TEST" in line:
            if current is not None:
                sequences.append(current)
            current = {"parameters": {}, "templates": []}
            in_table = False
            continue
        if current is None:
            continue

        if "LAMBDA" in line and "M" in line and "N" in line and "m" in line and "n" in line:
            current["parameters"].update(_extract_parameters(line))
            continue

        if line.strip().startswith("Template"):
            in_table = True
            continue

        if in_table:
            if not line.strip() or line.strip().startswith("-"):
                in_table = False
                continue
            parts = line.split()
            if len(parts) >= 12:
                tmpl = parts[0]
                w_counts = [int(v) for v in parts[1:9]]
                chi_sq = float(parts[9])
                p_val = float(parts[10])
                assignment = parts[11]
                index = int(parts[12]) if len(parts) > 12 else None
                current["templates"].append({
                    "template": tmpl,
                    "w_counts": w_counts,
                    "chi_squared": chi_sq,
                    "p_value": p_val,
                    "assignment": assignment,
                    "index": index,
                })

    if current is not None:
        sequences.append(current)

    return {"sequences": sequences}


def _parse_stats_txt(test_name: str, stats_text: str) -> dict:
    parsed = {"parameters": _extract_parameters(stats_text)}
    if test_name in {"NonOverlappingTemplate", "Non Overlapping Template"}:
        parsed.update(_parse_nonoverlap_stats(stats_text))
    return parsed


def _collect_results(case_dir: Path, algorithm_dir: Path) -> dict:
    final_report_path = algorithm_dir / "finalAnalysisReport.txt"
    final_report_text = final_report_path.read_text()
    parsed_final = _parse_final_report(final_report_text)

    test_details = {}
    for test_dir in algorithm_dir.iterdir():
        if not test_dir.is_dir():
            continue
        test_name = test_dir.name
        detail = {}

        results_file = test_dir / "results.txt"
        if results_file.exists():
            detail["p_values"] = _parse_results_txt(results_file.read_text())

        stats_file = test_dir / "stats.txt"
        if stats_file.exists():
            detail["stats"] = _parse_stats_txt(test_name, stats_file.read_text())

        if detail:
            test_details[test_name] = detail

    return {
        "final_report_parsed": parsed_final,
        "test_details": test_details,
    }


def _write_inputs(case_dir: Path, params: dict, dataset_path: Path) -> None:
    inputs = {
        "name": params["name"],
        "dataset_file": str(dataset_path.resolve()),
        "bit_length": params["bit_length"],
        "num_sequences": params["num_sequences"],
        "assess_params": {
            "tests": params["tests"],
            "input_format": params["input_format"],
            "nonoverlap": params.get("nonoverlap", 9),
            "overlap": params.get("overlap", 9),
        },
        "data_format": "ascii" if params["input_format"] == 0 else "binary",
    }

    with (case_dir / "inputs.json").open("w") as f:
        json.dump(inputs, f, indent=2)


def _load_config() -> list[dict]:
    with CONFIG_PATH.open("r") as f:
        config = json.load(f)
    return config["assess_runs"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run sts-2.1.2-modified assess over fixed datasets.")
    parser.add_argument("--name", help="Run a single dataset by name")
    args = parser.parse_args()

    sts_dir = _find_sts_dir()
    runs = _load_config()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    selected = [r for r in runs if args.name is None or r["name"] == args.name]
    if not selected:
        raise SystemExit(f"Dataset '{args.name}' not found in config.")

    for params in selected:
        dataset_path = DATASETS_DIR / params["dataset_file"]
        if not dataset_path.exists():
            raise FileNotFoundError(f"Missing dataset: {dataset_path}")

        _run_assess(sts_dir, dataset_path, params)

        case_dir = RESULTS_DIR / params["name"]
        if case_dir.exists():
            shutil.rmtree(case_dir)
        case_dir.mkdir(parents=True)

        algorithm_dir = sts_dir / "experiments" / "AlgorithmTesting"
        shutil.copytree(algorithm_dir, case_dir / "AlgorithmTesting")

        _write_inputs(case_dir, params, dataset_path)
        results = _collect_results(case_dir, case_dir / "AlgorithmTesting")
        with (case_dir / "results.json").open("w") as f:
            json.dump(results, f, indent=2)

        print(f"Generated results for {params['name']}")

    index = {
        "description": "NIST STS Test Cases for Python Implementation Validation",
        "test_cases": [{"name": r["name"]} for r in runs],
        "sts_version": "sts-2.1.2-modified",
    }
    with (RESULTS_DIR / "index.json").open("w") as f:
        json.dump(index, f, indent=2)


if __name__ == "__main__":
    main()
