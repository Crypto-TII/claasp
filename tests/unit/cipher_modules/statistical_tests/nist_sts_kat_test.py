# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ****************************************************************************

import math
import os
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import numpy as np
import pytest

from claasp.cipher_modules.statistical_tests.nist_sts import (
    NISTTests,
    parse_final_analysis_report,
    parse_nist_stats,
    _detect_nist_skip_reason,
    _normalize_test_name,
    _stats_indicates_not_applicable,
)


DATASETS = [
    {
        "name": "random_binary_10240bits.bin",
        "bits_per_sequence": 1000,
        "num_sequences": 10,
    },
    {
        "name": "random_binary_400000bits.bin",
        "bits_per_sequence": 400000,
        "num_sequences": 1,
    },
    {
        "name": "random_binary_10240bits.txt",
        "bits_per_sequence": 1000,
        "num_sequences": 10,
        "fixed_num_sequences": True,
        "text": True,
    },
    {
        "name": "alternating_bits_binary_10240bits.bin",
        "bits_per_sequence": 1000,
        "num_sequences": 10,
        "fixed_num_sequences": True,
    },
    {
        "name": "alternating_128-bits-blocks_binary_10240bits.bin",
        "bits_per_sequence": 1000,
        "num_sequences": 10,
        "fixed_num_sequences": True,
    },
]

TEST_CONFIGS: List[Dict[str, Any]] = [
    {"name": "frequency", "folder": "Frequency", "per_sequence": 1},
    {"name": "block_frequency", "folder": "BlockFrequency", "per_sequence": 1},
    {
        "name": "cumulative_sums_forward",
        "folder": "CumulativeSums",
        "display_name": "CumulativeSums[mode=0]",
        "per_sequence": 1,
        "table_parser": "cumulative_sums",
        "direction": "forward",
    },
    {
        "name": "cumulative_sums_backward",
        "folder": "CumulativeSums",
        "display_name": "CumulativeSums[mode=1]",
        "per_sequence": 1,
        "table_parser": "cumulative_sums",
        "direction": "backward",
    },
    {"name": "runs", "folder": "Runs", "per_sequence": 1},
    {"name": "longest_run", "folder": "LongestRun", "per_sequence": 1},
    {"name": "rank", "folder": "Rank", "per_sequence": 1},
    {"name": "dft", "folder": "FFT", "per_sequence": 1},
    {
        "name": "non_overlapping_template",
        "folder": "NonOverlappingTemplate",
        "per_sequence": None,
        "table_parser": "non_overlapping_template",
    },
    {
        "name": "overlapping_template",
        "folder": "OverlappingTemplate",
        "per_sequence": 1,
        "table_parser": "overlapping_template",
    },
    {"name": "universal", "folder": "Universal", "per_sequence": 1},
    {"name": "approximate_entropy", "folder": "ApproximateEntropy", "per_sequence": 1},
    {
        "name": "random_excursions",
        "folder": "RandomExcursions",
        "per_sequence": 8,
        "labels": [-4, -3, -2, -1, 1, 2, 3, 4],
    },
    {
        "name": "random_excursions_variant",
        "folder": "RandomExcursionsVariant",
        "per_sequence": 18,
        "labels": list(range(-9, 0)) + list(range(1, 10)),
    },
    {"name": "serial", "folder": "Serial", "per_sequence": 2, "labels": ["p_value1", "p_value2"]},
    {
        "name": "linear_complexity",
        "folder": "LinearComplexity",
        "per_sequence": 1,
        "table_parser": "linear_complexity",
    },
]

p_value_tol = 1e-3
comp_tol = 1e-2
VERBOSE = os.getenv("NIST_STS_KAT_VERBOSE", "").strip().lower() in {"1", "true", "yes"}


@contextmanager
def _maybe_silence_output():
    if VERBOSE:
        yield
        return
    with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
        yield


def _is_nan(value: Any) -> bool:
    try:
        return isinstance(value, float) and math.isnan(value)
    except TypeError:
        return False


def _values_match(a: Any, b: Any, abs_tol: float) -> (bool, str):
    if _is_nan(a) and _is_nan(b):
        return True, "-"
    if _is_nan(a) or _is_nan(b):
        return False, "-"
    return math.isclose(float(a), float(b), abs_tol=abs_tol), f"{abs(float(a) - float(b)):.12g}"


def _passed_match(nist_value: Any, claasp_value: Any) -> bool:
    if nist_value is None and claasp_value is None:
        return True
    if (nist_value is False and claasp_value is None) or (nist_value is None and claasp_value is False):
        return True
    return nist_value == claasp_value


def _make_not_applicable_record(label: str = "main", comp_info_keys: List[str] = None) -> Dict[str, Any]:
    comp_info_keys = comp_info_keys or []
    return {
        "p_value": float("nan"),
        "passed": None,
        "computational_information": {key: float("nan") for key in comp_info_keys},
        "label": label,
    }


def _is_not_applicable_stat(stat: Dict[str, Any]) -> bool:
    if not stat:
        return True
    if stat.get("passed") is None:
        return True
    return False


def _group_records_by_sequence(records: List[Dict[str, Any]]) -> Dict[int, Dict[str, Dict[str, Any]]]:
    grouped: Dict[int, Dict[str, Dict[str, Any]]] = {}
    for record in records:
        seq_index = record.get("sequence_index", 0)
        label = record.get("label", "main")
        grouped.setdefault(seq_index, {})[label] = record
    return grouped


def _final_report_not_applicable_row(nist_row: Optional[Dict[str, Any]], claasp_row: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    bin_len = 0
    if claasp_row and claasp_row.get("bin_counts"):
        bin_len = len(claasp_row["bin_counts"])
    elif nist_row and nist_row.get("bin_counts"):
        bin_len = len(nist_row["bin_counts"])
    if bin_len <= 0:
        bin_len = 10
    base_row = nist_row or claasp_row or {}
    return {
        **base_row,
        "uniformity_defined": False,
        "uniformity_p_value": float("nan"),
        "passed_sequences": 0,
        "total_sequences": 0,
        "proportion": 0.0,
        "bin_counts": [0] * bin_len,
    }


def _get_sequence_indices(
    nist_by_seq: Dict[int, Dict[str, Dict[str, Any]]],
    claasp_by_seq: Dict[int, Dict[str, Dict[str, Any]]],
    num_sequences: int,
) -> List[int]:
    sequence_indices = sorted(set(nist_by_seq.keys()).union(claasp_by_seq.keys()))
    if not sequence_indices:
        sequence_indices = list(range(num_sequences))
    return sequence_indices


def _claasp_records_for_test(assess_results: Dict[str, Any], test_config: Dict[str, Any]) -> List[Dict[str, Any]]:
    detailed = assess_results.get("detailed_results", {})
    name = test_config["name"]
    alpha = assess_results.get("alpha", 0.01)
    records: List[Dict[str, Any]] = []

    if name in {"cumulative_sums_forward", "cumulative_sums_backward"}:
        key = name
        return _records_from_assess_key(detailed, key, label="main", alpha=alpha)

    if name == "serial":
        records.extend(_records_from_assess_key(detailed, "serial_1", label="p_value1", alpha=alpha))
        records.extend(_records_from_assess_key(detailed, "serial_2", label="p_value2", alpha=alpha))
        return records

    if name in {"random_excursions", "random_excursions_variant"}:
        labels = test_config.get("labels", [])
        for label in labels:
            key = f"{name}_{label}"
            records.extend(_records_from_assess_key(detailed, key, label=str(label), alpha=alpha))
        return records

    if name == "non_overlapping_template":
        for key in sorted(k for k in detailed.keys() if k.startswith("non_overlapping_template_")):
            suffix = key.split("non_overlapping_template_", 1)[1]
            records.extend(_records_from_assess_key(detailed, key, label=f"template_{suffix}", alpha=alpha))
        return records

    if name == "overlapping_template":
        return _records_from_assess_key(
            detailed,
            name,
            label="main",
            alpha=alpha,
            default_passed_when_nan=False,
        )

    return _records_from_assess_key(detailed, name, label="main", alpha=alpha)


def _records_from_assess_key(
    detailed: Dict[str, Any],
    key: str,
    label: str,
    alpha: float,
    default_passed_when_nan: Optional[bool] = None,
) -> List[Dict[str, Any]]:
    if key not in detailed:
        return []
    records: List[Dict[str, Any]] = []
    per_sequence = detailed[key]
    for seq_index, seq_results in enumerate(per_sequence):
        if not seq_results:
            record = _make_not_applicable_record(label)
        else:
            res = seq_results[0]
            p_value = res.get("p_value", res.get("p_value1", float("nan")))
            passed = res.get("passed", None)
            if passed is None:
                if p_value is not None and not _is_nan(p_value):
                    passed = p_value >= alpha
                elif p_value is not None and _is_nan(p_value) and default_passed_when_nan is not None:
                    passed = default_passed_when_nan
            record = {
                "p_value": p_value,
                "passed": passed,
                "computational_information": res.get("computational_information", {}),
                "label": label,
            }
        record["sequence_index"] = seq_index
        records.append(record)
    return records


def _compare_stat(
    mismatches: List[str],
    test_label: str,
    seq_index: int,
    label: str,
    nist_stat: Dict[str, Any],
    claasp_stat: Dict[str, Any],
) -> None:
    p_match, _ = _values_match(nist_stat["p_value"], claasp_stat["p_value"], p_value_tol)
    if not p_match:
        mismatches.append(
            f"{test_label} seq {seq_index} {label}: p_value mismatch (NIST {nist_stat['p_value']}, CLAASP {claasp_stat['p_value']})"
        )

    passed_match = _passed_match(nist_stat["passed"], claasp_stat["passed"])
    if not passed_match:
        mismatches.append(
            f"{test_label} seq {seq_index} {label}: passed mismatch (NIST {nist_stat['passed']}, CLAASP {claasp_stat['passed']})"
        )

    nist_comp_info = nist_stat.get("computational_information", {})
    claasp_comp_info = claasp_stat.get("computational_information", {})
    common_keys = sorted(set(nist_comp_info.keys()).intersection(claasp_comp_info.keys()))
    for key in common_keys:
        nist_value = nist_comp_info.get(key, None)
        claasp_value = claasp_comp_info.get(key, None)
        if isinstance(nist_value, (int, float)) and isinstance(claasp_value, (int, float)):
            match, _ = _values_match(nist_value, claasp_value, comp_tol)
        else:
            match = nist_value == claasp_value
        if not match:
            mismatches.append(
                f"{test_label} seq {seq_index} {label}: comp_info {key} mismatch (NIST {nist_value}, CLAASP {claasp_value})"
            )


def _compare_final_report(
    mismatches: List[str],
    nist_rows: List[Dict[str, Any]],
    claasp_tests: List[Dict[str, Any]],
    skip_names: Set[str] = None,
    not_applicable_names: Set[str] = None,
) -> None:
    skip_names = skip_names or set()
    not_applicable_names = not_applicable_names or set()
    nist_by_name: Dict[str, List[Dict[str, Any]]] = {}
    for row in nist_rows:
        nist_by_name.setdefault(row["normalized_name"], []).append(row)

    claasp_by_name: Dict[str, List[Dict[str, Any]]] = {}
    for test in claasp_tests:
        claasp_by_name.setdefault(_normalize_test_name(test["test_name"]), []).append(test)

    all_names = sorted(set(nist_by_name.keys()).union(claasp_by_name.keys()))
    for name in all_names:
        if name in skip_names:
            continue
        nist_list = nist_by_name.get(name, [])
        claasp_list = claasp_by_name.get(name, [])
        max_len = max(len(nist_list), len(claasp_list))
        for idx in range(max_len):
            nist_row = nist_list[idx] if idx < len(nist_list) else None
            claasp_row = claasp_list[idx] if idx < len(claasp_list) else None
            display_name = claasp_row["test_name"] if claasp_row else (nist_row["test_name"] if nist_row else name)
            if not nist_row or not claasp_row:
                missing = "NIST" if not nist_row else "CLAASP"
                mismatches.append(f"Final report {display_name}: missing {missing} entry")
                continue
            if name in not_applicable_names:
                nist_row = _final_report_not_applicable_row(nist_row, claasp_row)
                claasp_row = _final_report_not_applicable_row(claasp_row, claasp_row)
            if nist_row["bin_counts"] != claasp_row.get("bin_counts", []):
                mismatches.append(
                    f"Final report {display_name}: bin_counts mismatch (NIST {nist_row['bin_counts']}, CLAASP {claasp_row.get('bin_counts', [])})"
                )
            if nist_row.get("uniformity_defined", True):
                match_uniformity, _ = _values_match(
                    nist_row["uniformity_p_value"],
                    claasp_row.get("uniformity_p_value", float("nan")),
                    p_value_tol,
                )
                if not match_uniformity:
                    mismatches.append(
                        f"Final report {display_name}: uniformity p_value mismatch (NIST {nist_row['uniformity_p_value']}, CLAASP {claasp_row.get('uniformity_p_value')})"
                    )
            match_proportion, _ = _values_match(
                nist_row["proportion"],
                claasp_row.get("proportion", float("nan")),
                comp_tol,
            )
            if not match_proportion:
                mismatches.append(
                    f"Final report {display_name}: proportion mismatch (NIST {nist_row['proportion']}, CLAASP {claasp_row.get('proportion')})"
                )


def _compare_test_config(
    mismatches: List[str],
    test_config: Dict[str, Any],
    nist_records: List[Dict[str, Any]],
    claasp_records: List[Dict[str, Any]],
    nist_not_applicable: bool,
    num_sequences: int,
) -> None:
    display_name = test_config.get("display_name", test_config["folder"])
    nist_by_seq = _group_records_by_sequence(nist_records)
    claasp_by_seq = _group_records_by_sequence(claasp_records)

    if test_config.get("name") == "non_overlapping_template":
        template_labels = sorted(
            set(
                label
                for labels in list(nist_by_seq.values()) + list(claasp_by_seq.values())
                for label in labels.keys()
            )
        )
        if not template_labels:
            template_labels = ["template_0"]

        for template_label in template_labels:
            sequence_indices = _get_sequence_indices(nist_by_seq, claasp_by_seq, num_sequences)
            for seq_index in sequence_indices:
                nist_labels_all = nist_by_seq.get(seq_index, {})
                claasp_labels_all = claasp_by_seq.get(seq_index, {})
                nist_stat = nist_labels_all.get(template_label)
                claasp_stat = claasp_labels_all.get(template_label)
                claasp_not_applicable = _is_not_applicable_stat(claasp_stat)
                if (not nist_stat and not claasp_stat) or (not nist_stat and nist_not_applicable) or (
                    not claasp_stat and claasp_not_applicable
                ):
                    nist_keys = list((nist_stat or {}).get("computational_information", {}).keys())
                    claasp_keys = list((claasp_stat or {}).get("computational_information", {}).keys())
                    placeholder_keys = claasp_keys or nist_keys
                    nist_stat = nist_stat or _make_not_applicable_record("main", placeholder_keys)
                    claasp_stat = claasp_stat or _make_not_applicable_record("main", placeholder_keys)

                if not nist_stat or not claasp_stat:
                    mismatches.append(
                        f"{display_name} template {template_label} seq {seq_index}: missing {'NIST' if not nist_stat else 'CLAASP'} entry"
                    )
                    continue
                _compare_stat(mismatches, display_name, seq_index, template_label, nist_stat, claasp_stat)
        return

    if test_config.get("labels") and test_config.get("name") in {
        "random_excursions",
        "random_excursions_variant",
        "serial",
    }:
        labels = test_config.get("labels") or []
        for label in labels:
            label_key = str(label)
            sequence_indices = _get_sequence_indices(nist_by_seq, claasp_by_seq, num_sequences)
            for seq_index in sequence_indices:
                nist_labels_all = nist_by_seq.get(seq_index, {})
                claasp_labels_all = claasp_by_seq.get(seq_index, {})
                nist_stat = nist_labels_all.get(label_key)
                claasp_stat = claasp_labels_all.get(label_key)
                claasp_not_applicable = _is_not_applicable_stat(claasp_stat)
                if (not nist_stat and not claasp_stat) or (not nist_stat and nist_not_applicable) or (
                    not claasp_stat and claasp_not_applicable
                ):
                    nist_keys = list((nist_stat or {}).get("computational_information", {}).keys())
                    claasp_keys = list((claasp_stat or {}).get("computational_information", {}).keys())
                    placeholder_keys = claasp_keys or nist_keys
                    nist_stat = nist_stat or _make_not_applicable_record("main", placeholder_keys)
                    claasp_stat = claasp_stat or _make_not_applicable_record("main", placeholder_keys)

                if not nist_stat or not claasp_stat:
                    mismatches.append(
                        f"{display_name} label {label_key} seq {seq_index}: missing {'NIST' if not nist_stat else 'CLAASP'} entry"
                    )
                    continue
                _compare_stat(mismatches, display_name, seq_index, label_key, nist_stat, claasp_stat)
        return

    sequence_indices = _get_sequence_indices(nist_by_seq, claasp_by_seq, num_sequences)
    for seq_index in sequence_indices:
        nist_labels = nist_by_seq.get(seq_index, {})
        claasp_labels = claasp_by_seq.get(seq_index, {})
        all_labels = sorted(set(nist_labels.keys()).union(claasp_labels.keys()))
        if not all_labels and nist_not_applicable:
            all_labels = ["main"]

        for label in all_labels:
            nist_stat = nist_labels.get(label)
            claasp_stat = claasp_labels.get(label)
            claasp_not_applicable = _is_not_applicable_stat(claasp_stat)
            if (not nist_stat and not claasp_stat) or (not nist_stat and nist_not_applicable) or (
                not claasp_stat and claasp_not_applicable
            ):
                nist_keys = list((nist_stat or {}).get("computational_information", {}).keys())
                claasp_keys = list((claasp_stat or {}).get("computational_information", {}).keys())
                placeholder_keys = claasp_keys or nist_keys
                nist_stat = nist_stat or _make_not_applicable_record(label, placeholder_keys)
                claasp_stat = claasp_stat or _make_not_applicable_record(label, placeholder_keys)

            if not nist_stat or not claasp_stat:
                mismatches.append(
                    f"{display_name} seq {seq_index} label {label}: missing {'NIST' if not nist_stat else 'CLAASP'} entry"
                )
                continue
            _compare_stat(mismatches, display_name, seq_index, label, nist_stat, claasp_stat)


def _dataset_num_sequences(dataset_path: Path, dataset: Dict[str, Any]) -> int:
    if dataset.get("fixed_num_sequences"):
        return int(dataset["num_sequences"])
    bits_per_sequence = dataset["bits_per_sequence"]
    padded_bytes_per_sequence = ((bits_per_sequence + 31) // 32) * 4
    return dataset_path.stat().st_size // padded_bytes_per_sequence


def test_nist_sts_kat_matches_claasp() -> None:
    base_dir = Path(__file__).parent / "test_data"
    datasets_dir = base_dir / "datasets"
    assess_output_root = base_dir / "assess_output"

    mismatches: List[str] = []

    for dataset in DATASETS:
        dataset_path = datasets_dir / dataset["name"]
        assert dataset_path.exists(), f"Missing dataset file {dataset_path}"

        bits_per_sequence = dataset["bits_per_sequence"]
        num_sequences = _dataset_num_sequences(dataset_path, dataset)

        test_mask = "111111111111111"
        with _maybe_silence_output():
            claasp_results = NISTTests.assess(
                file_path=str(dataset_path),
                bit_length=bits_per_sequence,
                num_sequences=num_sequences,
                input_format="ascii" if dataset.get("text", False) else "binary",
                tests=test_mask,
                verbose=VERBOSE,
            )

        assess_output_path = assess_output_root / dataset["name"] / "experiments" / "AlgorithmTesting"
        assert assess_output_path.exists(), f"Missing assess output at {assess_output_path}"

        final_report_path = assess_output_path / "finalAnalysisReport.txt"
        nist_final_rows = parse_final_analysis_report(str(final_report_path)) if final_report_path.is_file() else []

        final_report_skip_names: Set[str] = set()
        final_report_not_applicable_names: Set[str] = set()

        for test_config in TEST_CONFIGS:
            folder = test_config["folder"]
            stats_path = assess_output_path / folder / "stats.txt"
            if not stats_path.is_file():
                mismatches.append(f"{dataset['name']} {folder}: stats.txt not found")
                continue

            nist_records = parse_nist_stats(str(stats_path), test_config)
            reason = None
            if stats_path.is_file() and not nist_records:
                reason = _detect_nist_skip_reason(str(stats_path))
            nist_not_applicable = reason in {
                "test not applicable for this dataset",
                "no p-values found in stats.txt",
                "p-value undefined in NIST output",
                "test error in NIST output",
                "stats.txt not readable",
            }
            if stats_path.is_file() and _stats_indicates_not_applicable(str(stats_path)):
                nist_not_applicable = True
                if test_config.get("name") in {"overlapping_template", "universal"}:
                    final_report_not_applicable_names.add(_normalize_test_name(folder))

            claasp_records = _claasp_records_for_test(claasp_results, test_config)
            _compare_test_config(
                mismatches,
                test_config,
                nist_records,
                claasp_records,
                nist_not_applicable,
                num_sequences,
            )

        if nist_final_rows:
            _compare_final_report(
                mismatches,
                nist_final_rows,
                claasp_results.get("tests", []),
                final_report_skip_names,
                final_report_not_applicable_names,
            )

    if mismatches:
        summary = "\n".join(f"  - {item}" for item in mismatches[:20])
        if len(mismatches) > 20:
            summary += f"\n  ... and {len(mismatches) - 20} more"
        pytest.fail(f"NIST-STS KAT comparison failed with {len(mismatches)} mismatch(es):\n{summary}")
