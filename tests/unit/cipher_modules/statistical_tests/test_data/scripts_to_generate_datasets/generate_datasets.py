#!/usr/bin/env python3
"""Generate fixed datasets for NIST STS tests.

Usage:
  python3 generate_datasets.py --all
  python3 generate_datasets.py --name random_ascii_small
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np


SCRIPT_DIR = Path(__file__).resolve().parent
DATASETS_DIR = SCRIPT_DIR.parent / "datasets"
CONFIG_PATH = SCRIPT_DIR / "datasets_config.json"


def _write_ascii_sequences(path: Path, sequences: list[np.ndarray]) -> None:
    with path.open("w") as f:
        for seq in sequences:
            f.write("".join(str(int(b)) for b in seq))
            f.write("\n")


def _write_binary_sequences(path: Path, sequences: list[np.ndarray]) -> None:
    with path.open("wb") as f:
        for seq in sequences:
            packed = np.packbits(seq.astype(np.uint8))
            f.write(packed.tobytes())


def _generate_random(bit_length: int, num_sequences: int, seed: int | None) -> list[np.ndarray]:
    if seed is not None:
        np.random.seed(seed)
    return [np.random.randint(0, 2, bit_length, dtype=np.uint8) for _ in range(num_sequences)]


def _generate_structured(bit_length: int, num_sequences: int, pattern_type: str, seed: int | None) -> list[np.ndarray]:
    if seed is not None:
        np.random.seed(seed)

    sequences = []
    if pattern_type == "alternating":
        base = np.fromiter((i % 2 for i in range(bit_length)), dtype=np.uint8)
        for _ in range(num_sequences):
            sequences.append(base.copy())
    elif pattern_type == "blocks":
        block_size = 64
        for _ in range(num_sequences):
            seq = np.zeros(bit_length, dtype=np.uint8)
            val = 0
            for start in range(0, bit_length, block_size):
                seq[start:start + block_size] = val
                val = 1 - val
            sequences.append(seq)
    else:
        raise ValueError(f"Unsupported pattern_type: {pattern_type}")

    return sequences


def generate_dataset(entry: dict) -> Path:
    name = entry["name"]
    dtype = entry["type"]
    output = entry["output"]
    bit_length = int(entry["bit_length"])
    num_sequences = int(entry["num_sequences"])
    seed = entry.get("seed")

    output_path = DATASETS_DIR / output

    if dtype == "random_ascii":
        sequences = _generate_random(bit_length, num_sequences, seed)
        _write_ascii_sequences(output_path, sequences)
    elif dtype == "random_binary":
        sequences = _generate_random(bit_length, num_sequences, seed)
        _write_binary_sequences(output_path, sequences)
    elif dtype == "structured_ascii":
        sequences = _generate_structured(bit_length, num_sequences, entry["pattern_type"], seed)
        _write_ascii_sequences(output_path, sequences)
    elif dtype == "structured_binary":
        sequences = _generate_structured(bit_length, num_sequences, entry["pattern_type"], seed)
        _write_binary_sequences(output_path, sequences)
    else:
        raise ValueError(f"Unknown dataset type: {dtype}")

    print(f"Generated {name} -> {output_path}")
    return output_path


def load_config() -> list[dict]:
    with CONFIG_PATH.open("r") as f:
        config = json.load(f)
    return config["datasets"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate fixed datasets for NIST STS tests.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true", help="Generate all datasets")
    group.add_argument("--name", help="Generate a single dataset by name")

    args = parser.parse_args()

    datasets = load_config()
    DATASETS_DIR.mkdir(parents=True, exist_ok=True)

    if args.all:
        for entry in datasets:
            generate_dataset(entry)
        return

    for entry in datasets:
        if entry["name"] == args.name:
            generate_dataset(entry)
            return

    raise SystemExit(f"Dataset '{args.name}' not found in {CONFIG_PATH}")


if __name__ == "__main__":
    main()
