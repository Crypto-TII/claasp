"""Capture fixed legacy evaluation evidence while running an inventory slice.

This development-only helper runs in the compatibility image. It records
integer input/output observations from the original tests without making the
v5 runtime depend on either pytest, Sage, or the legacy package.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from claasp.cipher import Cipher


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, default=Path("next/migration/legacy_inventory.json"))
    parser.add_argument("--slice", default="M10.9d6")
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    inventory = json.loads(arguments.inventory.read_text(encoding="utf-8"))
    tests = sorted({
        record["path"] for record in inventory["records"]
        if record.get("milestone_owner") == arguments.slice and record["kind"] == "test"
    })
    observations = []
    original = Cipher.evaluate

    def recording_evaluate(self, cipher_input, intermediate_output=False, verbosity=False):
        result = original(self, cipher_input, intermediate_output=intermediate_output, verbosity=verbosity)
        if not intermediate_output and isinstance(result, int) and all(isinstance(value, int) for value in cipher_input):
            observations.append({
                "legacy_class": f"{type(self).__module__}.{type(self).__name__}",
                "legacy_id": self.id,
                "inputs": list(cipher_input),
                "output": result,
            })
        return result

    Cipher.evaluate = recording_evaluate
    try:
        status = pytest.main([*tests, "-q", "-p", "no:cacheprovider"])
    finally:
        Cipher.evaluate = original
        unique = {
            (item["legacy_class"], tuple(item["inputs"]), item["output"]): item
            for item in observations
        }
        arguments.output.write_text(
            json.dumps(list(unique.values()), sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
    return int(status)


if __name__ == "__main__":
    raise SystemExit(main())
