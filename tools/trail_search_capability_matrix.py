"""Generate or check the public primitive trail-search capability matrix."""

from __future__ import annotations

import argparse
import inspect
import json
from pathlib import Path

from claasp.analysis.trail_search import TrailSearchCapabilityError, require_word_sat_capability
from claasp.primitives._catalogue_exports import ALL_EXPORTS, load_export
from claasp.representations.constraints.sat import WordDifferentialSATModel, WordLinearSATModel
from claasp.semantics.cryptanalysis import TrailKind

OUTPUT = Path("docs/architecture/audits/data/trail-search-capability-matrix.json")


def _primitive(name):
    primitive_type = load_export(name)
    parameters = inspect.signature(primitive_type).parameters
    options = {"number_of_rounds": 1} if "number_of_rounds" in parameters else {}
    if "number_of_initialization_clocks" in parameters:
        options["number_of_initialization_clocks"] = 1
    if "keystream_bit_size" in parameters:
        options["keystream_bit_size"] = 1
    return primitive_type(**options), options


def _classification(reason):
    if " domain " in reason:
        return "intentionally_out_of_scope"
    return "unsupported"


def generate():
    """Construct every public graph and both exact models where supported."""

    rows = []
    for name in sorted(ALL_EXPORTS):
        try:
            primitive, options = _primitive(name)
        except Exception as error:  # catalogue constructors have heterogeneous restrictions
            rows.append(
                {
                    "primitive": name,
                    "configuration": "default or number_of_rounds=1",
                    "xor_differential": "unsupported",
                    "xor_linear": "unsupported",
                    "reason": f"reduced graph construction: {type(error).__name__}: {error}",
                }
            )
            continue
        row = {
            "primitive": name,
            "configuration": options or "default",
        }
        reasons = []
        for kind, model_type in (
            (TrailKind.XOR_DIFFERENTIAL, WordDifferentialSATModel),
            (TrailKind.XOR_LINEAR, WordLinearSATModel),
        ):
            try:
                require_word_sat_capability(primitive, kind)
                model_options = {"maximum_weight": None} if kind is TrailKind.XOR_LINEAR else {}
                model_type(primitive, **model_options).cnf_formula()
                row[kind.value] = "supported_and_tested"
            except TrailSearchCapabilityError as error:
                reason = str(error).split("first unsupported feature is ", 1)[-1]
                row[kind.value] = _classification(reason)
                reasons.append(reason)
            except Exception as error:
                row[kind.value] = "unsupported"
                reasons.append(f"model construction: {type(error).__name__}: {error}")
        row["reason"] = None if not reasons else reasons[0]
        rows.append(row)
    return {
        "schema": 1,
        "meaning": {
            "supported_and_tested": "reduced/default graph and exact CNF construction passed",
            "unsupported": "a precise component or construction gap remains",
            "intentionally_out_of_scope": "the graph domain lacks exact Word XOR semantics",
        },
        "rows": rows,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    rendered = json.dumps(generate(), indent=2, sort_keys=True) + "\n"
    if arguments.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != rendered:
            raise SystemExit(f"{OUTPUT} is stale; regenerate it")
        return
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
