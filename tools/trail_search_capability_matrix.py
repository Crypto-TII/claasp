"""Generate or check the public primitive trail-search capability matrix."""

from __future__ import annotations

import argparse
import inspect
import json
from pathlib import Path

from claasp.analysis.trail_search import (
    TrailSearchCapabilityError,
    _require_exact_trail_capability,
)
from claasp.primitives._catalogue_exports import ALL_EXPORTS, load_export
from claasp.representations.constraints.sat import WordDifferentialSATModel, WordLinearSATModel
from claasp.semantics.cryptanalysis import TrailKind

OUTPUT = Path("docs/architecture/audits/data/trail-search-capability-matrix.json")

_CONFIGURATION_OVERRIDES = {
    # These constructors reject an arbitrary one-round request.  Use their
    # smallest vetted/default graph instead of recording a false constructor gap.
    "Bivium": {},
    "CipherFour": {},
    "Kalyna": {},
    "Led": {"number_of_rounds": 4},
    "LowMC": {},
}


def _primitive(name):
    primitive_type = load_export(name)
    parameters = inspect.signature(primitive_type).parameters
    options = dict(_CONFIGURATION_OVERRIDES.get(name, {}))
    if name not in _CONFIGURATION_OVERRIDES and "number_of_rounds" in parameters:
        options["number_of_rounds"] = 1
    if name not in _CONFIGURATION_OVERRIDES and "number_of_initialization_clocks" in parameters:
        options["number_of_initialization_clocks"] = 1
    if name not in _CONFIGURATION_OVERRIDES and "keystream_bit_size" in parameters:
        options["keystream_bit_size"] = 1
    return primitive_type(**options), options


def generate():
    """Construct every public graph and audit both exact model contracts.

    Full CNF materialization is deliberately covered by component and integration
    tests rather than repeated for every large default catalogue graph here.
    """

    rows = []
    for name in sorted(ALL_EXPORTS):
        attempted_configuration = _CONFIGURATION_OVERRIDES.get(
            name, "default or number_of_rounds=1"
        )
        try:
            primitive, options = _primitive(name)
        except Exception as error:  # catalogue constructors have heterogeneous restrictions
            rows.append(
                {
                    "primitive": name,
                    "configuration": attempted_configuration or "default",
                    "xor_differential": "unsupported",
                    "xor_differential_limitation": "graph_construction",
                    "xor_differential_reason": (
                        f"reduced graph construction: {type(error).__name__}: {error}"
                    ),
                    "xor_linear": "unsupported",
                    "xor_linear_limitation": "graph_construction",
                    "xor_linear_reason": (
                        f"reduced graph construction: {type(error).__name__}: {error}"
                    ),
                }
            )
            continue
        row = {
            "primitive": name,
            "configuration": options or "default",
        }
        for kind, model_type in (
            (TrailKind.XOR_DIFFERENTIAL, WordDifferentialSATModel),
            (TrailKind.XOR_LINEAR, WordLinearSATModel),
        ):
            try:
                _require_exact_trail_capability(primitive, kind, backend="sat")
                model_options = {"maximum_weight": None} if kind is TrailKind.XOR_LINEAR else {}
                model_type(primitive, **model_options)
                row[kind.value] = "supported_and_tested"
                row[f"{kind.value}_limitation"] = None
                row[f"{kind.value}_reason"] = None
            except TrailSearchCapabilityError as error:
                reason = str(error).split("first unsupported feature is ", 1)[-1]
                row[kind.value] = "unsupported"
                row[f"{kind.value}_limitation"] = "exact_semantics"
                row[f"{kind.value}_reason"] = reason
            except Exception as error:
                row[kind.value] = "unsupported"
                row[f"{kind.value}_limitation"] = "exact_semantics"
                row[f"{kind.value}_reason"] = f"model construction: {type(error).__name__}: {error}"
        rows.append(row)
    return {
        "schema": 3,
        "meaning": {
            "supported_and_tested": (
                "the reduced/default graph passed the exact component/domain contract; "
                "the encodings are covered by focused construction and solver tests"
            ),
            "unsupported": (
                "the graph cannot enter the exact optimizer for the recorded component, "
                "weight-domain, output, or constructor reason"
            ),
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
