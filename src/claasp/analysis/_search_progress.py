"""Append-only, machine-readable progress for exact trail optimizations."""

import json
from math import exp, log
from pathlib import Path


class _SearchLog:
    def __init__(self, filename, primitive, kind):
        self.path = None if filename is None else Path(filename)
        self.context = {"primitive": primitive, "kind": kind}
        self.attempt = 0
        self.observations = []

    def record(self, bound, result, *, objective="weight_at_most"):
        if self.path is None:
            return
        self.attempt += 1
        status = result.status.value
        record = {
            **self.context,
            "attempt": self.attempt,
            "objective": objective,
            "bound": bound,
            "status": status,
            "runtime_seconds": result.runtime_seconds,
        }
        # Only UNSAT on a weight-at-most query proves a strict weight bound.
        if objective == "weight_at_most" and bound is not None and status == "unsatisfiable":
            record["proved_minimum_weight"] = bound + 1
        if objective == "weight_at_most" and bound is not None and result.runtime_seconds > 0:
            prior = next((item for item in reversed(self.observations) if item[0] != bound), None)
            if prior is not None:
                slope = (log(result.runtime_seconds) - log(prior[1])) / (bound - prior[0])
                record["estimated_seconds_at_next_weight"] = result.runtime_seconds * exp(
                    max(-50, min(50, slope))
                )
                record["estimate_is_proof"] = False
            self.observations.append((bound, result.runtime_seconds))
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")
