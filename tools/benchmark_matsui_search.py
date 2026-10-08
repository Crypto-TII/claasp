#!/usr/bin/env python3
"""Benchmark the exact Matsui search and its audited family baselines."""

from __future__ import annotations

import argparse
import json
import platform
import sys
import tracemalloc
from fractions import Fraction
from math import log2
from pathlib import Path
from statistics import median
from time import monotonic

from claasp.analysis._matsui import MatsuiEdge, matsui_branch_and_bound
from claasp.analysis._trail_propagation import xor_differential_component_transitions
from claasp.analysis.arx import check_speck_trail
from claasp.analysis.spn import check_spn_trail
from claasp.components import BitVectorSBox
from claasp.primitives import Present, Speck
from claasp.primitives.block_ciphers.des import DES
from claasp.primitives.block_ciphers.gift import Gift
from claasp.semantics.cryptanalysis import (
    SBoxTransitionSemantics,
    Trail,
    TrailKind,
    TrailStep,
    XorDifference,
)


def _best_sbox_transition(table, output_width):
    semantics = SBoxTransitionSemantics(table, output_width=output_width)
    transitions = tuple(
        semantics.xor_differential(source, target)
        for source in range(1, 1 << semantics.input_width)
        for target in range(1 << semantics.output_width)
        if semantics.xor_differential(source, target).is_possible
    )
    seed = transitions[0]

    def successors(_round_index, _state, strict_minimum):
        for transition in transitions:
            probability = Fraction(transition.numerator, transition.denominator)
            if probability > strict_minimum:
                yield MatsuiEdge(None, probability, transition)

    outcome = matsui_branch_and_bound(
        rounds=1,
        initial_state=None,
        incumbent_probability=Fraction(seed.numerator, seed.denominator),
        incumbent_payload=(seed,),
        suffix_probability_bounds=(Fraction(1), Fraction(1)),
        successors=successors,
    )
    transition = outcome.payload[0]
    if not semantics.check(transition):
        raise RuntimeError("S-box Matsui search returned an invalid transition")
    return outcome


def _measure(operation, repeats):
    runtimes = []
    peaks = []
    result = None
    for _ in range(repeats):
        tracemalloc.start()
        started = monotonic()
        result = operation()
        runtimes.append(monotonic() - started)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peaks.append(peak)
    return result, median(runtimes), int(median(peaks))


def _des_case(repeats):
    primitive = DES(number_of_rounds=2)
    all_sboxes = tuple(
        item for item in primitive.graph.components if isinstance(item, BitVectorSBox)
    )
    sboxes = all_sboxes[:8]

    def run():
        return tuple(_best_sbox_transition(item.table, item.output_bit_size) for item in sboxes)

    outcomes, runtime, peak = _measure(run, repeats)
    best = max(outcome.probability for outcome in outcomes)
    active_sbox = all_sboxes[13]
    if active_sbox.component_id is None:
        raise RuntimeError("DES S-box must have a component id")
    witness_semantics = SBoxTransitionSemantics(
        active_sbox.table, output_width=active_sbox.output_bit_size
    )
    witness = witness_semantics.xor_differential(0x08, 0x06)
    witness_trail = Trail(
        TrailKind.XOR_DIFFERENTIAL,
        XorDifference(0x40000000000, 64),
        XorDifference(0x80100100000, 64),
        (TrailStep(active_sbox.component_id, witness),),
    )
    propagated = xor_differential_component_transitions(
        primitive,
        witness_trail,
        input_differences={"plaintext": witness_trail.input_pattern.value, "key": 0},
    )
    return {
        "family": "DES",
        "workload": "DES-2 nonlinear-round bound over all eight rectangular 6-to-4 S-boxes",
        "scope": "local Matsui bound plus the two-round Feistel activity proof; not a generic DES adapter",
        "best_probability": f"{best.numerator}/{best.denominator}",
        "best_weight": -log2(float(best)),
        "expected_trail_weight": 2.0,
        "validation": best == Fraction(1, 4)
        and witness_semantics.check(witness)
        and Fraction(witness.numerator, witness.denominator) == Fraction(1, 4)
        and bool(propagated),
        "runtime_seconds_median": runtime,
        "peak_memory_bytes_median": peak,
    }


def _present_case(repeats):
    primitive = Present(number_of_rounds=2)
    result, runtime, peak = _measure(
        lambda: primitive.analysis.find_optimal_trail(
            "xor_differential", backend="dependency_free"
        ),
        repeats,
    )
    return {
        "family": "SPN",
        "workload": "PRESENT-2 exact dependency-free XOR-differential search",
        "scope": "existing exact SPN baseline used to cross-check the Matsui program",
        "best_weight": result.trail.total_weight,
        "validation": result.is_optimal and check_spn_trail(primitive, result.trail),
        "runtime_seconds_median": runtime,
        "peak_memory_bytes_median": peak,
    }


def _speck_case(repeats):
    primitive = Speck(number_of_rounds=2)
    result, runtime, peak = _measure(
        lambda: primitive.analysis.find_optimal_trail(
            "xor_differential", backend="dependency_free"
        ),
        repeats,
    )
    return {
        "family": "ARX",
        "workload": "Speck32/64-2 exact Matsui XOR-differential search",
        "scope": "full reviewed dependency-free trail search",
        "best_weight": result.trail.total_weight,
        "validation": result.is_optimal and check_speck_trail(primitive, result.trail),
        "runtime_seconds_median": runtime,
        "peak_memory_bytes_median": peak,
        "technique": result.metadata.technique,
    }


def _gift_case(repeats):
    bitsliced = Gift.realize("bitsliced", number_of_rounds=1, block_bit_size=64)
    lookup = Gift.realize("sbox", number_of_rounds=1, block_bit_size=64)
    sbox = next(item for item in lookup.graph.components if isinstance(item, BitVectorSBox))
    outcome, runtime, peak = _measure(
        lambda: _best_sbox_transition(sbox.table, sbox.output_bit_size), repeats
    )
    probability = outcome.probability
    equivalent = all(
        bitsliced.evaluate(plaintext=value, key=0) == lookup.evaluate(plaintext=value, key=0)
        for value in range(16)
    )
    return {
        "family": "bitsliced",
        "workload": "GIFT64-1 grouped four-bit S-box transition search",
        "scope": "macro transition; dependent internal AND/OR probabilities are not multiplied",
        "best_probability": f"{probability.numerator}/{probability.denominator}",
        "best_weight": -log2(float(probability)),
        "validation": probability == Fraction(3, 8) and equivalent,
        "runtime_seconds_median": runtime,
        "peak_memory_bytes_median": peak,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if arguments.repeats <= 0:
        parser.error("--repeats must be positive")
    payload = {
        "schema_version": 1,
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "repeats": arguments.repeats,
        "results": [
            _des_case(arguments.repeats),
            _present_case(arguments.repeats),
            _speck_case(arguments.repeats),
            _gift_case(arguments.repeats),
        ],
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if arguments.output is None:
        print(rendered, end="")
    else:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
