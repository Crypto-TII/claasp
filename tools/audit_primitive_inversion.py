#!/usr/bin/env python3
"""Audit graph-native inversion over every public primitive parameter set.

The parent process isolates each configuration in a worker process.  This is
intentional: inversion is the subject of the audit, so an unexpectedly slow or
memory-hungry graph must not prevent the remaining catalogue from being
measured.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = ROOT / "docs" / "architecture" / "audits" / "primitive_inversion_audit.md"


class _InversionTimeout(Exception):
    pass


def _encoded_value(value_type, seed: bytes):
    from claasp.domains import PrimeField

    integer = int.from_bytes(hashlib.sha256(seed).digest(), "big")
    if isinstance(value_type.domain, PrimeField):
        values = tuple(
            (integer >> (index * 17)) % value_type.domain.modulus
            for index in range(value_type.unit_count)
        )
        return values[0] if len(values) == 1 else values
    width = value_type.encoded_bit_size
    if width is None:
        return tuple(integer >> (index * 8) & 0xFF for index in range(value_type.unit_count))
    return integer & ((1 << width) - 1)


def _round_trip(primitive, inverse, recover_input: str, sample_number: int) -> bool:
    values = {
        name: _encoded_value(
            port.value_type, f"{primitive.family_name}:{name}:{sample_number}".encode()
        )
        for name, port in primitive.input_ports.items()
    }
    output = primitive.evaluate(values)
    inverse_values = {"output": output}
    inverse_values.update((name, value) for name, value in values.items() if name != recover_input)
    return inverse.evaluate(inverse_values) == values[recover_input]


def _attempt_inversion(
    primitive,
    recover_input: str,
    timeout: float,
    repetitions: int,
) -> dict:
    import signal

    from claasp.transformations import TransformationError

    def timed_out(signum, frame):
        raise _InversionTimeout

    old_handler = signal.signal(signal.SIGALRM, timed_out)
    timings = []
    inverse = None
    try:
        for _ in range(repetitions):
            signal.setitimer(signal.ITIMER_REAL, timeout)
            attempt_started = time.perf_counter_ns()
            inverse = primitive.inverse(recover_input).primitive
            timings.append((time.perf_counter_ns() - attempt_started) / 1_000_000)
            signal.setitimer(signal.ITIMER_REAL, 0)
    except _InversionTimeout:
        return {
            "status": "timeout",
            "diagnostic": f"inverse construction exceeded {timeout:g} s",
            "elapsed_ms": timeout * 1000,
        }
    except TransformationError as error:
        return {
            "status": "not-supported",
            "failure_reason": error.reason.value,
            "diagnostic": str(error),
            "source_ids": list(error.source_ids),
        }
    except Exception as error:  # pragma: no cover - audit records arbitrary transformation failures
        return {
            "status": "inversion-error",
            "diagnostic": f"{type(error).__name__}: {error}",
        }
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)

    semantic_passes = 0
    try:
        signal.signal(signal.SIGALRM, timed_out)
        signal.setitimer(signal.ITIMER_REAL, timeout)
        for sample_number in range(2):
            semantic_passes += _round_trip(
                primitive,
                inverse,
                recover_input,
                sample_number,
            )
    except _InversionTimeout:
        status = "semantic-timeout"
        diagnostic = f"two semantic round trips exceeded {timeout:g} s"
    except Exception as error:  # pragma: no cover - audit records arbitrary execution failures
        status = "semantic-error"
        diagnostic = f"{type(error).__name__}: {error}"
    else:
        status = "verified" if semantic_passes == 2 else "semantic-mismatch"
        diagnostic = (
            None
            if status == "verified"
            else "recovered value differed from the original first input"
        )
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)

    return {
        "status": status,
        "diagnostic": diagnostic,
        "semantic_passes": semantic_passes,
        "semantic_samples": 2,
        "inversion_ms": statistics.median(timings),
        "timing_repetitions": len(timings),
        "inverse_components": len(inverse.components),
        "inverse_bindings": len(inverse.bindings),
    }


def _one_round_instance(primitive_class, parameters: dict, graph_rounds: int):
    if graph_rounds == 1:
        return primitive_class(**parameters), "already one graph round"
    signature = inspect.signature(primitive_class)
    for parameter_name in ("number_of_rounds", "number_of_steps"):
        if parameter_name in signature.parameters:
            one_round_parameters = dict(parameters)
            one_round_parameters[parameter_name] = 1
            return primitive_class(**one_round_parameters), f"{parameter_name}=1"
    return None, "public constructor has no single-round parameter"


def _recover_input(primitive, bijectivity_obligation: bool) -> str:
    if not bijectivity_obligation:
        return next(iter(primitive.input_ports))
    preferred_roles = ("plaintext", "state", "input_state", "input")
    by_role = {primitive.input_descriptor(name).role: name for name in primitive.input_ports}
    for role in preferred_roles:
        if role in by_role:
            return by_role[role]
    return next(iter(primitive.input_ports))


def _worker(primitive_index: int, parameter_index: int, timeout: float, repetitions: int) -> dict:
    from claasp.catalogue import catalogue
    from claasp.primitives._catalogue_exports import load_export

    record = catalogue.primitives()[primitive_index]
    parameter_set = record.parameter_sets[parameter_index]
    result = {
        "primitive": record.name,
        "category": record.category,
        "parameter_set": parameter_set.name,
        "parameters": dict(parameter_set.values),
        "bijectivity_obligation": record.bijectivity_obligation,
    }
    started = time.perf_counter()
    try:
        primitive_class = load_export(record.name)
        primitive = primitive_class(**dict(parameter_set.values))
    except Exception as error:  # pragma: no cover - audit records arbitrary catalogue failures
        result.update(
            status="construction-error",
            diagnostic=f"{type(error).__name__}: {error}",
            elapsed_ms=(time.perf_counter() - started) * 1000,
        )
        return result

    result.update(
        graph_rounds=len(primitive.rounds),
        components=len(primitive.components),
        bindings=len(primitive.bindings),
    )
    if not primitive.input_ports:
        result.update(
            status="not-applicable",
            diagnostic="primitive has no input to recover",
            one_round_status="not-applicable",
            one_round_diagnostic="primitive has no input to recover",
        )
        return result
    recover_input = _recover_input(primitive, record.bijectivity_obligation)
    result["recover_input"] = recover_input

    try:
        one_round, one_round_basis = _one_round_instance(
            primitive_class,
            dict(parameter_set.values),
            len(primitive.rounds),
        )
    except Exception as error:
        result.update(
            one_round_status="construction-error",
            one_round_basis="constructor override",
            one_round_diagnostic=f"{type(error).__name__}: {error}",
        )
    else:
        result["one_round_basis"] = one_round_basis
        if one_round is None:
            result["one_round_status"] = "unavailable"
        else:
            one_round_result = _attempt_inversion(
                one_round,
                recover_input,
                timeout,
                repetitions,
            )
            result.update((f"one_round_{name}", value) for name, value in one_round_result.items())
            result["one_round_graph_rounds"] = len(one_round.rounds)

    full_result = _attempt_inversion(
        primitive,
        recover_input,
        timeout,
        repetitions,
    )
    result.update(full_result)
    if "inversion_ms" in result:
        result["normalized_ms_per_graph_round"] = result["inversion_ms"] / len(primitive.rounds)
    return result


def _worker_main(arguments) -> int:
    result = _worker(
        arguments.primitive_index,
        arguments.parameter_index,
        arguments.timeout,
        arguments.repetitions,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


def _run_isolated(task, timeout: float, repetitions: int) -> dict:
    primitive_index, parameter_index, identity = task
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--worker",
        str(primitive_index),
        str(parameter_index),
        "--timeout",
        str(timeout),
        "--repetitions",
        str(repetitions),
    ]
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = str(ROOT / "src")
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout * (2 * repetitions + 3) + 10,
            env=environment,
        )
    except subprocess.TimeoutExpired:
        return {
            **identity,
            "status": "worker-timeout",
            "diagnostic": "isolated audit worker exceeded its outer deadline",
        }
    if completed.returncode:
        detail = completed.stderr.strip().splitlines()
        return {
            **identity,
            "status": "worker-error",
            "diagnostic": detail[-1] if detail else f"worker exited {completed.returncode}",
        }
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {
            **identity,
            "status": "worker-error",
            "diagnostic": "worker did not return one JSON result",
        }


def _git_revision() -> str:
    return subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _escape(value) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _milliseconds(value) -> str:
    return "—" if value is None else f"{value:.3f}"


def _write_report(
    results: list[dict],
    destination: Path,
    timeout: float,
    repetitions: int,
    jobs: int,
) -> None:
    statuses = Counter(item["status"] for item in results)
    by_category = defaultdict(list)
    for item in results:
        by_category[item["category"]].append(item)
    verified_primitives = {item["primitive"] for item in results if item["status"] == "verified"}
    fully_verified = {
        name
        for name in {item["primitive"] for item in results}
        if all(item["status"] == "verified" for item in results if item["primitive"] == name)
    }
    one_round_statuses = Counter(item.get("one_round_status", "not-run") for item in results)
    obligated = [item for item in results if item["bijectivity_obligation"]]
    unobligated = [item for item in results if not item["bijectivity_obligation"]]
    slowest = sorted(
        (item for item in results if item["status"] == "verified"),
        key=lambda item: item["inversion_ms"],
        reverse=True,
    )[:10]
    lines = [
        "# Primitive inversion audit",
        "",
        f"Generated at {datetime.now(UTC).isoformat(timespec='seconds')} from commit "
        f"`{_git_revision()}` on {platform.platform()}, Python {platform.python_version()}.",
        "",
        "## Scope and interpretation",
        "",
        "This audit covers every public primitive and every named parameter set in the "
        "committed v5 catalogue, including toy and single-component primitives. The "
        "operation under test recovers the catalogue-designated data/state input from the primitive "
        "output while retaining every other primitive input. The bijectivity obligation therefore "
        "describes that retained-input map, not global bijectivity of a multi-input function. "
        "For a primitive without a "
        "bijectivity obligation, the first input remains the explicitly qualified recovery "
        "target. Therefore, **verified** means that "
        "the current solver-free graph transformation constructed an inverse and recovered "
        "the original target input for two deterministic semantic samples. It does not mean "
        "that a multi-input primitive is globally bijective without retained inputs.",
        "",
        "The catalogue's bijectivity obligation is reported independently. A `yes` is a "
        "specification/classification claim; a failed transformation on such a row identifies "
        "a methodology gap, not proof that the mathematical primitive is non-invertible. "
        "The obligation is attached to each named catalogue configuration; constructors that "
        "accept arbitrary tables, matrices, or domains can also create non-bijective graphs "
        "outside those named configurations.",
        "Fixed semantic evidence separately records Fancy's lossy odd-round collision and "
        "collisions in ToyAES's optional two-bit-word teaching variants; neither negative "
        "case changes the positive obligation of ToyAES's named eight-bit-word configuration.",
        "",
        f"Inverse construction was measured {repetitions} time(s) per successful configuration "
        f"and the median is shown. Each attempt had a {timeout:g}-second limit, with {jobs} "
        "isolated workers running concurrently. `1-round ms` is a separately constructed public "
        "configuration using `number_of_rounds=1` or `number_of_steps=1`; a one-graph-round "
        "primitive reuses its full measurement. `ms/round` is also supplied as the full "
        "construction time divided by immutable graph-round count. Construction of the forward "
        "graph and semantic evaluation are excluded from inversion timings.",
        "",
        "## Summary",
        "",
        f"- Public primitives: **{len({item['primitive'] for item in results})}**",
        f"- Official parameter sets checked: **{len(results)}**",
        f"- Primitives with at least one verified configuration: **{len(verified_primitives)}**",
        f"- Primitives verified for every official configuration: **{len(fully_verified)}**",
        "- Configuration outcomes: "
        + ", ".join(f"**{count} {status}**" for status, count in sorted(statuses.items())),
        f"- Retained-input-bijective catalogue configurations verified by the current transformation: "
        f"**{sum(item['status'] == 'verified' for item in obligated)}/{len(obligated)}**",
        f"- Configurations without a catalogue bijectivity obligation that still support "
        f"first-input recovery with auxiliaries: **{sum(item['status'] == 'verified' for item in unobligated)}/{len(unobligated)}**",
        "- One-round outcomes: "
        + ", ".join(
            f"**{count} {status}**" for status, count in sorted(one_round_statuses.items())
        ),
        "",
        "| Category | Primitives | Configurations | Verified | Not supported | Timed out | Other |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for category, items in sorted(by_category.items()):
        category_statuses = Counter(item["status"] for item in items)
        timed_out = category_statuses["timeout"] + category_statuses["worker-timeout"]
        other = (
            len(items)
            - category_statuses["verified"]
            - category_statuses["not-supported"]
            - timed_out
        )
        lines.append(
            f"| `{category}` | {len({item['primitive'] for item in items})} | {len(items)} | "
            f"{category_statuses['verified']} | {category_statuses['not-supported']} | "
            f"{timed_out} | {other} |"
        )

    reasons = Counter(
        item.get("failure_reason", item["status"])
        for item in results
        if item["status"] != "verified"
    )
    lines.extend(
        [
            "",
            "### Failure and stall diagnostics",
            "",
            "| Diagnostic class | Configurations |",
            "|---|---:|",
            *[f"| `{reason}` | {count} |" for reason, count in sorted(reasons.items())],
            "",
            "### Slowest verified full inversions",
            "",
            "| Primitive | Parameter set | Full ms | Graph rounds | ms/round |",
            "|---|---|---:|---:|---:|",
            *[
                f"| `{item['primitive']}` | `{item['parameter_set']}` | "
                f"{item['inversion_ms']:.3f} | {item['graph_rounds']} | "
                f"{item['normalized_ms_per_graph_round']:.3f} |"
                for item in slowest
            ],
            "",
            "## Methodology status",
            "",
            "This report is the acceptance evidence for tracker slice `M10.10h`. Its catalogue "
            "completeness condition is that every configuration carrying a bijectivity obligation "
            "has status `verified`. At this checkpoint, "
            f"**{sum(item['status'] == 'verified' for item in obligated)}/{len(obligated)}** "
            "such configurations satisfy that condition.",
            "",
            "Non-verified rows remain visible because the audit also probes first-input recovery "
            "for hashes, stream-output functions, lossy teaching components, and other primitives without "
            "a catalogue bijectivity obligation. They are qualified results, not gaps in the "
            "bijective coverage claim. Future optimization can use the slowest-results table to "
            "prioritize graph construction cost, but must retain the same solver-free contracts, "
            "typed failures, provenance, and independent semantic round trips.",
            "",
            "## Configuration results",
            "",
            "Times are milliseconds. Parameters are the exact values passed to the public constructor.",
        ]
    )
    for category, items in sorted(by_category.items()):
        lines.extend(
            [
                "",
                f"### {category}",
                "",
                "| Primitive | Parameter set | Parameters | Recover | Obligation | Graph rounds | Components | 1-round outcome | 1-round ms | Full outcome | Full ms | ms/round | Semantic | Diagnostic |",
                "|---|---|---|---|:---:|---:|---:|---|---:|---|---:|---:|:---:|---|",
            ]
        )
        for item in sorted(items, key=lambda value: (value["primitive"], value["parameter_set"])):
            parameters = json.dumps(item["parameters"], sort_keys=True, separators=(",", ":"))
            semantic = (
                f"{item.get('semantic_passes', 0)}/{item.get('semantic_samples', 0)}"
                if "semantic_samples" in item
                else "—"
            )
            diagnostic = item.get("failure_reason", "")
            if item.get("diagnostic"):
                detail = item["diagnostic"]
                if diagnostic and detail.startswith(f"{diagnostic}: "):
                    detail = detail[len(diagnostic) + 2 :]
                diagnostic += (": " if diagnostic else "") + detail
            one_round_status = item.get("one_round_status", "not-run")
            one_round_diagnostic = item.get("one_round_diagnostic")
            if one_round_diagnostic and one_round_status != "verified":
                one_round_status += f": {one_round_diagnostic}"
            lines.append(
                f"| `{item['primitive']}` | `{item['parameter_set']}` | `{_escape(parameters)}` | "
                f"`{item.get('recover_input', '—')}` | "
                f"{'yes' if item['bijectivity_obligation'] else 'no'} | "
                f"{item.get('graph_rounds', '—')} | {item.get('components', '—')} | "
                f"`{_escape(one_round_status)}` | {_milliseconds(item.get('one_round_inversion_ms'))} | "
                f"`{item['status']}` | {_milliseconds(item.get('inversion_ms'))} | "
                f"{_milliseconds(item.get('normalized_ms_per_graph_round'))} | {semantic} | "
                f"{_escape(diagnostic) if diagnostic else '—'} |"
            )

    lines.extend(
        [
            "",
            "## Reproduction",
            "",
            "From ``:",
            "",
            "```console",
            "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3.11 tools/audit_primitive_inversion.py",
            "```",
            "",
            "The report is a point-in-time benchmark. Compare future methodology changes on the "
            "same machine, Python version, timeout, and repetition count.",
            "",
        ]
    )
    destination.write_text("\n".join(lines), encoding="utf-8")


def _parent_main(arguments) -> int:
    from claasp.catalogue import catalogue

    tasks = []
    for primitive_index, record in enumerate(catalogue.primitives()):
        for parameter_index, parameter_set in enumerate(record.parameter_sets):
            tasks.append(
                (
                    primitive_index,
                    parameter_index,
                    {
                        "primitive": record.name,
                        "category": record.category,
                        "parameter_set": parameter_set.name,
                        "parameters": dict(parameter_set.values),
                        "bijectivity_obligation": record.bijectivity_obligation,
                    },
                )
            )
    results = []
    with ThreadPoolExecutor(max_workers=arguments.jobs) as executor:
        futures = {
            executor.submit(_run_isolated, task, arguments.timeout, arguments.repetitions): task
            for task in tasks
        }
        for completed, future in enumerate(as_completed(futures), 1):
            result = future.result()
            results.append(result)
            print(
                f"[{completed:3}/{len(tasks)}] {result['primitive']}:{result['parameter_set']} "
                f"{result['status']}",
                flush=True,
            )
    destination = Path(arguments.output).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    _write_report(results, destination, arguments.timeout, arguments.repetitions, arguments.jobs)
    print(f"wrote {destination}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=DEFAULT_REPORT)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("primitive_index", nargs="?", type=int)
    parser.add_argument("parameter_index", nargs="?", type=int)
    arguments = parser.parse_args()
    if arguments.timeout <= 0 or arguments.repetitions <= 0 or arguments.jobs <= 0:
        parser.error("timeout, repetitions, and jobs must be positive")
    if arguments.worker:
        if arguments.primitive_index is None or arguments.parameter_index is None:
            parser.error("worker mode requires primitive and parameter-set indexes")
        return _worker_main(arguments)
    return _parent_main(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
