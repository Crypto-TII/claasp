#!/usr/bin/env python3
"""Lowest-weight XOR differential trail of Keccak-p[800] (32-bit lanes) for one round count.

Reproduces the differential searches of CLAASP campaign 20261011-161107-keccak-addecf
(CLAASP commit 412000306ee381e9d4bc1680ebc85bba6c55ee70). Run it in a CLAASP environment with
the solvers on PATH, for example:

    sage -python differential_search.py --rounds 2 --backend sat --threads 16 --time-limit 7800

differential_search_loop.py (same folder) runs this search for a range of round counts.

Backends (--backend), in the order of the campaign cascade:
    sat   SatXorDifferentialModel,  ParKissat (PARKISSAT_EXT) with -c=<threads>
    cp    MznXorDifferentialModel,  MiniZinc + OR-Tools CP-SAT (MZN_SOLVER_PATH must list cp-sat)
    milp  MilpXorDifferentialModel, SCIP (SCIP_EXT) with OMP_NUM_THREADS=<threads>
    smt   SmtXorDifferentialModel,  Z3 (Z3_EXT), single-threaded

The campaign ran these searches on KeccakSboxPermutation, CLAASP's Keccak-p representation with
chi written as a 5-bit S-box (approved as an equivalent of KeccakPermutation). The only constraint
is a nonzero input difference. The weight is -log2 of the probability of the single trail found.
--time-limit stops the search after that many seconds (CP-SAT also gets it natively), kills the
solver processes and reports STOPPED.
"""
import argparse
import importlib
import json
import os
import signal
import time

MODELS = {
    "sat": "claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model.SatXorDifferentialModel",
    "cp": "claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_model.MznXorDifferentialModel",
    "milp": "claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model.MilpXorDifferentialModel",
    "smt": "claasp.cipher_modules.models.smt.smt_models.smt_xor_differential_model.SmtXorDifferentialModel",
}


class TimeUp(BaseException):
    """The time limit for this round ran out (SIGALRM)."""


class Stopped(BaseException):
    """`timeout` (SIGTERM) or Ctrl-C ended the run."""


def _time_up(signum, frame):
    # Kill solvers while the process tree is intact: on the way out, subprocess.run kills only its direct
    # child, and CLAASP starts SCIP through a shell, so SCIP would otherwise be orphaned and keep running.
    stop_solvers()
    raise TimeUp()


def _stop(signum, frame):
    stop_solvers()
    raise Stopped()


def install_signal_handlers():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGALRM, _time_up)


def print_claasp_location():
    import claasp
    print(f"CLAASP: {os.path.dirname(claasp.__file__)}", flush=True)


def stop_solvers():
    """Kill the solver processes this script started. SCIP keeps running after SIGTERM, so solvers are
    killed explicitly whenever a search is stopped (Linux, via /proc)."""
    if not os.path.isdir("/proc"):
        return
    parent_of = {}
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            try:
                with open(f"/proc/{entry}/stat") as fh:
                    parent_of[int(entry)] = int(fh.read().rsplit(")", 1)[1].split()[1])
            except (OSError, ValueError, IndexError):
                pass
    victims, frontier = [], {os.getpid()}
    while frontier:
        frontier = {pid for pid, ppid in parent_of.items() if ppid in frontier}
        victims.extend(frontier)
    for pid in victims:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


PARKISSAT_ATTEMPTS = 3


def call_with_retries(backend, call, summary):
    """Run call(); with ParKissat (backend sat), retry up to PARKISSAT_ATTEMPTS times when the solver run
    itself fails. Multi-threaded ParKissat intermittently garbles or truncates its output, or crashes, on
    quick instances (seen as ValueError/IndexError/RuntimeError inside CLAASP's parser); each failure is
    recorded in summary["solver_retries"]."""
    attempts = PARKISSAT_ATTEMPTS if backend == "sat" else 1
    for attempt in range(1, attempts + 1):
        try:
            return call()
        except Exception as exc:  # noqa: BLE001 -- TimeUp/Stopped are BaseException and pass through
            if attempt == attempts:
                raise
            summary.setdefault("solver_retries", []).append(f"attempt {attempt}: {type(exc).__name__}: {exc}"[:300])


def load(dotted):
    module, _, name = dotted.rpartition(".")
    return getattr(importlib.import_module(module), name)


def solver_kwargs(backend, threads, time_limit):
    """The solver settings the campaign's job runner passed to CLAASP for each backend."""
    if backend == "sat":
        return {"solver_name": "PARKISSAT_EXT", "options": [f"-c={threads}"]}
    if backend == "cp":
        # In seconds: CLAASP hands it to the minizinc package as timedelta(seconds=...), which converts it
        # to MiniZinc's --time-limit in milliseconds.
        return {"solver_name": "cp-sat", "num_of_processors": threads, "timelimit": time_limit}
    if backend == "milp":
        os.environ["OMP_NUM_THREADS"] = str(threads)
        return {"solver_name": "SCIP_EXT", "external_solver_name": "SCIP_EXT"}
    return {"solver_name": "Z3_EXT"}


def value(solution, component_id):
    values = solution.get("components_values") or {}
    for key in (component_id, component_id + "_o"):
        if key in values:
            return values[key].get("value")
    return None


def add_options(ap):
    """Options shared by this script and differential_search_loop.py (all but --rounds and the time limit)."""
    ap.add_argument("--backend", choices=sorted(MODELS), default="sat")
    ap.add_argument("--threads", type=int, default=16)
    ap.add_argument("--save", help="directory for the full CLAASP solution (round-<r>.json)")


def search_round(rounds, args, time_limit):
    """Run the search for one round count; returns (summary, solution, whole_run_stopped)."""
    import sage.all  # noqa: F401 -- load Sage before CLAASP: with some Sage versions (9.5) importing CLAASP
    # first fails with "ImportError: cannot import name ZZ"
    install_signal_handlers()  # importing Sage replaces the SIGALRM handler (cysignals): put ours back
    from claasp.cipher_modules.models.utils import set_fixed_variables
    from claasp.ciphers.permutations.keccak_sbox_permutation import KeccakSboxPermutation

    summary = {"technique": "differential", "rounds": rounds, "backend": args.backend, "threads": args.threads,
               "status": None}
    solution, whole_run_stopped = None, False
    start = time.time()
    try:
        if time_limit:
            signal.alarm(time_limit)
        cipher = KeccakSboxPermutation(number_of_rounds=rounds, word_size=32)
        n = cipher.inputs_size_to_dict()["plaintext"]  # 800
        output_id = [c.id for c in cipher.all_components() if c.type == "cipher_output"][-1]
        nonzero_input = set_fixed_variables("plaintext", "not_equal", list(range(n)), [0] * n)
        solution = call_with_retries(args.backend, lambda: load(MODELS[args.backend])(cipher).find_lowest_weight_xor_differential_trail(
            fixed_values=[nonzero_input], **solver_kwargs(args.backend, args.threads, time_limit)), summary)
        signal.alarm(0)
        summary.update(status=str(solution.get("status", "")), weight=solution.get("total_weight"),
                       input_difference=value(solution, "plaintext"), output_difference=value(solution, output_id),
                       solving_seconds=solution.get("solving_time_seconds"))
    except TimeUp:
        summary.update(status="STOPPED", stopped_by="time limit")
    except (Stopped, KeyboardInterrupt):
        summary.update(status="STOPPED", stopped_by="interrupted")
        whole_run_stopped = True
    except Exception as exc:  # noqa: BLE001 -- report it instead of crashing
        summary.update(status="ERROR", error=f"{type(exc).__name__}: {exc}"[:500])
    finally:
        signal.alarm(0)
    if summary["status"] in ("STOPPED", "ERROR"):
        stop_solvers()
    summary["wall_seconds"] = round(time.time() - start, 1)
    return summary, solution, whole_run_stopped


def overview(s):
    status = s["status"]
    if status == "STOPPED":
        text = f"stopped ({s.get('stopped_by')}) before the solver answered: no trail, no bound"
    elif status == "ERROR":
        text = f"error: {s['error']}"
    elif status.upper().startswith("UNSAT"):
        text = ("UNSAT cannot be right here (a trail always exists for a nonzero input difference): "
                "treat it as a backend/encoding failure, not as a bound")
    else:
        text = f"{status}, weight {s['weight']} (-log2 of the trail probability)"
    return f"round {s['rounds']} ({s['backend']}): {text}, {s['wall_seconds']} s"


def report(summary, solution, args):
    print(overview(summary))
    if summary.get("input_difference"):
        print(f"  input difference:  {summary['input_difference']}")
        print(f"  output difference: {summary['output_difference']}")
    if args.save and solution is not None:
        os.makedirs(args.save, exist_ok=True)
        with open(os.path.join(args.save, f"round-{summary['rounds']}.json"), "w") as fh:
            json.dump(solution, fh, indent=1, default=str)
    print("RESULT " + json.dumps(summary, default=str), flush=True)


def main():
    ap = argparse.ArgumentParser(description="Lowest-weight XOR differential trail of Keccak-p[800], one round count")
    ap.add_argument("--rounds", type=int, required=True, help="number of rounds to analyze")
    ap.add_argument("--time-limit", type=int, help="seconds before the search is stopped")
    add_options(ap)
    args = ap.parse_args()
    install_signal_handlers()
    print_claasp_location()
    summary, solution, _ = search_round(args.rounds, args, args.time_limit)
    report(summary, solution, args)
    raise SystemExit({"STOPPED": 124, "ERROR": 1}.get(summary["status"], 0))


if __name__ == "__main__":
    main()
