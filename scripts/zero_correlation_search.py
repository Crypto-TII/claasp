#!/usr/bin/env python3
"""Zero-correlation search on Keccak-p[800] (32-bit lanes) for one round count.

Reproduces the zero-correlation searches of CLAASP campaign 20261011-161107-keccak-addecf
(CLAASP commit 412000306ee381e9d4bc1680ebc85bba6c55ee70). Run it in a CLAASP environment with
the solvers on PATH, for example:

    sage -python zero_correlation_search.py --rounds 1 --backend sat --time-limit 7800
    sage -python zero_correlation_search.py --rounds 3 --backend smt --first 0 --last 99

zero_correlation_search_loop.py (same folder) runs this search for a range of round counts.

This is the loop CLAASP's Cipher.zero_correlation_linear_search runs on KeccakPermutation
(Cipher.find_impossible_property with type "linear"), written out so that every result is printed
as soon as it is found. For each one-bit input mask i and one-bit output mask j it asks the solver
for any linear trail; UNSATISFIABLE means no trail connects the two masks, so their correlation is
exactly zero in CLAASP's model. A full sweep is 800 x 800 = 640,000 solver calls, which is why every
campaign run ended at its time limit with nothing. --first/--last restrict the input bits so a sweep
can be split across processes. Mask bit k means the integer 1 << k (CLAASP writes it big-endian).

Backends (--backend), each through CLAASP's Cipher.model(<backend>, "xor_linear"):
    sat   SatXorLinearModel,  Kissat (KISSAT_EXT), as in the campaign
    cp    MznXorLinearModel,  MiniZinc + OR-Tools CP-SAT with <threads> processors
    milp  MilpXorLinearModel, SCIP (SCIP_EXT) with OMP_NUM_THREADS=<threads>
    smt   SmtXorLinearModel,  Z3 (Z3_EXT)
--time-limit stops the sweep after that many seconds and reports what it found so far.
"""
import argparse
import json
import os
import signal
import sys
import time

BACKENDS = ("cp", "milp", "sat", "smt")


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
    """Kill the solver processes this script started, so none outlives a stopped search (Linux, via /proc)."""
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


def solver_kwargs(backend, threads):
    if backend == "sat":
        return {"solver_name": "KISSAT_EXT"}
    if backend == "cp":
        return {"solver_name": "cp-sat", "num_of_processors": threads}
    if backend == "milp":
        os.environ["OMP_NUM_THREADS"] = str(threads)
        return {"solver_name": "SCIP_EXT", "external_solver_name": "SCIP_EXT"}
    return {"solver_name": "Z3_EXT"}


def add_options(ap):
    """Options shared by this script and zero_correlation_search_loop.py (all but --rounds and the time limit)."""
    ap.add_argument("--backend", choices=BACKENDS, default="sat")
    ap.add_argument("--threads", type=int, default=1, help="cp: processors; milp: OMP threads")
    ap.add_argument("--first", type=int, default=0, help="first input-mask bit")
    ap.add_argument("--last", type=int, default=799, help="last input-mask bit")


def search_round(rounds, args, time_limit):
    """Sweep one round count; returns (summary, None, whole_run_stopped)."""
    import sage.all  # noqa: F401 -- load Sage before CLAASP: with some Sage versions (9.5) importing CLAASP
    # first fails with "ImportError: cannot import name ZZ"
    from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
    from claasp.ciphers.permutations.keccak_permutation import KeccakPermutation

    summary = {"technique": "zero_correlation", "rounds": rounds, "backend": args.backend, "status": None}
    found, checked, finished_inputs = [], 0, []
    start = last_report = time.time()
    whole_run_stopped = False
    try:
        if time_limit:
            signal.alarm(time_limit)
        cipher = KeccakPermutation(number_of_rounds=rounds, word_size=32)
        n = cipher.inputs_size_to_dict()["plaintext"]  # 800
        output_id = cipher.all_components()[-1].id  # the component CLAASP's own search constrains
        model = cipher.model(args.backend, "xor_linear")
        kwargs = solver_kwargs(args.backend, args.threads)
        last = min(args.last, n - 1)
        summary.update(first_input_bit=args.first, last_input_bit=last, pairs_in_range=(last - args.first + 1) * n)

        def single_bit(component_id, bit):
            return set_fixed_variables(component_id, "equal", list(range(n)), integer_to_bit_list(1 << bit, n, "big"))

        for i in range(args.first, last + 1):
            for j in range(n):
                fixed = [single_bit("plaintext", i), single_bit(output_id, j)]
                solution = model.find_one_xor_linear_trail(fixed, **kwargs)
                checked += 1
                if solution["status"] == "UNSATISFIABLE":
                    found.append([i, j])
                    print(f"round {rounds}: zero correlation: input mask bit {i} -> output mask bit {j}", flush=True)
                if time.time() - last_report >= 60:
                    last_report = time.time()
                    print(f"progress: round {rounds}, input bit {i}, output bit {j}; "
                          f"{checked} pairs in {last_report - start:.0f} s", file=sys.stderr, flush=True)
            finished_inputs.append(i)
        signal.alarm(0)
        summary["status"] = "COMPLETED"
    except TimeUp:
        summary.update(status="STOPPED", stopped_by="time limit")
    except (Stopped, KeyboardInterrupt):
        summary.update(status="STOPPED", stopped_by="interrupted")
        whole_run_stopped = True
    except Exception as exc:  # noqa: BLE001 -- report it instead of crashing
        summary.update(status="ERROR", error=f"{type(exc).__name__}: {exc}"[:500])
    finally:
        signal.alarm(0)
    if summary["status"] != "COMPLETED":
        stop_solvers()
    elapsed = time.time() - start
    rate = checked / elapsed if elapsed > 0 else None
    summary.update(pairs_checked=checked, zero_correlation_pairs=len(found), zero_correlation_pairs_list=found[:1000],
                   input_bits_finished=len(finished_inputs), wall_seconds=round(elapsed, 1),
                   pairs_per_second=round(rate, 4) if rate else None,
                   estimated_hours_for_all_640000_pairs=round(640000 / rate / 3600, 1) if rate else None)
    return summary, None, whole_run_stopped


def overview(s):
    text = (f"{s['status']}" + (f" ({s['stopped_by']})" if s.get("stopped_by") else "")
            + f", {s['pairs_checked']} pairs checked, {s['zero_correlation_pairs']} with zero correlation")
    if s.get("error"):
        text += f", error: {s['error']}"
    return f"round {s['rounds']} ({s['backend']}): {text}, {s['wall_seconds']} s"


def report(summary, solution, args):
    print(overview(summary))
    print("RESULT " + json.dumps(summary, default=str), flush=True)


def main():
    ap = argparse.ArgumentParser(description="Zero-correlation search on Keccak-p[800], one round count")
    ap.add_argument("--rounds", type=int, required=True, help="number of rounds to analyze")
    ap.add_argument("--time-limit", type=int, help="seconds before the sweep is stopped")
    add_options(ap)
    args = ap.parse_args()
    install_signal_handlers()
    print_claasp_location()
    summary, solution, _ = search_round(args.rounds, args, args.time_limit)
    report(summary, solution, args)
    raise SystemExit({"STOPPED": 124, "ERROR": 1}.get(summary["status"], 0))


if __name__ == "__main__":
    main()
