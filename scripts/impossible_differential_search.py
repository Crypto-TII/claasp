#!/usr/bin/env python3
"""Impossible-differential search on Keccak-p[800] (32-bit lanes) for one round count, two methods.

Reproduces the impossible-differential searches of CLAASP campaign 20261011-161107-keccak-addecf
(CLAASP commit 412000306ee381e9d4bc1680ebc85bba6c55ee70). Run it in a CLAASP environment with
the solvers on PATH, for example:

    sage -python impossible_differential_search.py --rounds 2 --method mitm --backend sat --time-limit 7800
    sage -python impossible_differential_search.py --rounds 1 --method pairwise --backend smt --first 0 --last 99

impossible_differential_search_loop.py (same folder) runs this search for a range of round counts.

mitm (campaign rounds 2-6): CLAASP's meet-in-the-middle models on KeccakInvertiblePermutation
    (they need the inverse cipher). They look for a nonzero input and output difference whose forward
    and backward propagations contradict each other at --middle-round (default max(1, rounds // 2),
    as in the campaign). SATISFIABLE means an impossible differential was found (printed as bit
    patterns; ? marks a bit the model leaves undetermined, and repeated runs may return different
    patterns); UNSATISFIABLE only means the model found none at that middle round, not that none
    exists. Backends:
        sat   SatBitwiseImpossibleXorDifferentialModel, ParKissat (PARKISSAT_EXT) with -c=<threads> (campaign)
        milp  MilpBitwiseImpossibleXorDifferentialModel, SCIP (SCIP_EXT) with OMP_NUM_THREADS=<threads>
        cp    MznImpossibleXorDifferentialModel, MiniZinc + OR-Tools CP-SAT with <threads> processors
        smt   not available: CLAASP has no SMT meet-in-the-middle model (use --method pairwise)

pairwise (campaign round 1): the loop CLAASP's Cipher.impossible_differential_search runs
    (scenario "non-key") on KeccakPermutation, written out so that every result is printed as soon
    as it is found. For each one-bit input difference i and one-bit output difference j it asks the
    solver for any differential trail; UNSATISFIABLE means the pair (i, j) is impossible. A full sweep
    is 800 x 800 = 640,000 solver calls; --first/--last restrict the input bits so a sweep can be
    split across processes. Bit k means the integer 1 << k (CLAASP writes it big-endian). Backends,
    each through CLAASP's Cipher.model(<backend>, "xor_differential"):
        sat   SatXorDifferentialModel,  Kissat (KISSAT_EXT), as in the campaign
        cp    MznXorDifferentialModel,  MiniZinc + OR-Tools CP-SAT with <threads> processors
        milp  MilpXorDifferentialModel, SCIP (SCIP_EXT) with OMP_NUM_THREADS=<threads>
        smt   SmtXorDifferentialModel,  Z3 (Z3_EXT)

--time-limit stops the search after that many seconds, kills the solver processes and reports
STOPPED (for pairwise, with what it found so far).
"""
import argparse
import json
import os
import signal
import sys
import time

BACKENDS = ("cp", "milp", "sat", "smt")
MITM_BACKENDS = ("cp", "milp", "sat")


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


def cipher_output_id(cipher):
    return [c.id for c in cipher.all_components() if c.type == "cipher_output"][-1]


def threads_for(args):
    if args.threads:
        return args.threads
    return 16 if args.method == "mitm" else 1  # the campaign's settings


def add_options(ap):
    """Options shared by this script and impossible_differential_search_loop.py (all but --rounds and the time limit)."""
    ap.add_argument("--method", choices=("mitm", "pairwise"), default="mitm")
    ap.add_argument("--backend", choices=BACKENDS, default="sat")
    ap.add_argument("--threads", type=int, help="solver threads/processors (default: 16 for mitm, 1 for pairwise)")
    ap.add_argument("--middle-round", type=int, help="mitm: default max(1, rounds // 2)")
    ap.add_argument("--first", type=int, default=0, help="pairwise: first input bit")
    ap.add_argument("--last", type=int, default=799, help="pairwise: last input bit")


def check_options(ap, args):
    if args.method == "mitm" and args.backend not in MITM_BACKENDS:
        ap.error("CLAASP has no SMT meet-in-the-middle impossible-differential model; "
                 "use --backend sat, milp or cp, or --method pairwise")


def run_mitm(rounds, args, time_limit, summary):
    from claasp.cipher_modules.models.utils import set_fixed_variables
    from claasp.ciphers.permutations.keccak_invertible_permutation import KeccakInvertiblePermutation

    if args.backend not in MITM_BACKENDS:
        raise ValueError("CLAASP has no SMT meet-in-the-middle impossible-differential model; "
                         "use --backend sat, milp or cp, or --method pairwise")
    threads = threads_for(args)
    cipher = KeccakInvertiblePermutation(number_of_rounds=rounds, word_size=32)
    n = cipher.inputs_size_to_dict()["plaintext"]  # 800
    output_id = cipher_output_id(cipher)
    middle_round = args.middle_round or max(1, rounds // 2)
    summary.update(middle_round=middle_round, threads=threads)

    def nonzero(component_id):
        return set_fixed_variables(component_id, "not_equal", list(range(n)), [0] * n)

    if args.backend == "sat":
        from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_impossible_xor_differential_model import (
            SatBitwiseImpossibleXorDifferentialModel,
        )
        solution = call_with_retries("sat", lambda: SatBitwiseImpossibleXorDifferentialModel(cipher).find_one_bitwise_impossible_xor_differential_trail(
            middle_round=middle_round, fixed_values=[nonzero("plaintext"), nonzero(output_id)],
            solver_name="PARKISSAT_EXT", options=[f"-c={threads}"]), summary)
    elif args.backend == "milp":
        from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_impossible_xor_differential_model import (
            MilpBitwiseImpossibleXorDifferentialModel,
        )
        os.environ["OMP_NUM_THREADS"] = str(threads)
        model = MilpBitwiseImpossibleXorDifferentialModel(cipher)
        solution = model.find_one_bitwise_impossible_xor_differential_trail(
            middle_round=middle_round, fixed_values=[nonzero("plaintext"), nonzero(output_id)],
            solver_name="SCIP_EXT", external_solver_name="SCIP_EXT")
    else:
        from claasp.cipher_modules.models.cp.mzn_models.mzn_impossible_xor_differential_model import (
            MznImpossibleXorDifferentialModel,
        )
        model = MznImpossibleXorDifferentialModel(cipher)
        # the CP model constrains the output through the inverse cipher's output component
        solution = model.find_one_impossible_xor_differential_trail(
            number_of_rounds=rounds, fixed_values=[nonzero("plaintext"), nonzero("inverse_" + output_id)],
            solver_name="cp-sat", initial_round=1, middle_round=middle_round, final_round=rounds,
            num_of_processors=threads,
            # milliseconds: this CLAASP model passes it unchanged to MiniZinc's --time-limit
            timelimit=time_limit * 1000 if time_limit else None)
    signal.alarm(0)
    if isinstance(solution, list):  # some CLAASP versions wrap a single solution in a list
        solution = solution[0] if solution else {"status": "UNSATISFIABLE"}
    values = solution.get("components_values") or {}
    output = values.get(output_id) or values.get("inverse_" + output_id) or {}
    summary.update(status=str(solution.get("status", "")), solving_seconds=solution.get("solving_time_seconds"),
                   input_difference=(values.get("plaintext") or {}).get("value"), output_difference=output.get("value"))
    return solution


def run_pairwise(rounds, args, summary, progress):
    from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
    from claasp.ciphers.permutations.keccak_permutation import KeccakPermutation

    threads = threads_for(args)
    summary["threads"] = threads
    cipher = KeccakPermutation(number_of_rounds=rounds, word_size=32)
    n = cipher.inputs_size_to_dict()["plaintext"]  # 800
    output_id = cipher.all_components()[-1].id  # the component CLAASP's own search constrains
    model = cipher.model(args.backend, "xor_differential")
    if args.backend == "sat":
        kwargs = {"solver_name": "KISSAT_EXT"}
    elif args.backend == "cp":
        kwargs = {"solver_name": "cp-sat", "num_of_processors": threads}
    elif args.backend == "milp":
        os.environ["OMP_NUM_THREADS"] = str(threads)
        kwargs = {"solver_name": "SCIP_EXT", "external_solver_name": "SCIP_EXT"}
    else:
        kwargs = {"solver_name": "Z3_EXT"}
    last = min(args.last, n - 1)
    summary.update(first_input_bit=args.first, last_input_bit=last, pairs_in_range=(last - args.first + 1) * n)

    def single_bit(component_id, bit):
        return set_fixed_variables(component_id, "equal", list(range(n)), integer_to_bit_list(1 << bit, n, "big"))

    start = last_report = time.time()
    for i in range(args.first, last + 1):
        for j in range(n):
            fixed = [single_bit("plaintext", i), single_bit(output_id, j)]
            solution = model.find_one_xor_differential_trail(fixed, **kwargs)
            progress["checked"] += 1
            if solution["status"] == "UNSATISFIABLE":
                progress["found"].append([i, j])
                print(f"round {rounds}: impossible: input difference bit {i} -> output difference bit {j}", flush=True)
            if time.time() - last_report >= 60:
                last_report = time.time()
                print(f"progress: round {rounds}, input bit {i}, output bit {j}; "
                      f"{progress['checked']} pairs in {last_report - start:.0f} s", file=sys.stderr, flush=True)
        progress["finished_inputs"] += 1
    signal.alarm(0)
    summary["status"] = "COMPLETED"


def search_round(rounds, args, time_limit):
    """Run the search for one round count; returns (summary, solution, whole_run_stopped)."""
    import sage.all  # noqa: F401 -- load Sage before CLAASP: with some Sage versions (9.5) importing CLAASP
    # first fails with "ImportError: cannot import name ZZ"
    summary = {"technique": "impossible_differential", "rounds": rounds, "method": args.method,
               "backend": args.backend, "status": None}
    progress = {"checked": 0, "found": [], "finished_inputs": 0}
    solution, whole_run_stopped = None, False
    start = time.time()
    try:
        if time_limit:
            signal.alarm(time_limit)
        if args.method == "mitm":
            solution = run_mitm(rounds, args, time_limit, summary)
        else:
            run_pairwise(rounds, args, summary, progress)
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
    elapsed = time.time() - start
    summary["wall_seconds"] = round(elapsed, 1)
    if args.method == "pairwise":
        rate = progress["checked"] / elapsed if elapsed > 0 else None
        summary.update(pairs_checked=progress["checked"], impossible_pairs=len(progress["found"]),
                       impossible_pairs_list=progress["found"][:1000], input_bits_finished=progress["finished_inputs"],
                       pairs_per_second=round(rate, 4) if rate else None,
                       estimated_hours_for_all_640000_pairs=round(640000 / rate / 3600, 1) if rate else None)
    return summary, solution, whole_run_stopped


def overview(s):
    status = s["status"]
    head = f"round {s['rounds']} ({s['method']}, {s['backend']}): "
    if status == "ERROR":
        return head + f"error: {s['error']}, {s['wall_seconds']} s"
    if s["method"] == "pairwise":
        return head + (f"{status}" + (f" ({s['stopped_by']})" if s.get("stopped_by") else "")
                       + f", {s['pairs_checked']} pairs checked, {s['impossible_pairs']} impossible, {s['wall_seconds']} s")
    if status == "STOPPED":
        text = f"stopped ({s.get('stopped_by')}) before the solver answered: inconclusive"
    elif status.upper().startswith("SAT"):
        text = f"SATISFIABLE: impossible differential found at middle round {s.get('middle_round')}"
    elif status.upper().startswith("UNSAT"):
        text = (f"UNSATISFIABLE: no contradiction at middle round {s.get('middle_round')} "
                "(not a proof that no impossible differential exists)")
    else:
        text = status
    return head + f"{text}, {s['wall_seconds']} s"


def report(summary, solution, args):
    print(overview(summary))
    if summary.get("input_difference"):
        print("  bit patterns: 0 = no difference, 1 = difference, ? = bit left undetermined by the model")
        print(f"  input difference:  {summary['input_difference']}")
        print(f"  output difference: {summary['output_difference']}")
    print("RESULT " + json.dumps(summary, default=str), flush=True)


def main():
    ap = argparse.ArgumentParser(description="Impossible-differential search on Keccak-p[800], one round count")
    ap.add_argument("--rounds", type=int, required=True, help="number of rounds to analyze")
    ap.add_argument("--time-limit", type=int, help="seconds before the search is stopped")
    add_options(ap)
    args = ap.parse_args()
    check_options(ap, args)
    install_signal_handlers()
    print_claasp_location()
    summary, solution, _ = search_round(args.rounds, args, args.time_limit)
    report(summary, solution, args)
    raise SystemExit({"STOPPED": 124, "ERROR": 1}.get(summary["status"], 0))


if __name__ == "__main__":
    main()
