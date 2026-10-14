#!/usr/bin/env python3
"""Run differential_search.py's search for every round count in --rounds, one after another.

Same options as differential_search.py, except that --rounds takes one round count (3), a range (1-6) or a list
(1,3,5), and --time-per-round gives each round its own time limit: a round that runs out is reported
as STOPPED and the next round starts. An outer `timeout` (SIGTERM) or Ctrl-C stops the whole run
after reporting the current round. Keep this file next to differential_search.py, which holds the search itself.

    sage -python differential_search_loop.py --rounds 1-6 --backend sat --threads 16 --time-per-round 7800
"""
import argparse

import differential_search as one


def parse_rounds(text):
    rounds = []
    for part in text.split(","):
        first, _, last = part.partition("-")
        rounds.extend(range(int(first), int(last or first) + 1))
    return rounds


def main():
    ap = argparse.ArgumentParser(description="differential_search for a range of round counts")
    ap.add_argument("--rounds", required=True, help="one round count (3), a range (1-6) or a list (1,3,5)")
    ap.add_argument("--time-per-round", type=int, help="seconds each round may use before the next round starts")
    one.add_options(ap)
    args = ap.parse_args()
    if hasattr(one, "check_options"):
        one.check_options(ap, args)
    one.install_signal_handlers()
    one.print_claasp_location()
    results, stopped = [], False
    for rounds in parse_rounds(args.rounds):
        summary, solution, stopped = one.search_round(rounds, args, args.time_per_round)
        one.report(summary, solution, args)
        results.append(summary)
        if stopped:
            break
    print("overview:")
    for summary in results:
        print("  " + one.overview(summary), flush=True)
    raise SystemExit(124 if stopped else 0)


if __name__ == "__main__":
    main()
