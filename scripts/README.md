# Keccak-p[800] search scripts

Standalone scripts that run CLAASP's differential, linear, zero-correlation and impossible-differential
searches on Keccak-p[800] (32-bit lanes). Each technique has two files:

| technique | one round count | several round counts |
|---|---|---|
| differential (lowest-weight trail) | `differential_search.py` | `differential_search_loop.py` |
| linear (lowest-weight trail) | `linear_search.py` | `linear_search_loop.py` |
| zero correlation | `zero_correlation_search.py` | `zero_correlation_search_loop.py` |
| impossible differential | `impossible_differential_search.py` | `impossible_differential_search_loop.py` |

A `*_loop.py` file imports its one-round script, so keep both in the same folder.

## 1. Start the CLAASP container

The container mounts the CLAASP checkout it is started from at `/home/sage/tii-claasp` and installs
CLAASP from it, so start it from a checkout that contains this `scripts/` folder.

**New container**, from the repository root:

```bash
make rundocker        # builds the "claasp" image, runs "make install", opens a shell in /home/sage/tii-claasp
# Apple Silicon: make rundocker-m1 (x86_64 image under emulation)
```

Then, inside the container:

```bash
cd /home/sage/tii-claasp/scripts
sage -python differential_search.py --rounds 1 --backend sat --time-limit 600
```

**Container that is already running**: find its name with `docker ps` and run the scripts from the host
with `docker exec`:

```bash
C=<container name>
docker exec -w /home/sage/tii-claasp $C make install      # only if CLAASP is not installed in it yet
docker exec -w /home/sage/tii-claasp/scripts $C sage -python differential_search.py --rounds 1 --backend sat --time-limit 600
```

The first line each script prints is `CLAASP: <path>`, the CLAASP installation it imported.

## 2. Examples

Run from `/home/sage/tii-claasp/scripts` inside the container (or prefix each line with
`docker exec -w /home/sage/tii-claasp/scripts <container>`):

```bash
# one round count
sage -python differential_search.py            --rounds 1 --backend sat --time-limit 600
sage -python linear_search.py                  --rounds 1 --backend sat --time-limit 600
sage -python zero_correlation_search.py        --rounds 1 --backend sat --first 0 --last 0 --time-limit 600
sage -python impossible_differential_search.py --rounds 2 --method mitm --backend sat --time-limit 600

# rounds 1 to 6, up to 130 minutes per round
sage -python differential_search_loop.py --rounds 1-6 --backend sat --threads 16 --time-per-round 7800

# long run in the background from the host; the log appears in scripts/ on the host too
docker exec -d -w /home/sage/tii-claasp/scripts <container> \
    sh -c 'sage -python linear_search_loop.py --rounds 1-6 --time-per-round 7800 > linear.log 2>&1'
```

## 3. Options

| option | scripts | meaning |
|---|---|---|
| `--rounds` | all | one-round scripts: one number; loop scripts: `3`, a range `1-6` or a list `1,3,5` |
| `--time-limit S` | one-round scripts | stop the search after S seconds |
| `--time-per-round S` | loop scripts | each round gets S seconds; a round that runs out is reported as STOPPED and the next round starts |
| `--backend` | all | `sat` (default), `cp`, `milp` or `smt`; see the table below |
| `--threads N` | all | solver threads; default 16 for differential, linear and impossible differential `mitm`, 1 for zero correlation and impossible differential `pairwise` |
| `--save DIR` | differential, linear | also write the full CLAASP solution to `DIR/round-<r>.json` |
| `--first`, `--last` | zero correlation, impossible differential `pairwise` | range of input bits to sweep (0 to 799) |
| `--method` | impossible differential | `mitm` (default; meet-in-the-middle model on the invertible permutation) or `pairwise` |
| `--middle-round` | impossible differential `mitm` | round where the forward and backward propagations meet; default `max(1, rounds // 2)` |

`sage -python <script> --help` lists the options; the docstring at the top of each file explains its
search in more detail.

## 4. Backends and solvers

| `--backend` | differential, linear | zero correlation | impossible differential `mitm` | impossible differential `pairwise` |
|---|---|---|---|---|
| `sat` | ParKissat (`-c=<threads>`) | Kissat | ParKissat | Kissat |
| `cp` | MiniZinc + OR-Tools CP-SAT | MiniZinc + OR-Tools CP-SAT | MiniZinc + OR-Tools CP-SAT | MiniZinc + OR-Tools CP-SAT |
| `milp` | SCIP | SCIP | SCIP | SCIP |
| `smt` | Z3 | Z3 | not available | Z3 |

To see which solvers a container has:

```bash
for b in parkissat kissat minizinc scip z3; do command -v $b || echo "$b: missing"; done
minizinc --solvers | grep -i cp-sat
```

An image built from an older `docker/Dockerfile` may not contain `scip`; `--backend milp` then fails.

## 5. Output and exit codes

Each round prints a one-line summary and a machine-readable line `RESULT {...}` (JSON). Loop scripts end
with an `overview:` of all rounds. Zero-correlation and impossible-differential `pairwise` sweeps print
each pair as soon as it is found and a `progress:` line on stderr every minute.

| exit code | one-round scripts | loop scripts |
|---|---|---|
| 0 | search finished | all rounds reported |
| 124 | stopped by the time limit, `timeout` or Ctrl-C | stopped by `timeout` or Ctrl-C |
| 1 | error (the message is in the summary) | |

## 6. Things to know

- **Sweeps are long.** A zero-correlation or `pairwise` impossible-differential sweep checks
  800 × 800 = 640,000 bit pairs. Use `--first`/`--last` to run a small range, or to split the sweep across
  several processes.
- **UNSAT in a trail search is a failure, not a bound.** Every nonzero input difference or mask has some
  trail, so an UNSATISFIABLE answer from a differential or linear search means the backend or encoding
  failed; the scripts say so in the summary.
- **Linear weights.** CLAASP reports w = -log2|c|. The Keccak team's correlation weight is
  -log2(c²) = 2w; `linear_search.py` prints both.
- **Stopping.** When a search is stopped, the scripts also kill the solver processes they started
  (through `/proc`, so this works on Linux, including inside the container).
- **ParKissat retries.** Multi-threaded ParKissat sometimes crashes or garbles its output on very quick
  instances; the scripts retry such a run up to 3 times (backend `sat` with ParKissat only) and record
  each retry in the summary.
