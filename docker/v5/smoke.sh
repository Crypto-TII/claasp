#!/bin/sh
set -eu

test "$(python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')" = "3.12"
test "$(dpkg --print-architecture)" = "${TARGETARCH:-$(dpkg --print-architecture)}"
python -m pip --version | grep 'pip 24.0' >/dev/null
python -m pip check >/dev/null

for executable in \
    cadical cbc cc cddexec_gmp cryptominisat5 dieharder espresso fzn-choco.sh glpsol glucose glucose-syrup gurobi_cl highs kissat mathsat minisat minizinc msolve niststs parkissat pdflatex scip Singular soplex yices-sat yices-smt2 z3
do
    command -v "$executable" >/dev/null
done

cryptominisat5 --version | grep 'CryptoMiniSat version 5.11.15' >/dev/null
gurobi_cl --version | grep 'Gurobi Optimizer version 13.0.2' >/dev/null
mathsat -version | grep 'MathSAT5 version 5.6.20' >/dev/null
minizinc --solvers | grep -i chuffed >/dev/null
minizinc --solvers | grep -i choco >/dev/null
python -c 'import gurobipy, matplotlib, mpmath, mypy, numpy, pandas, pytest, sklearn, sphinx'

ruff --version | grep '0.16.8' >/dev/null
python -m mypy --version | grep '2.3.1' >/dev/null
python -m pytest --version | grep '9.1.1' >/dev/null
sphinx-build --version | grep '9.0.4' >/dev/null
