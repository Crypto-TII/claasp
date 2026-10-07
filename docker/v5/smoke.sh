#!/bin/sh
set -eu

test "$(python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')" = "3.12"
test "$(dpkg --print-architecture)" = "${TARGETARCH:-$(dpkg --print-architecture)}"
python -m pip --version | grep 'pip 24.0' >/dev/null
python -m pip check >/dev/null

for executable in \
    cc cddexec_gmp cryptominisat5 dieharder glpsol kissat minisat minizinc msolve niststs pdflatex Singular z3
do
    command -v "$executable" >/dev/null
done

cryptominisat5 --version | grep 'CryptoMiniSat version 5.11.15' >/dev/null
minizinc --solvers | grep -i chuffed >/dev/null
python -c 'import matplotlib, mypy, numpy, pandas, pytest, sklearn, sphinx'

ruff --version | grep '0.16.8' >/dev/null
python -m mypy --version | grep '2.3.1' >/dev/null
python -m pytest --version | grep '9.1.1' >/dev/null
sphinx-build --version | grep '9.0.4' >/dev/null
