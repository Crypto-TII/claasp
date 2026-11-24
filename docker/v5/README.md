# Solver executables in the release image

The v5 image includes the command-line solvers present in the legacy CLAASP
image: CaDiCaL, Choco, Chuffed, COIN-BC, CryptoMiniSat, GLPK, Glucose,
Glucose Syrup, Gurobi, HiGHS, Kissat, MathSAT, MiniSat, MiniZinc,
ParKissat, SCIP, SoPlex, Yices and Z3. Versions and source checksums are
pinned in `Dockerfile`. `smoke.sh` checks that every command is installed on
both AMD64 and ARM64, and GitHub Actions runs the available v5 driver tests.

Gurobi is installed with its Python package, but solving requires a valid
license supplied at runtime. The image contains no license credentials.
MathSAT's bundled license permits research and evaluation use; check its
terms before using the image for other purposes. The vendor license texts
are installed in `/usr/local/share/licenses`.

V5 currently provides direct solver drivers for CryptoMiniSat, GLPK,
Gurobi, HiGHS, Kissat, MiniSat, MiniZinc and Z3. The other executables are
available in the image for legacy command-line workflows.
