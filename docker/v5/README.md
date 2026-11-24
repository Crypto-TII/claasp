# Solver executables in the release image

The v5 release image installs external solver executables used by CLAASP.
Versions and source checksums are pinned in `Dockerfile`. `smoke.sh` checks
their availability on AMD64 and ARM64, and GitHub Actions runs the supported
v5 driver tests.

Gurobi is installed with its Python package, but solving requires a valid
license supplied at runtime. The image contains no license credentials.
MathSAT's bundled license permits research and evaluation use; check its
terms before using the image for other purposes. The vendor license texts
are installed in `/usr/local/share/licenses`.

Use `Catalogue().solvers(view="both")` to inspect supported solver drivers
and their local availability. The executables can also be invoked directly
from the shell.
