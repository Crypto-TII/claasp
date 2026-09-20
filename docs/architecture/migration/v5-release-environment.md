# CLAASP 5 canonical release environment

The canonical validation image is defined by `docker/v5/Dockerfile`. It is a
Sage-free Ubuntu 24.04 image for `linux/amd64` and `linux/arm64`, with Python
3.12.3 and a complete exact Python dependency lock. The Ubuntu image digest,
system packages, source releases, and source archive checksums are pinned.

The image contains MiniZinc/Chuffed, GLPK, Z3, MiniSat, Singular, msolve,
Dieharder, the project's patched non-interactive NIST STS build, a C compiler,
and LaTeX/TikZ. msolve 0.10.1 is built from its checked source release because
the Ubuntu 24.04 arm64 package (0.6.5) segfaulted on the project's existing
exporter acceptance fixture. The source build runs msolve's own 64-test suite
before installation. A transparent `minizinc` wrapper passes `--no-optimize`
to Ubuntu's MiniZinc 2.8.2 on both architectures: its default single-pass
optimizer asserts on fixed Boolean constraints under ARM64, while the
unoptimized FlatZinc path passes the same 26 MiniZinc acceptance tests on both
architectures. This workaround is version-bound and must be reviewed when
MiniZinc is upgraded.

`docker/v5/smoke.sh` verifies architecture, Python, installed executables,
Chuffed registration, optional Python imports, and exact quality-tool
versions. `docker/v5/check.sh` runs dependency-free and external tests,
Python and guide doctests, warning-free HTML, formatting, linting, the audited
typing baseline, every migration/catalogue closure gate, and wheel audit.
CI builds both architectures without publishing them and executes this matrix
under both architectures. Every third-party workflow action is pinned to a
full commit identity, while an adjacent major-version comment keeps update
reviews legible.

The image is not public and the workflow has no registry login or push step.
Once the private destination organization and registry exist, an immutable
digest may be pushed there; public publication remains part of the controlled
M11 launch.
