#!/bin/sh
set -eu

# MiniZinc 2.8.2's single-pass optimizer can assert while simplifying fixed
# Boolean constraints on ARM64.  Disabling that optimization preserves the
# FlatZinc model and gives both release architectures the same reliable path.
exec /usr/bin/minizinc --no-optimize "$@"
