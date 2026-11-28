#!/usr/bin/env bash
# Install a compatible Gecode executable and MiniZinc library on Linux.
# Run as root in the CLAASP image (or with sudo). Existing working installs
# are preserved. Requires curl, make, a C++ compiler and MPFR/GMP headers.
set -euo pipefail

smoke_test() {
    printf '%s\n' 'include "globals.mzn"; array[1..3] of int: values=[1,3,7]; var 1..3: i; var 0.0..1.0: p; constraint p=int2float(values[i])/7.0; solve satisfy;' \
        | minizinc --solver gecode --time-limit 5000 --input-from-stdin >/dev/null 2>&1
}

if smoke_test; then
    exit 0
fi
if [[ $(id -u) != 0 ]]; then
    echo 'Run this installer as root (or with sudo).' >&2
    exit 1
fi

gecode_prefix=/opt/gecode-6.3.0
if [[ ! -x "$gecode_prefix/bin/fzn-gecode" ]]; then
    gecode_build_dir=$(mktemp -d)
    trap 'rm -rf "$gecode_build_dir"' EXIT
    curl -fsSL --retry 3 \
        https://github.com/Gecode/gecode/archive/refs/tags/release-6.3.0.tar.gz \
        -o "$gecode_build_dir/gecode.tar.gz"
    echo "3edd6b13a6b9543614f7377c53a71c565ff315898d4788b651d01285bf91100a  $gecode_build_dir/gecode.tar.gz" | sha256sum -c -
    tar -xzf "$gecode_build_dir/gecode.tar.gz" -C "$gecode_build_dir"
    (
        cd "$gecode_build_dir/gecode-release-6.3.0"
        ./configure --prefix="$gecode_prefix" --disable-gist --disable-qt \
            --disable-examples --disable-doc-dot --disable-doc-search
        make -j"${GECODE_BUILD_JOBS:-4}"
        make install
    )
fi

printf '%s\n' "$gecode_prefix/lib" > /etc/ld.so.conf.d/claasp-gecode-6.3.0.conf
ldconfig

minizinc_stdlib_dir=$(minizinc --config-dirs | python3 -c 'import json,sys; print(json.load(sys.stdin)["mznStdlibDir"])')
mkdir -p "$minizinc_stdlib_dir/solvers"
cat > "$minizinc_stdlib_dir/solvers/gecode.msc" <<EOF
{
  "id": "org.gecode.gecode",
  "name": "Gecode",
  "description": "Gecode FlatZinc executable",
  "version": "6.3.0",
  "mznlib": "$gecode_prefix/share/minizinc/gecode",
  "executable": "$gecode_prefix/bin/fzn-gecode",
  "tags": ["cp", "int", "float", "set", "restart"],
  "stdFlags": ["-a", "-f", "-n", "-p", "-r", "-s", "-t"],
  "supportsMzn": false,
  "supportsFzn": true,
  "needsSolns2Out": true,
  "needsMznExecutable": false,
  "needsStdlibDir": false,
  "isGUIApplication": false
}
EOF
smoke_test
