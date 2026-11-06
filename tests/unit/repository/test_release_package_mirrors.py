"""Snapshot resolution and package hashes survive a download-server outage."""

import hashlib
import os
import subprocess
from pathlib import Path

import pytest


@pytest.mark.parametrize("mirror_ok", [True, False])
def test_snapshot_fallback_checks_the_resolved_hash_and_keeps_install_arguments(
    tmp_path, mirror_ok
):
    root = Path(__file__).resolve().parents[3]
    digest = hashlib.sha256(b"snapshot package").hexdigest()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    archives = tmp_path / "archives"
    archives.mkdir()
    log = tmp_path / "commands"
    state = tmp_path / "state"
    apt = bindir / "apt-get"
    apt.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$*" >> "$COMMAND_LOG"\n'
        'case "$*" in\n'
        '  *--print-uris*) printf "\\047https://snapshot.ubuntu.com/ubuntu/20261027T000000Z/pool/main/p/pkg/pkg_1_arm64.deb\\047 pkg_1_arm64.deb 16 SHA256:%s\\n" "$EXPECTED_DIGEST"; exit 0 ;;\n'
        "esac\n"
        'if [ ! -f "$STATE" ]; then touch "$STATE"; exit 100; fi\n'
        'test -f "$CLAASP_APT_ARCHIVES/pkg_1_arm64.deb"\n'
    )
    helper = bindir / "apt-helper"
    helper.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$*" >> "$COMMAND_LOG"\n'
        # Arguments: two -o settings, download-file, URI, destination, SHA256.
        'test "$8" = "SHA256:$EXPECTED_DIGEST" || exit 9\n'
        'test "$MIRROR_OK" = yes || exit 1\n'
        'printf "snapshot package" > "$7"\n'
    )
    apt.chmod(0o755)
    helper.chmod(0o755)
    result = subprocess.run(
        ["sh", str(root / "docker/v5/install-packages.sh"), "pkg=1"],
        env={
            **os.environ,
            "PATH": f"{bindir}:{os.environ['PATH']}",
            "CLAASP_APT_HELPER": str(helper),
            "CLAASP_APT_ARCHIVES": str(archives),
            "COMMAND_LOG": str(log),
            "STATE": str(state),
            "EXPECTED_DIGEST": digest,
            "MIRROR_OK": "yes" if mirror_ok else "no",
        },
        capture_output=True,
        text=True,
    )
    commands = log.read_text().splitlines()
    assert all("pkg=1" in line for line in commands if "install" in line)
    assert "Acquire::ForceHash=SHA256" in commands[1]
    assert any("http://archive.ubuntu.com/ubuntu/pool/" in line for line in commands)
    if mirror_ok:
        assert result.returncode == 0, result.stderr
        assert hashlib.sha256((archives / "pkg_1_arm64.deb").read_bytes()).hexdigest() == digest
        assert len([line for line in commands if "install" in line]) == 3
    else:
        assert result.returncode != 0
        assert "No mirror supplied the snapshot-verified package" in result.stderr
        assert len([line for line in commands if "install" in line]) == 2


@pytest.mark.skipif(not Path("/usr/lib/apt/apt-helper").exists(), reason="requires Ubuntu apt")
@pytest.mark.parametrize("valid_hash", [True, False])
def test_real_apt_downloader_verifies_snapshot_hashes(tmp_path, valid_hash):
    source = tmp_path / "source.deb"
    source.write_bytes(b"pinned package bytes")
    digest = hashlib.sha256(source.read_bytes() if valid_hash else b"different bytes").hexdigest()
    result = subprocess.run(
        [
            "/usr/lib/apt/apt-helper",
            "download-file",
            source.as_uri(),
            str(tmp_path / "downloaded.deb"),
            f"SHA256:{digest}",
        ],
        capture_output=True,
        text=True,
    )
    assert (result.returncode == 0) is valid_hash, result.stderr
