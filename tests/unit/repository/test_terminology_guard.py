"""Keep obsolete generic Cipher identifiers out of executable v5 source."""

import importlib.util
import sys
from pathlib import Path

ROOT = next(
    parent for parent in Path(__file__).resolve().parents if (parent / "pyproject.toml").is_file()
)
SCRIPT = ROOT / "tools" / "terminology_guard.py"


def _module():
    spec = importlib.util.spec_from_file_location("terminology_guard", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # Dataclasses resolve their annotations through ``sys.modules``, so the
    # module must be registered before ``exec_module`` runs its class bodies.
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules[spec.name]
    return module


def test_source_contains_no_obsolete_cipher_identifiers():
    module = _module()
    violations = module.find_violations()
    assert not violations, "obsolete Cipher identifiers reintroduced:\n" + "\n".join(
        str(violation) for violation in violations
    )


def test_guard_still_detects_a_reintroduced_generic_cipher_reference(tmp_path):
    module = _module()
    scan_root = tmp_path / "src" / "claasp"
    scan_root.mkdir(parents=True)
    (scan_root / "regressed.py").write_text(
        'class CipherFoo:\n    """A cipher graph description."""\n'
    )

    original_root = module.NEXT_ROOT
    try:
        module.NEXT_ROOT = tmp_path
        violations = module.find_violations(("src/claasp",))
    finally:
        module.NEXT_ROOT = original_root

    assert len(violations) == 1


def test_guard_allows_the_real_block_cipher_taxonomy_and_ciphertext(tmp_path):
    module = _module()
    scan_root = tmp_path / "src" / "claasp"
    scan_root.mkdir(parents=True)
    (scan_root / "fine.py").write_text(
        '"""Keyed block-cipher graphs, e.g. block_ciphers and tweakable_block_ciphers.\n'
        "Evaluation returns plaintext/ciphertext pairs; ChaCha was a stream cipher mode.\n"
        "Exact paper titles may name ARX ciphers or SPN ciphers.\n"
        '"""\n'
    )

    original_root = module.NEXT_ROOT
    try:
        module.NEXT_ROOT = tmp_path
        violations = module.find_violations(("src/claasp",))
    finally:
        module.NEXT_ROOT = original_root

    assert violations == []


def test_guard_allows_cipher_in_documentation_comments_and_strings(tmp_path):
    module = _module()
    source = tmp_path / "src" / "claasp"
    source.mkdir(parents=True)
    (source / "fine.py").write_text(
        '"""The cipher propagates differences. Legacy Cipher API."""\n'
        "# Split the cipher at an internal boundary.\n"
        'description = "claasp.ciphers and Cipher are historical names"\n'
        "class CipherFour: pass\n"
        "block_cipher = ciphertext = stream_cipher = None\n"
    )
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "example.rst").write_text(
        "Given a block cipher, split the cipher at each internal boundary.\n"
        "Historical example: class CipherFoo.\n"
    )
    module.NEXT_ROOT = tmp_path
    assert module.find_violations(("src/claasp", "docs")) == []


def test_guard_detects_obsolete_imports_attributes_and_parameters(tmp_path):
    module = _module()
    source = tmp_path / "src" / "claasp"
    source.mkdir(parents=True)
    (source / "regressed.py").write_text(
        "from claasp.ciphers import Cipher\ndef analyze(cipher):\n    return cipher.CipherDiagram\n"
    )
    module.NEXT_ROOT = tmp_path
    assert [item.line_number for item in module.find_violations()] == [1, 2, 3]
