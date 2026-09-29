"""Enforce M10.9a: no generic 'cipher'/'ciphers' vocabulary in public v5 code.

CLAASP v5 renamed the generic graph abstraction ``Cipher`` to ``Primitive``
and the public catalogue package ``ciphers`` to ``primitives`` (see the
"Primitive terminology and catalogue taxonomy" section of
``docs/architecture/v5-plan.md``). This test wires
:mod:`tools.terminology_guard` into the routine fast unit-test run so a
regression to the transitional vocabulary fails CI immediately, without a
separate job.
"""

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


def test_source_and_docs_contain_no_generic_cipher_vocabulary():
    module = _module()
    violations = module.find_violations()
    assert not violations, "generic 'cipher' vocabulary reintroduced:\n" + "\n".join(
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

    assert len(violations) == 2


def test_guard_allows_the_real_block_cipher_taxonomy_and_ciphertext(tmp_path):
    module = _module()
    scan_root = tmp_path / "src" / "claasp"
    scan_root.mkdir(parents=True)
    (scan_root / "fine.py").write_text(
        '"""Keyed block-cipher graphs, e.g. block_ciphers and tweakable_block_ciphers.\n'
        "Evaluation returns plaintext/ciphertext pairs; ChaCha was a stream cipher mode.\n"
        '"""\n'
    )

    original_root = module.NEXT_ROOT
    try:
        module.NEXT_ROOT = tmp_path
        violations = module.find_violations(("src/claasp",))
    finally:
        module.NEXT_ROOT = original_root

    assert violations == []
