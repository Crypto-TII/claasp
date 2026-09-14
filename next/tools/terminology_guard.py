"""Guard against reintroducing generic ``cipher``/``ciphers`` vocabulary.

CLAASP v5 uses ``primitive`` as its generic public term (see the "Primitive
terminology and catalogue taxonomy" section of ``docs/architecture/v5-plan.md``
and milestone M10.9a). The word ``cipher`` remains correct only where it names
a real mathematical category (``block_cipher(s)``, ``tweakable_block_cipher(s)``,
and their prose equivalents such as "block cipher") or is part of an
established cryptographic term such as ``ciphertext`` or "stream cipher" used
descriptively (for example to name the legacy construction that a fixed-length
permutation was extracted from).

This module is dependency-free (standard library only) so it can run in the
fast unit-test job without pulling in any optional tooling. It is exercised by
``tests/unit/test_terminology_guard.py`` and may also be run directly:

.. code-block:: console

   python tools/terminology_guard.py
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

NEXT_ROOT = Path(__file__).resolve().parents[1]

#: Directories (relative to the ``next/`` root) scanned for banned vocabulary.
DEFAULT_SCAN_ROOTS = ("src/claasp_next", "docs")

#: File suffixes considered source/documentation text.
SCANNED_SUFFIXES = (".py", ".rst")

#: Directory name fragments never scanned (build artifacts, caches).
SKIPPED_DIR_PARTS = ("__pycache__", "_build", ".egg-info")

#: Phrases that legitimately retain the word "cipher" because they name a
#: real mathematical category (the v5 taxonomy's ``block_ciphers`` and
#: ``tweakable_block_ciphers`` families, in both their identifier and prose
#: spellings) or an established cryptographic term. Matching is
#: case-insensitive; each entry is masked out of the text before the
#: generic-vocabulary scan runs, so these exact phrases never trigger a
#: violation while any other appearance of "cipher"/"ciphers" does.
ALLOWED_PHRASES = (
    "block_ciphers",
    "block_cipher",
    "block ciphers",
    "block cipher",
    "block-ciphers",
    "block-cipher",
    "tweakable_block_ciphers",
    "tweakable_block_cipher",
    "tweakable block ciphers",
    "tweakable block cipher",
    "tweakable-block-ciphers",
    "tweakable-block-cipher",
    "ciphertext",
    "stream cipher",
    "stream-cipher",
    "stream_cipher",
)

_ALLOWED_PATTERN = re.compile(
    "|".join(re.escape(phrase) for phrase in sorted(ALLOWED_PHRASES, key=len, reverse=True)),
    re.IGNORECASE,
)
_CIPHER_PATTERN = re.compile("ciphers?", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class Violation:
    """One disallowed occurrence of generic ``cipher``/``ciphers`` vocabulary."""

    path: Path
    line_number: int
    line: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line_number}: {self.line.strip()}"


def _mask_allowed_phrases(text: str) -> str:
    """Replace every allowed phrase with same-length filler so it cannot match."""

    return _ALLOWED_PATTERN.sub(lambda match: "#" * len(match.group(0)), text)


def _iter_scanned_files(roots: tuple[str, ...]) -> list[Path]:
    files: list[Path] = []
    for root_name in roots:
        root = NEXT_ROOT / root_name
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if path.is_dir():
                continue
            if any(part in SKIPPED_DIR_PARTS or part.endswith(".egg-info") for part in path.parts):
                continue
            if path.suffix in SCANNED_SUFFIXES:
                files.append(path)
    return files


def find_violations(roots: tuple[str, ...] = DEFAULT_SCAN_ROOTS) -> list[Violation]:
    """Return every disallowed generic ``cipher``/``ciphers`` occurrence.

    A violation is any appearance of "cipher" or "ciphers" (in any casing,
    including inside identifiers such as ``CipherDiagram`` or
    ``AESBlockCipher``) that is not part of an :data:`ALLOWED_PHRASES` entry.
    """

    violations: list[Violation] = []
    for path in _iter_scanned_files(roots):
        text = path.read_text(encoding="utf-8")
        masked = _mask_allowed_phrases(text)
        if not _CIPHER_PATTERN.search(masked):
            continue
        for line_number, (original_line, masked_line) in enumerate(
            zip(text.splitlines(), masked.splitlines()), start=1
        ):
            if _CIPHER_PATTERN.search(masked_line):
                violations.append(Violation(path, line_number, original_line))
    return violations


def main() -> int:
    violations = find_violations()
    if not violations:
        print("terminology guard: no generic 'cipher'/'ciphers' vocabulary found")
        return 0
    print("terminology guard: disallowed generic 'cipher' vocabulary found:", file=sys.stderr)
    for violation in violations:
        print(f"  {violation}", file=sys.stderr)
    print(
        "\nUse 'primitive' for the generic graph abstraction and catalogue "
        "vocabulary; 'cipher' remains correct only for the real "
        "block_cipher(s)/tweakable_block_cipher(s) category, 'ciphertext', "
        "or a named legacy construction such as 'stream cipher'. See the "
        "'Primitive terminology and catalogue taxonomy' section of "
        "docs/architecture/v5-plan.md.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
