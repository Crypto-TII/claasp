"""Guard against obsolete generic Cipher identifiers in Python code.

CLAASP v5 uses Primitive for the generic graph abstraction. Documentation,
comments and string literals may freely use cryptographic terminology,
including the word cipher. Only executable Python identifiers are checked;
real taxonomy names and the published name CipherFour remain valid.

This module is dependency-free (standard library only) so it can run in the
fast unit-test job without pulling in any optional tooling. It is exercised by
``tests/unit/repository/test_terminology_guard.py`` and may also be run directly:

.. code-block:: console

   python tools/terminology_guard.py
"""

from __future__ import annotations

import io
import re
import sys
import tokenize
from dataclasses import dataclass
from pathlib import Path

NEXT_ROOT = Path(__file__).resolve().parents[1]

#: Source directories relative to the repository root.
DEFAULT_SCAN_ROOTS = ("src/claasp",)

#: Only Python files contain executable identifiers.
SCANNED_SUFFIXES = (".py",)

#: Directory name fragments never scanned (build artifacts, caches).
SKIPPED_DIR_PARTS = ("__pycache__", "_build", ".egg-info")

#: Valid taxonomy identifiers and the published teaching-primitive name.
ALLOWED_PHRASES = (
    "CipherFour",
    "block_ciphers",
    "block_cipher",
    "tweakable_block_ciphers",
    "tweakable_block_cipher",
    "ciphertext",
    "stream_cipher",
)
_ALLOWED_PATTERN = re.compile(
    "|".join(re.escape(phrase) for phrase in sorted(ALLOWED_PHRASES, key=len, reverse=True)),
    re.IGNORECASE,
)
_CIPHER_PATTERN = re.compile("ciphers?", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class Violation:
    """One source line containing an obsolete generic Cipher identifier."""

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
    """Return obsolete identifiers, ignoring prose, comments and strings.

    Python tokenization also covers imports, attributes, parameters and class
    names without mistaking docstrings or historical path citations for code.
    Each offending source line is reported once.
    """

    violations: list[Violation] = []
    for path in _iter_scanned_files(roots):
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        offending_lines = set()
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.NAME and _CIPHER_PATTERN.search(
                _mask_allowed_phrases(token.string)
            ):
                offending_lines.add(token.start[0])
        for line_number in sorted(offending_lines):
            violations.append(Violation(path, line_number, lines[line_number - 1]))
    return violations


def main() -> int:
    violations = find_violations()
    if not violations:
        print("terminology guard: no obsolete Cipher identifiers found")
        return 0
    print("terminology guard: obsolete Cipher identifiers found:", file=sys.stderr)
    for violation in violations:
        print(f"  {violation}", file=sys.stderr)
    print(
        "\nUse Primitive/primitive for generic Python API identifiers. "
        "The word cipher is allowed in documentation, comments and strings.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
