"""Generate the lazy public primitive export map from implementation-owned declarations."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).parents[1]
DESTINATION = ROOT / "src/claasp/primitives/_catalogue_exports.py"


def render_exports(entries=None) -> tuple[str, int]:
    """Return deterministic exports discovered from implementation owners."""
    from catalogue_discovery import primitive_exports

    rows = list(primitive_exports(entries))
    rows.sort()
    categories = sorted({category for category, _, _ in rows})
    lines = [
        '"""Generated public primitive catalogue exports.',
        "",
        "Regenerate with ``tools/generate_catalogue_metadata.py``.",
        '"""',
        "",
        "from importlib import import_module",
        "",
        "CATEGORY_EXPORTS = {",
    ]
    for category in categories:
        lines.append(f"    {json.dumps(category)}: {{")
        for _, name, module in (row for row in rows if row[0] == category):
            lines.append(f"        {json.dumps(name)}: {json.dumps(module)},")
        lines.append("    },")
    lines.extend(
        [
            "}",
            "",
            "ALL_EXPORTS = {",
            "    name: module for exports in CATEGORY_EXPORTS.values() for name, module in exports.items()",
            "}",
            "",
            "",
            "def load_export(name: str, exports=ALL_EXPORTS):",
            '    """Load one public primitive class without eagerly importing the catalogue.',
            "",
            "    Unknown export names are reported as attributes because this loader backs",
            "    the package-level lazy attribute boundary.",
            "",
            "    EXAMPLES::",
            "",
            '        >>> load_export("AES").__name__',
            "        'AES'",
            "        >>> try:",
            '        ...     load_export("not-a-primitive")',
            "        ... except AttributeError as error:",
            "        ...     print(error)",
            "        not-a-primitive",
            '    """',
            "",
            "    try:",
            "        module_name = exports[name]",
            "    except KeyError as error:",
            "        raise AttributeError(name) from error",
            "    return getattr(import_module(module_name), name)",
            "",
            "",
            '__all__ = ["ALL_EXPORTS", "CATEGORY_EXPORTS", "load_export"]',
            "",
        ]
    )
    return "\n".join(lines), len(rows)


def main() -> None:
    source, count = render_exports()
    DESTINATION.write_text(source, encoding="utf-8")
    print(f"wrote {DESTINATION.relative_to(ROOT)} with {count} exports")


if __name__ == "__main__":
    main()
