"""Generate the lazy public primitive export map from the machine inventory."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).parents[2]
INVENTORY = ROOT / "next/migration/legacy_inventory.json"
SINGLE_COMPONENT_CATALOGUE = ROOT / "next/migration/single_component_catalogue.json"
DESTINATION = ROOT / "next/src/claasp_next/primitives/_catalogue_exports.py"


def render_exports() -> tuple[str, int]:
    """Return the deterministic generated module and exported-class count."""

    payload = json.loads(INVENTORY.read_text(encoding="utf-8"))
    rows = sorted(
        (
            item["primitive"]["primitive_category"],
            item["primitive"]["proposed_class"],
            item["primitive"]["proposed_module"],
        )
        for item in payload["records"]
        if "primitive" in item and item["primitive"]["primitive_category"] != "outside_scope"
    )
    rows = [row for row in rows if row[0] != "single_component_primitives"]
    component_catalogue = json.loads(SINGLE_COMPONENT_CATALOGUE.read_text(encoding="utf-8"))
    rows.extend(
        ("single_component_primitives", name, module)
        for name, module in component_catalogue.items()
    )
    rows.sort()
    categories = sorted({category for category, _, _ in rows})
    lines = [
        '"""Generated public primitive catalogue exports.',
        "",
        "Regenerate with ``tools/generate_primitive_exports.py``.",
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
