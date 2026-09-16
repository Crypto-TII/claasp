"""Generate the lazy public primitive export map from the machine inventory."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).parents[2]
INVENTORY = ROOT / "next/migration/legacy_inventory.json"
DESTINATION = ROOT / "next/src/claasp_next/primitives/_catalogue_exports.py"


def main() -> None:
    payload = json.loads(INVENTORY.read_text(encoding="utf-8"))
    rows = sorted(
        (
            item["primitive"]["primitive_category"],
            item["primitive"]["proposed_class"],
            item["primitive"]["proposed_module"],
        )
        for item in payload["records"]
        if "primitive" in item
        and item["primitive"]["primitive_category"] != "outside_scope"
    )
    categories = sorted({category for category, _, _ in rows})
    lines = [
        '"""Generated public primitive catalogue exports.',
        "",
        "Regenerate with ``tools/generate_primitive_exports.py``.",
        '"""',
        "",
        "from importlib import import_module",
        "",
        "",
        "CATEGORY_EXPORTS = {",
    ]
    for category in categories:
        lines.append(f"    {category!r}: {{")
        for _, name, module in (row for row in rows if row[0] == category):
            lines.append(f"        {name!r}: {module!r},")
        lines.append("    },")
    lines.extend([
        "}",
        "",
        "ALL_EXPORTS = {",
        "    name: module",
        "    for exports in CATEGORY_EXPORTS.values()",
        "    for name, module in exports.items()",
        "}",
        "",
        "",
        "def load_export(name: str, exports=ALL_EXPORTS):",
        '    """Load one public primitive class without eagerly importing the catalogue."""',
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
    ])
    DESTINATION.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {DESTINATION.relative_to(ROOT)} with {len(rows)} exports")


if __name__ == "__main__":
    main()
