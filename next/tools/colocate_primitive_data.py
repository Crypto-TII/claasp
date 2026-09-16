"""Colocate frozen catalogue specifications with their owning primitives.

This is a deterministic migration helper.  It replaces each generated
``<primitive>.py`` wrapper with a same-import-path package containing
``primitive.py`` and ``data/`` while preserving the public import path.
"""

from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).parents[1] / "src/claasp_next/primitives"
CATEGORIES = (
    "block_ciphers", "tweakable_block_ciphers", "permutations",
    "block_functions", "functions",
)


def _exports(source: str) -> tuple[str, ...]:
    tree = ast.parse(source)
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "__all__"):
            value = ast.literal_eval(node.value)
            return tuple(value)
    raise ValueError("generated primitive wrapper has no literal __all__")


def colocate() -> int:
    moved = 0
    for category in CATEGORIES:
        category_root = ROOT / category
        shared_data = category_root / "data"
        if not shared_data.exists():
            continue
        for index_path in sorted(shared_data.glob("*.index.json")):
            stem = index_path.name.removesuffix(".index.json")
            module_path = category_root / f"{stem}.py"
            if not module_path.exists():
                raise FileNotFoundError(f"missing owner module for {index_path}")
            source = module_path.read_text(encoding="utf-8")
            exports = _exports(source)
            owner = category_root / stem
            data = owner / "data"
            data.mkdir(parents=True, exist_ok=False)
            module_path.replace(owner / "primitive.py")
            (owner / "__init__.py").write_text(
                "\n".join(
                    [f'"""Public {stem} primitive package."""', ""]
                    + [f"from .primitive import {name}" for name in exports]
                    + ["", f"__all__ = {list(exports)!r}", ""]
                ),
                encoding="utf-8",
            )
            (data / "__init__.py").write_text(
                f'"""Primitive-owned frozen graph data for {stem}."""\n',
                encoding="utf-8",
            )
            index_path.replace(data / "index.json")
            for artifact in sorted(shared_data.glob(f"{stem}.*.json.gz")):
                artifact.replace(data / artifact.name.removeprefix(f"{stem}."))
            moved += 1
        marker = shared_data / "__init__.py"
        if marker.exists():
            marker.unlink()
        shared_data.rmdir()
    return moved


if __name__ == "__main__":
    print(f"colocated {colocate()} primitive data packages")
