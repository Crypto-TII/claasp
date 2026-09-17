#!/usr/bin/env python3
"""Remove intermediate graph artifacts and normalize native source layout."""

from __future__ import annotations

import json
from pathlib import Path
import shutil


ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = ROOT / "next" / "src" / "claasp_next" / "primitives"


def main() -> None:
    converted_modules: dict[str, str] = {}
    indexes = sorted(SOURCE_ROOT.glob("**/data/index.json"))
    for index in indexes:
        package = index.parent.parent
        module = ".".join(package.relative_to(ROOT / "next" / "src").parts)
        if package.name == "lowmc":
            for artifact in index.parent.iterdir():
                if artifact.name == "__pycache__":
                    shutil.rmtree(artifact)
                elif artifact.suffix == ".gz" or artifact.name in {"index.json", "__init__.py"}:
                    artifact.unlink()
            continue
        target = package.with_suffix(".py")
        if target.exists():
            raise FileExistsError(target)
        shutil.move(package / "primitive.py", target)
        shutil.rmtree(package)
        converted_modules[module] = str(target.relative_to(ROOT / "next" / "src"))

    aes_module = SOURCE_ROOT / "block_ciphers" / "aes.py"
    aes_package = SOURCE_ROOT / "block_ciphers" / "aes"
    if aes_module.exists():
        aes_package.mkdir()
        shutil.move(aes_module, aes_package / "primitive.py")
        (aes_package / "__init__.py").write_text(
            '"""AES primitive, realizations, and research variants."""\n\n'
            'from .primitive import (AES, AES128, AESVariant, AES_AFFINE_MATRIX, AES_SBOX, '
            'PARAMETERS_CONFIGURATION_LIST)\n\n'
            '__all__ = ["AES", "AES128", "AESVariant", "AES_AFFINE_MATRIX", "AES_SBOX", '
            '"PARAMETERS_CONFIGURATION_LIST"]\n',
            encoding="utf-8",
        )

    inventory_path = ROOT / "next" / "migration" / "legacy_inventory.json"
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    for record in inventory["records"]:
        module = record.get("primitive", {}).get("proposed_module")
        if module in converted_modules:
            record["v5_destination"] = converted_modules[module]
        elif module == "claasp_next.primitives.block_ciphers.aes":
            record["v5_destination"] = "claasp_next/primitives/block_ciphers/aes/__init__.py"
    inventory_path.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"converted {len(converted_modules)} simple primitive packages to modules")


if __name__ == "__main__":
    main()
