#!/usr/bin/env python3
"""Compile readable v4 primitive builders into dependency-free v5 source.

This is a development migration tool.  Its output contains the algorithmic
round/key-schedule source; it never serializes an instantiated graph.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
import re
import shutil


ROOT = Path(__file__).resolve().parents[2]
V5_ROOT = ROOT / "next" / "src"
INVENTORY = ROOT / "next" / "migration" / "legacy_inventory.json"


def _replacement(node: ast.ImportFrom) -> str | None:
    names = ", ".join(
        name.name if name.asname is None else f"{name.name} as {name.asname}"
        for name in node.names
    )
    if node.module == "claasp.cipher":
        return "from claasp_next.graph.bit_builder import BitGraphPrimitive"
    if node.module == "claasp.DTOs.component_state":
        return "from claasp_next.graph.bit_builder import BitState"
    if node.module == "claasp.name_mappings":
        return f"from claasp_next.primitive_inputs import {names}"
    if node.module in {"claasp.utils.utils", "claasp.utils.integer_functions"}:
        return f"from claasp_next.graph.bit_builder import {names}"
    if node.module == "claasp.component":
        return f"from claasp_next.graph.bit_builder import {names}"
    if node.module == "claasp.ciphers.block_ciphers.katan_block_cipher":
        return f"from claasp_next.primitives.block_ciphers.katan import {names}"
    if node.module == "claasp.ciphers.permutations.util":
        return f"from claasp_next.graph.bit_builder import {names}"
    if node.module == "claasp.ciphers.block_ciphers" and any(
        name.name == "lowmc_generate_matrices" for name in node.names
    ):
        return "# LowMC uses only vetted primitive-owned constant data"
    if node.module and node.module.startswith("sage."):
        return "# Sage construction replaced by dependency-free v5 constants"
    return None


def compile_source(source: Path, destination: Path, old_class: str, new_class: str) -> None:
    text = source.read_text(encoding="utf-8")
    tree = ast.parse(text)
    lines = text.splitlines()
    edits: list[tuple[int, int, list[str]]] = []
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            replacement = _replacement(node)
            if replacement is not None:
                edits.append((node.lineno - 1, node.end_lineno, [replacement]))
    for start, end, replacement in reversed(edits):
        lines[start:end] = replacement
    text = "\n".join(lines) + "\n"
    text = re.sub(rf"\b{re.escape(old_class)}\b", new_class, text)
    text = re.sub(rf"\bclass {re.escape(new_class)}\(Cipher\):", f"class {new_class}(BitGraphPrimitive):", text)
    text = re.sub(r"\bComponentState\b", "BitState", text)
    if source.name == "lowmc_block_cipher.py":
        text = text.replace('+ "/" + self.constants', '+ "/data/" + self.constants')
        text = re.sub(
            r'\n\s*# Only generate constant data if needed\n\s*if not exists\(.*?\):\n\s*lowmc_generate_matrices\.main\(.*?\)\n',
            '\n        if not exists(dirname(realpath(__file__)) + "/data/" + self.constants):\n'
            '            raise ValueError("unsupported LowMC parameter set: no vetted constant data is packaged")\n',
            text,
        )
    if source.name in {"xoodoo_permutation.py", "xoodoo_sbox_permutation.py"}:
        text = re.sub(
            r'R = PolynomialRing\(GF\(2\), "t"\).*?\n\n\nclass',
            'QI = SI = t = None\n\n\nclass', text, flags=re.DOTALL,
        )
    text = text.replace("claasp.ciphers", "claasp.__LEGACY_CATALOGUE__")
    for old, new in (
        ("cipher_type", "primitive_type"),
        ("cipher_inputs_bit_size", "primitive_inputs_bit_size"),
        ("cipher_inputs", "primitive_inputs"),
        ("cipher_output_bit_size", "primitive_output_bit_size"),
        ("cipher_reference_code", "primitive_reference_code"),
        ("add_cipher_output_component", "add_primitive_output_component"),
        ("cipher_output", "primitive_output"),
        ("cipher_state", "primitive_state"),
        ("cipher_block_size", "primitive_block_size"),
        ("get_cipher", "get_primitive"),
        ("build_cipher", "build_primitive"),
        ("print_cipher", "print_primitive"),
        ("des_cipher", "des_primitive"),
        ("CIPHER_BLOCK_SIZE", "PRIMITIVE_BLOCK_SIZE"),
    ):
        text = text.replace(old, new)
    text = re.sub(r"\bciphers\b", "primitives", text)
    text = re.sub(r"\bcipher\b", "primitive", text)
    text = text.replace("Cipher", "Primitive")
    text = text.replace("claasp.__LEGACY_CATALOGUE__", "claasp.ciphers")
    destination.write_text(text, encoding="utf-8")


def main() -> None:
    payload = json.loads(INVENTORY.read_text(encoding="utf-8"))
    by_module = {
        record.get("primitive", {}).get("proposed_module"): record
        for record in payload["records"]
        if record.get("primitive", {}).get("proposed_module")
    }
    compiled = 0
    for module, record in sorted(by_module.items()):
        module_path = V5_ROOT.joinpath(*module.split("."))
        destination = module_path.with_suffix(".py")
        if not destination.exists():
            destination = module_path / "primitive.py"
        if not destination.exists() or "BitGraphPrimitive" not in destination.read_text(encoding="utf-8"):
            continue
        source = ROOT / record["path"]
        if source.name == "chacha_stream_cipher.py":
            continue
        tree = ast.parse(source.read_text(encoding="utf-8"))
        source_classes = [
            node.name for node in tree.body
            if isinstance(node, ast.ClassDef)
            and any(isinstance(base, ast.Name) and base.id == "Cipher" for base in node.bases)
        ]
        if not source_classes:
            continue
        old_class = source_classes[0]
        compile_source(source, destination, old_class, record["primitive"]["proposed_class"])
        if source.name == "lowmc_block_cipher.py":
            data_directory = destination.parent / "data"
            for data_file in source.parent.glob("lowmc_constants_*.dat"):
                shutil.copy2(data_file, data_directory / data_file.name)
        compiled += 1
    print(f"compiled {compiled} readable primitive sources")


if __name__ == "__main__":
    main()
