"""Guard the preserved native NIST numerical implementation and runtime resources."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "tools/data/legacy_native_nist_contract.json"


class _NumericalBody(ast.NodeTransformer):
    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        node.returns = None
        for argument in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
            argument.annotation = None
        for argument in (node.args.vararg, node.args.kwarg):
            if argument is not None:
                argument.annotation = None
        self._remove_docstring(node)
        return node

    def visit_ClassDef(self, node):
        self.generic_visit(node)
        self._remove_docstring(node)
        return node

    def visit_AnnAssign(self, node):
        if node.value is None:
            return None
        return ast.Assign(targets=[node.target], value=node.value)

    @staticmethod
    def _remove_docstring(node):
        if (
            node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        ):
            node.body.pop(0)


def _canonical(node):
    if isinstance(node, ast.AST):
        return {
            "kind": type(node).__name__,
            **{
                key: _canonical(value)
                for key, value in ast.iter_fields(node)
                if key != "type_params"
            },
        }
    if isinstance(node, list):
        return [_canonical(value) for value in node]
    return node


def numerical_definitions(path):
    tree = _NumericalBody().visit(ast.parse(path.read_text()))
    return {
        node.name: hashlib.sha256(
            json.dumps(_canonical(node), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.ClassDef))
    }


def validate(root=ROOT):
    contract = json.loads((root / CONTRACT.relative_to(ROOT)).read_text())
    source = root / contract["v5_module"]
    found = numerical_definitions(source)
    expected = {**contract["definitions"], **contract["additional_v5_definitions"]}
    if found != expected:
        changed = sorted(
            name for name in set(found) | set(expected) if found.get(name) != expected.get(name)
        )
        raise ValueError(f"native NIST numerical/API bodies differ from pinned legacy: {changed}")
    for row in contract["resources"]:
        if hashlib.sha256((root / row["v5_path"]).read_bytes()).hexdigest() != row["sha256"]:
            raise ValueError(f"preserved native NIST resource changed: {row['v5_path']}")
    return {
        "preserved_definitions": len(contract["definitions"]),
        "preserved_resources": len(contract["resources"]),
        "scope": "original numerical/API AST except docstrings and annotations, templates and retained KAT input files; statistical interpretation is tested separately",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.parse_args()
    print(json.dumps(validate(), indent=2))


if __name__ == "__main__":
    main()
