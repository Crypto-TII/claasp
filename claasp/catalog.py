"""CLAASP catalog and discovery helpers.

This module centralizes repository-level discovery utilities, such as listing
available cipher classes, listing component classes, and generating the
components-versus-methods matrix.

EXAMPLES::

    sage: from claasp.catalog import list_claasp_ciphers
    sage: ciphers = list_claasp_ciphers()
    sage: 'SpeckBlockCipher' in ciphers
    True

    sage: from claasp.catalog import list_real_component_classes
    sage: real_components = list_real_component_classes()
    sage: 'MultiInputNonlinearLogicalOperator' in real_components
    False
    sage: 'Modular' in real_components
    False

    sage: from claasp.catalog import build_component_method_table
    sage: header, rows = build_component_method_table(include_abstract=False)
    sage: header[0]
    'method'
    sage: len(rows) > 0
    True
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path


ABSTRACT_COMPONENT_CLASS_NAMES = frozenset({"MultiInputNonlinearLogicalOperator", "Modular"})


@dataclass(frozen=True)
class ClassInfo:
    """Class metadata discovered from CLAASP source files."""

    name: str
    qualified_name: str
    source_file: Path
    methods: frozenset[str]


def _package_root() -> Path:
    return Path(__file__).resolve().parent


def _public_methods_from_class(class_node: ast.ClassDef) -> set[str]:
    methods: set[str] = set()
    for node in class_node.body:
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("_"):
            methods.add(node.name)
    return methods


def _module_path_from_file(file_path: Path, package_root: Path) -> str:
    relative = file_path.relative_to(package_root).with_suffix("")
    return "claasp." + ".".join(relative.parts)


def _iter_classes_in_tree(file_path: Path) -> list[ast.ClassDef]:
    tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
    return [node for node in tree.body if isinstance(node, ast.ClassDef)]


def _discover_component_class_info(include_abstract: bool) -> list[ClassInfo]:
    package_root = _package_root()
    components_dir = package_root / "components"
    infos: list[ClassInfo] = []

    for file_path in sorted(components_dir.glob("*.py")):
        if file_path.name == "__init__.py":
            continue

        module_path = _module_path_from_file(file_path, package_root)
        for class_node in _iter_classes_in_tree(file_path):
            if not include_abstract and class_node.name in ABSTRACT_COMPONENT_CLASS_NAMES:
                continue

            infos.append(
                ClassInfo(
                    name=class_node.name,
                    qualified_name=f"{module_path}.{class_node.name}",
                    source_file=file_path,
                    methods=frozenset(_public_methods_from_class(class_node)),
                )
            )

    return sorted(infos, key=lambda info: info.name)


def list_component_classes(include_abstract=True, qualified=False):
    """Return CLAASP component class names discovered from ``claasp/components``.

    INPUT:

    - ``include_abstract`` -- **boolean** (default: ``True``); include abstract/base-only components.
    - ``qualified`` -- **boolean** (default: ``False``); if ``True``, return fully-qualified class names.

    EXAMPLES::

        sage: from claasp.catalog import list_component_classes
        sage: components = list_component_classes()
        sage: 'Xor' in components
        True
        sage: 'Modular' in list_component_classes(include_abstract=False)
        False
    """
    infos = _discover_component_class_info(include_abstract=include_abstract)
    if qualified:
        return [info.qualified_name for info in infos]

    return [info.name for info in infos]


def list_real_component_classes(qualified=False):
    """Return non-abstract CLAASP component class names.

    This excludes ``MultiInputNonlinearLogicalOperator`` and ``Modular``.

    INPUT:

    - ``qualified`` -- **boolean** (default: ``False``); if ``True``, return fully-qualified class names.

    EXAMPLES::

        sage: from claasp.catalog import list_real_component_classes
        sage: real_components = list_real_component_classes()
        sage: 'And' in real_components
        True
        sage: 'MultiInputNonlinearLogicalOperator' in real_components
        False
    """
    return list_component_classes(include_abstract=False, qualified=qualified)


def list_claasp_ciphers(qualified=False):
    """Return CLAASP cipher/permutation class names discovered from ``claasp/ciphers``.

    A class is considered a cipher if its class name ends with ``Cipher`` or ``Permutation``.

    INPUT:

    - ``qualified`` -- **boolean** (default: ``False``); if ``True``, return fully-qualified class names.

    EXAMPLES::

        sage: from claasp.catalog import list_claasp_ciphers
        sage: ciphers = list_claasp_ciphers()
        sage: 'SpeckBlockCipher' in ciphers
        True
        sage: 'ChachaPermutation' in ciphers
        True
    """
    package_root = _package_root()
    ciphers_dir = package_root / "ciphers"
    discovered: list[tuple[str, str]] = []

    for file_path in sorted(ciphers_dir.rglob("*.py")):
        if file_path.name == "__init__.py":
            continue

        module_path = _module_path_from_file(file_path, package_root)
        for class_node in _iter_classes_in_tree(file_path):
            if class_node.name.endswith("Cipher") or class_node.name.endswith("Permutation"):
                discovered.append((class_node.name, f"{module_path}.{class_node.name}"))

    discovered.sort(key=lambda item: item[0])
    if qualified:
        return [qualified_name for _, qualified_name in discovered]

    return [name for name, _ in discovered]


def _base_component_methods() -> set[str]:
    package_root = _package_root()
    component_file = package_root / "component.py"
    for class_node in _iter_classes_in_tree(component_file):
        if class_node.name == "Component":
            return _public_methods_from_class(class_node)

    raise ValueError(f"Could not find Component class in {component_file}")


def build_component_method_table(include_abstract=True):
    """Build a component-method table where rows are methods and columns are components.

    Cell values:

    - ``X`` means the method is implemented directly in the component class.
    - ``B`` means the method is inherited from base ``Component``.
    - ``""`` means the method is not available.

    INPUT:

    - ``include_abstract`` -- **boolean** (default: ``True``); include abstract/base-only components.

    OUTPUT:

    - ``header`` -- **list**; ``["method", <component names...>]``
    - ``rows`` -- **list**; each row starts with method name followed by per-component markers.

    EXAMPLES::

        sage: from claasp.catalog import build_component_method_table
        sage: header, rows = build_component_method_table(include_abstract=False)
        sage: header[0]
        'method'
        sage: any(row[0] == 'sat_constraints' for row in rows)
        True
    """
    component_infos = _discover_component_class_info(include_abstract=include_abstract)
    base_methods = _base_component_methods()
    all_methods = sorted(set().union(*(set(info.methods) for info in component_infos), base_methods))

    header = ["method"] + [info.name for info in component_infos]
    rows: list[list[str]] = []
    for method in all_methods:
        row = [method]
        for info in component_infos:
            if method in info.methods:
                row.append("X")
            elif method in base_methods:
                row.append("B")
            else:
                row.append("")
        rows.append(row)

    return header, rows


def render_component_method_table_markdown(include_abstract=True):
    """Render component-method table as Markdown.

    INPUT:

    - ``include_abstract`` -- **boolean** (default: ``True``); include abstract/base-only components.

    EXAMPLES::

        sage: from claasp.catalog import render_component_method_table_markdown
        sage: text = render_component_method_table_markdown(include_abstract=False)
        sage: text.splitlines()[0]
        'Legend: X=implemented in class, B=inherited from Component'
    """
    header, rows = build_component_method_table(include_abstract=include_abstract)
    lines = [
        "Legend: X=implemented in class, B=inherited from Component",
        "",
        "| " + " | ".join(header) + " |",
        "| " + " | ".join(["---"] * len(header)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")

    return "\n".join(lines)