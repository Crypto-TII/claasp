"""CLAASP catalog and discovery helpers.

EXAMPLES::

    sage: from claasp.catalog import Catalog
    sage: catalog = Catalog()
    sage: catalog
    <claasp.catalog.Catalog object at ...>
"""

from __future__ import annotations

import ast
from functools import lru_cache
import importlib
import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path


ABSTRACT_COMPONENT_CLASS_NAMES = frozenset({"MultiInputNonlinearLogicalOperator", "Modular"})
IO_COMPONENT_CLASS_NAMES = frozenset({"CipherOutput", "IntermediateOutput"})
ARX_COMPONENTS = frozenset({"constant", "modadd", "rotate", "xor"})
PURE_ARX_COMPONENTS = frozenset({"modadd", "rotate", "xor"})
ANDRX_COMPONENTS = frozenset({"and", "constant", "rotate", "xor"})
PURE_ANDRX_COMPONENTS = frozenset({"and", "rotate", "xor"})
SPECIAL_CIPHER_FILTERS = frozenset({
    "tweakable_block_cipher",
    "sbox_based",
    "fsr_based",
    "arx",
    "purearx",
    "andrx",
    "pureandrx",
})
FILTER_ALIASES = {
    "block_cipher": "block_ciphers",
    "block_ciphers": "block_ciphers",
    "hash_function": "hash_functions",
    "hash_functions": "hash_functions",
    "macs": "mac",
    "mac": "mac",
    "permutation": "permutations",
    "permutations": "permutations",
    "pure-arx": "purearx",
    "pure_arx": "purearx",
    "purearx": "purearx",
    "pure-andrx": "pureandrx",
    "pure_andrx": "pureandrx",
    "pureandrx": "pureandrx",
    "single_component_cipher": "single_component_ciphers",
    "single_component_ciphers": "single_component_ciphers",
    "sbox-based": "sbox_based",
    "sbox_based": "sbox_based",
    "fsr-based": "fsr_based",
    "fsr_based": "fsr_based",
    "stream_cipher": "stream_ciphers",
    "stream_ciphers": "stream_ciphers",
    "toy": "toys",
    "toys": "toys",
    "tweakable_block_ciphers": "tweakable_block_cipher",
    "tweakable_block_cipher": "tweakable_block_cipher",
}
IO_CIPHER_COMPONENT_NAMES = frozenset(
    {"cipher_output", "intermediate_output", "round_key_output", "round_output"}
)
MODULE_INIT_FILE = "__init__.py"


@dataclass(frozen=True)
class ClassInfo:
    """Class metadata discovered from CLAASP source files."""

    name: str
    qualified_name: str
    module_name: str
    source_file: Path
    methods: frozenset[str]


@dataclass(frozen=True)
class CipherInfo:
    """Cipher metadata discovered from CLAASP source files."""

    name: str
    qualified_name: str
    module_name: str
    category: str
    components: tuple[str, ...]
    tags: frozenset[str]


class RenderedText(str):
    """String wrapper with terminal-friendly REPL representation."""

    def __repr__(self) -> str:
        return str(self)


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


def _allowed_component_name_from_cipher_method(method_name: str) -> str | None:
    if not (method_name.startswith("add_") and method_name.endswith("_component")):
        return None

    component_name = method_name[len("add_") : -len("_component")]
    if not component_name or component_name in IO_CIPHER_COMPONENT_NAMES:
        return None

    return component_name


def _allowed_components_from_cipher_api(cipher_file: Path) -> set[str]:
    allowed = set()

    for class_node in _iter_classes_in_tree(cipher_file):
        if class_node.name != "Cipher":
            continue

        for node in class_node.body:
            if not isinstance(node, ast.FunctionDef):
                continue

            component_name = _allowed_component_name_from_cipher_method(node.name)
            if component_name is not None:
                allowed.add(component_name)

    return allowed


def _allowed_component_name_from_module(file_path: Path) -> str | None:
    module_stem = file_path.stem
    ignored_module_names = {
        MODULE_INIT_FILE[:-3],
        "multi_input_non_linear_logical_operator_component",
        "modular_component",
    }
    if module_stem in ignored_module_names:
        return None

    component_name = module_stem[: -len("_component")]
    if not component_name or component_name in IO_CIPHER_COMPONENT_NAMES:
        return None

    return component_name


def _allowed_components_from_component_modules(components_dir: Path) -> set[str]:
    allowed = set()

    for file_path in sorted(components_dir.glob("*_component.py")):
        component_name = _allowed_component_name_from_module(file_path)
        if component_name is not None:
            allowed.add(component_name)

    return allowed


def _allowed_cipher_component_names(package_root: Path) -> frozenset[str]:
    """Infer valid cipher component names from API methods and component modules."""
    cipher_file = package_root / "cipher.py"
    components_dir = package_root / "components"
    allowed = _allowed_components_from_cipher_api(cipher_file)

    # Include concrete component modules to keep discovery forward-compatible
    # when new components are added before the Cipher wrapper methods.
    allowed.update(_allowed_components_from_component_modules(components_dir))

    return frozenset(allowed)


@lru_cache(maxsize=1)
def _default_allowed_cipher_components() -> frozenset[str]:
    return _allowed_cipher_component_names(_package_root())


def _extract_external_solver_executable(solver: dict) -> str | None:
    command = solver.get("keywords", {}).get("command", {})
    executable = command.get("executable")

    if isinstance(executable, str):
        return executable

    if isinstance(executable, list):
        for token in executable:
            if isinstance(token, str) and token.strip() and not token.startswith("-"):
                return token

    return None


def _solver_is_available(executable: str | None) -> bool:
    if executable is None:
        return False

    return shutil.which(executable) is not None


def _table(name: str, columns: list[str], rows: list[dict]) -> dict:
    return {"name": name, "columns": columns, "rows": rows}


def _normalize_column_selector(
    selector: str | list[str] | tuple[str, ...] | None,
) -> list[str] | None:
    if selector is None:
        return None

    items = [selector] if isinstance(selector, str) else list(selector)
    normalized = []
    seen = set()
    for item in items:
        token = str(item).strip()
        if not token or token in seen:
            continue
        normalized.append(token)
        seen.add(token)
    return normalized


def _project_table_columns(
    table: dict,
    columns: str | list[str] | tuple[str, ...] | None = None,
    exclude_columns: str | list[str] | tuple[str, ...] | None = None,
) -> dict:
    requested = _normalize_column_selector(columns)
    excluded = _normalize_column_selector(exclude_columns) or []
    available = table["columns"]

    if requested is None:
        selected = list(available)
    else:
        missing = [column for column in requested if column not in available]
        if missing:
            raise ValueError(f"Unknown selected columns: {missing}. Available columns: {available}")
        selected = [column for column in available if column in requested]

    missing_excluded = [column for column in excluded if column not in available]
    if missing_excluded:
        raise ValueError(f"Unknown excluded columns: {missing_excluded}. Available columns: {available}")

    if excluded:
        excluded_set = set(excluded)
        selected = [column for column in selected if column not in excluded_set]

    rows = [{column: row.get(column, "") for column in selected} for row in table["rows"]]
    return _table(table["name"], selected, rows)


def _normalize_filters(
    filters: str | list[str] | tuple[str, ...] | None,
    allowed_filters: set[str] | frozenset[str],
) -> set[str]:
    if filters is None:
        return set()

    if isinstance(filters, str):
        items = [filters]
    else:
        items = list(filters)

    normalized = set()
    for item in items:
        token = str(item).strip().lower()
        token = FILTER_ALIASES.get(token, token)
        normalized.add(token)

    unknown = normalized.difference(allowed_filters)
    if unknown:
        accepted_aliases = set()
        for alias, canonical in FILTER_ALIASES.items():
            if canonical not in allowed_filters:
                continue
            # Keep singular/plural aliases, but avoid separator-only duplicates
            # such as "sbox-based" vs "sbox_based" in the suggestion list.
            alias_compact = alias.replace("-", "").replace("_", "")
            canonical_compact = canonical.replace("-", "").replace("_", "")
            if alias_compact == canonical_compact:
                continue
            accepted_aliases.add(alias)
        accepted_values = sorted(set(allowed_filters).union(accepted_aliases))
        allowed = ", ".join(accepted_values)
        raise ValueError(f"Unknown cipher filters: {sorted(unknown)}. Allowed values: {allowed}")

    return normalized


def _normalize_components_filter(
    has_components: str | list[str] | tuple[str, ...] | None,
) -> set[str]:
    if has_components is None:
        return set()

    if isinstance(has_components, str):
        items = [has_components]
    else:
        items = list(has_components)

    normalized = set()
    for item in items:
        token = str(item).strip().lower().replace("-", "_")
        if token == "variable_rotate":
            token = "rotate"
        if token:
            normalized.add(token)

    return normalized


def _cipher_categories(package_root: Path) -> frozenset[str]:
    ciphers_dir = package_root / "ciphers"
    return frozenset(
        path.name
        for path in ciphers_dir.iterdir()
        if path.is_dir() and not path.name.startswith("__")
    )


def _supported_cipher_filters(cipher_categories: set[str] | frozenset[str]) -> frozenset[str]:
    return frozenset(set(cipher_categories).union(SPECIAL_CIPHER_FILTERS))


def _base_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_cipher_class(class_node: ast.ClassDef) -> bool:
    if class_node.name.startswith("_"):
        return False

    base_names = {_base_name(base) for base in class_node.bases}
    base_names.discard(None)
    if not base_names:
        return False

    if "Cipher" in base_names:
        return True

    return any(base_name.endswith(("Cipher", "Permutation", "HashFunction", "MAC")) for base_name in base_names)


def _cipher_components(
    source_text: str,
    allowed_components: set[str] | frozenset[str] | None = None,
) -> set[str]:
    operations = set(re.findall(r"add_([a-z0-9_]+)_component", source_text.lower()))
    if "variable_rotate" in operations:
        operations.remove("variable_rotate")
        operations.add("rotate")

    valid_components = _default_allowed_cipher_components() if allowed_components is None else set(allowed_components)
    operations.intersection_update(valid_components)

    return operations


def _resolve_module_source_file(module_name: str, package_root: Path) -> Path | None:
    if not module_name.startswith("claasp."):
        return None

    module_parts = module_name.split(".")[1:]
    if not module_parts:
        return None

    module_file = package_root.joinpath(*module_parts).with_suffix(".py")
    if module_file.exists():
        return module_file

    module_init = package_root.joinpath(*module_parts, MODULE_INIT_FILE)
    if module_init.exists():
        return module_init

    return None


def _is_cipher_module_name(module_name: str) -> bool:
    return module_name.startswith("claasp.ciphers.")


def _resolve_imported_module_name(node: ast.ImportFrom, current_parts: list[str]) -> str | None:
    if node.level == 0:
        return node.module or ""

    if len(current_parts) <= node.level:
        return None

    base_parts = current_parts[:-node.level]
    if node.module:
        resolved = ".".join(base_parts + node.module.split("."))
        # Some callers (for example tests) may resolve relative imports from
        # outside ``claasp.ciphers`` even when the imported module clearly
        # targets cipher packages. Normalize those to the canonical namespace.
        if node.module.startswith("ciphers.") and not resolved.startswith("claasp.ciphers."):
            return f"claasp.{node.module}"
        return resolved

    return ".".join(base_parts)


def _collect_simple_import_modules(node: ast.Import) -> set[str]:
    result = set()
    for alias in node.names:
        if _is_cipher_module_name(alias.name):
            result.add(alias.name)
    return result


def _collect_from_import_modules(
    node: ast.ImportFrom, current_parts: list[str], package_root: Path
) -> set[str]:
    result = set()
    imported = _resolve_imported_module_name(node, current_parts)
    if not imported or not _is_cipher_module_name(imported):
        return result

    # For "from pkg import mod" style imports the resolved name is the
    # package (e.g. "claasp.ciphers.stream_ciphers"), whose __init__.py
    # may be empty.  Also try each alias as a submodule so that the
    # actual cipher file is traversed.
    added_submodule = False
    for alias in node.names:
        candidate = f"{imported}.{alias.name}"
        if _resolve_module_source_file(candidate, package_root) is not None:
            result.add(candidate)
            added_submodule = True

    if not added_submodule:
        result.add(imported)
    return result


def _imported_cipher_modules(tree: ast.AST, current_module: str, package_root: Path) -> set[str]:
    modules = set()
    current_parts = current_module.split(".")

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(_collect_simple_import_modules(node))
        elif isinstance(node, ast.ImportFrom):
            modules.update(_collect_from_import_modules(node, current_parts, package_root))

    return modules


def _collect_components_from_cipher_module(
    module_name: str,
    package_root: Path,
    cache: dict[str, set[str]],
    visiting: set[str],
    allowed_components: set[str] | frozenset[str],
) -> set[str]:
    if module_name in cache:
        return set(cache[module_name])

    if module_name in visiting:
        return set()

    visiting.add(module_name)
    try:
        source_file = _resolve_module_source_file(module_name, package_root)
        if source_file is None:
            cache[module_name] = set()
            return set()

        source_text = source_file.read_text(encoding="utf-8")
        components = _cipher_components(source_text, allowed_components)
        tree = ast.parse(source_text, filename=str(source_file))
        for imported_module in _imported_cipher_modules(tree, module_name, package_root):
            components.update(
                _collect_components_from_cipher_module(
                    imported_module,
                    package_root,
                    cache,
                    visiting,
                    allowed_components,
                )
            )

        cache[module_name] = components
        return set(components)
    finally:
        visiting.remove(module_name)


def _infer_cipher_design_tags(operations: set[str]) -> set[str]:
    design_tags = set()
    if operations == PURE_ANDRX_COMPONENTS:
        design_tags.add("pureandrx")
        design_tags.add("andrx")
    elif operations == ANDRX_COMPONENTS:
        design_tags.add("andrx")
    if operations == PURE_ARX_COMPONENTS:
        design_tags.add("purearx")
        design_tags.add("arx")
    elif operations == ARX_COMPONENTS:
        design_tags.add("arx")
    if "sbox" in operations:
        design_tags.add("sbox_based")
    if "fsr" in operations:
        design_tags.add("fsr_based")
    return design_tags


def _cipher_tags(category: str, source_text: str, class_name: str, operations: set[str]) -> set[str]:
    tags = {category}
    if category == "hash_functions":
        tags.add("hash_function")

    tags.update(_infer_cipher_design_tags(operations))

    lower_name = class_name.lower()
    if "tweak" in source_text.lower() or "qarm" in lower_name or "mantis" in lower_name:
        tags.add("tweakable_block_cipher")

    return tags


def _load_cipher_instance(qualified_name: str):
    module_name, class_name = qualified_name.rsplit(".", 1)
    module = importlib.import_module(module_name)
    cls = getattr(module, class_name)
    return cls()


def _collect_solver_entries(
    family: str,
    internal_solvers: list[dict],
    external_solvers: list[dict],
    include_internal: bool,
    include_external: bool,
) -> list[dict]:
    rows = []

    if include_internal:
        for solver in internal_solvers:
            rows.append(
                {
                    "solver_name": solver.get("solver_name"),
                    "solver_brand_name": solver.get("solver_brand_name"),
                    "family": family,
                    "source": "internal",
                    "executable": None,
                    "available": True,
                }
            )

    if include_external:
        for solver in external_solvers:
            executable = _extract_external_solver_executable(solver)
            rows.append(
                {
                    "solver_name": solver.get("solver_name"),
                    "solver_brand_name": solver.get("solver_brand_name"),
                    "family": family,
                    "source": "external",
                    "executable": executable,
                    "available": _solver_is_available(executable),
                }
            )

    rows.sort(key=lambda r: (r["source"], str(r["solver_name"])))
    return rows


def _base_component_methods(package_root: Path) -> set[str]:
    component_file = package_root / "component.py"
    for class_node in _iter_classes_in_tree(component_file):
        if class_node.name == "Component":
            return _public_methods_from_class(class_node)

    return set()


def _is_python_source_file(file_path: Path) -> bool:
    return file_path.suffix == ".py" and file_path.name != MODULE_INIT_FILE and not file_path.name.startswith("_")


def _cipher_category_from_path(file_path: Path, ciphers_dir: Path) -> str:
    relative_parts = file_path.relative_to(ciphers_dir).parts
    return relative_parts[0] if len(relative_parts) > 1 else "other"


def _collect_imported_components(
    tree: ast.AST,
    module_name: str,
    package_root: Path,
    import_component_cache: dict[str, set[str]],
    allowed_components: set[str] | frozenset[str],
) -> set[str]:
    imported_components = set()
    for imported_module in _imported_cipher_modules(tree, module_name, package_root):
        imported_components.update(
            _collect_components_from_cipher_module(
                imported_module,
                package_root,
                import_component_cache,
                set(),
                allowed_components,
            )
        )

    return imported_components


def _discover_cipher_infos_from_file(
    file_path: Path,
    ciphers_dir: Path,
    package_root: Path,
    import_component_cache: dict[str, set[str]],
    allowed_components: set[str] | frozenset[str],
) -> list[CipherInfo]:
    module_name = _module_path_from_file(file_path, package_root)
    source_text = file_path.read_text(encoding="utf-8")
    tree = ast.parse(source_text, filename=str(file_path))
    discovered_components = _cipher_components(source_text, allowed_components).union(
        _collect_imported_components(
            tree,
            module_name,
            package_root,
            import_component_cache,
            allowed_components,
        )
    )
    category = _cipher_category_from_path(file_path, ciphers_dir)

    infos = []
    for class_node in (node for node in tree.body if isinstance(node, ast.ClassDef)):
        if not _is_cipher_class(class_node):
            continue

        class_name = class_node.name
        qualified_name = f"{module_name}.{class_name}"
        components = set(discovered_components)
        tags = frozenset(_cipher_tags(category, source_text, class_name, components))
        infos.append(
            CipherInfo(
                name=class_name,
                qualified_name=qualified_name,
                module_name=module_name,
                category=category,
                components=tuple(sorted(components)),
                tags=tags,
            )
        )

    return infos


def _matches_cipher_filters(
    info: CipherInfo,
    normalized_filters: set[str],
    required_components: set[str],
) -> bool:
    for filter_name in normalized_filters:
        if filter_name not in info.tags:
            return False
    if required_components and not required_components.issubset(set(info.components)):
        return False

    return True


def _cipher_metadata(qualified_name: str) -> dict:
    metadata = {
        "family_name": None,
        "cipher_type": None,
        "inputs": None,
        "inputs_bit_size": None,
        "output_bit_size": None,
        "number_of_rounds": None,
        "id": None,
        "metadata_error": None,
    }
    try:
        instance = _load_cipher_instance(qualified_name)
        metadata.update(
            {
                "family_name": getattr(instance, "family_name", None),
                "cipher_type": getattr(instance, "type", None),
                "inputs": getattr(instance, "inputs", None),
                "inputs_bit_size": getattr(instance, "inputs_bit_size", None),
                "output_bit_size": getattr(instance, "output_bit_size", None),
                "number_of_rounds": getattr(instance, "number_of_rounds", None),
                "id": getattr(instance, "id", None),
            }
        )
    except Exception as error:  # pragma: no cover - environment dependent
        metadata["metadata_error"] = f"{error.__class__.__name__}: {error}"

    return metadata


def _cipher_row(info: CipherInfo, include_metadata: bool, qualified: bool) -> dict:
    row = {
        "class_name": info.name,
        "module_name": info.module_name,
        "qualified_name": info.qualified_name,
        "category": info.category,
        "components": list(info.components),
        "tags": sorted(info.tags),
    }
    if include_metadata:
        row.update(_cipher_metadata(info.qualified_name))
    if not qualified:
        row.pop("qualified_name")

    return row


class Catalog:
    """Facade class for CLAASP discovery and catalog helpers.

    This class provides a single entry point to discover CLAASP assets such as
    ciphers, components, solvers, and implemented component methods.

    Each discovery method returns a plain table dictionary with the same shape:

    - ``name``: logical table name (for example ``"ciphers"``)
    - ``columns``: ordered list of column names
    - ``rows``: list of row dictionaries

    The consistent table format makes it easy to inspect results in Python,
    filter/project columns, and render or export data through helper methods.

    EXAMPLES::

        sage: from claasp.catalog import Catalog
        sage: catalog = Catalog()

        sage: # Basic cipher discovery structure.
        sage: ciphers = catalog.ciphers()
        sage: ciphers.keys()
        dict_keys(['name', 'columns', 'rows'])
        sage: ciphers['name']
        'ciphers'
        sage: ciphers['columns']
        ['class_name', 'module_name', 'category', 'components', 'tags']
        sage: ciphers['rows'][0].keys()
        dict_keys(['class_name', 'module_name', 'category', 'components', 'tags'])
        sage: ciphers['rows'][0]['class_name']
        'A51StreamCipher'

        sage: # Components and solvers follow the same table shape.
        sage: components = catalog.components()
        sage: components['name']
        'components'
        sage: components['rows'][0]['class_name']
        'And'

        sage: solvers = catalog.solvers()
        sage: solvers['name']
        'solvers'
        sage: solvers['rows'][0]['family']
        'cp'

        sage: methods = catalog.implemented_methods_per_component()
        sage: methods['name']
        'implemented_methods_per_component'
        sage: methods['rows'][0]['method']
        'algebraic_polynomials'

        sage: # Use convenience helpers to render ciphers directly.
        sage: catalog.show_ciphers()
        class_name                              | module_name                                                                 | category                 | components                                                                               | tags                                                     
        ----------------------------------------+-----------------------------------------------------------------------------+--------------------------+------------------------------------------------------------------------------------------+----------------------------------------------------------
        A51StreamCipher                         | claasp.ciphers.stream_ciphers.a5_1_stream_cipher                            | stream_ciphers           | ['constant', 'fsr', 'xor']                                                               | ['fsr_based', 'stream_ciphers']                          
        A52StreamCipher                         | claasp.ciphers.stream_ciphers.a5_2_stream_cipher                            | stream_ciphers           | ['and', 'constant', 'fsr', 'or', 'xor']                                                  | ['fsr_based', 'stream_ciphers']                          
        AESBlockCipher                          | claasp.ciphers.block_ciphers.aes_block_cipher                               | block_ciphers            | ['constant', 'mix_column', 'rotate', 'sbox', 'xor']                                      | ['block_ciphers', 'sbox_based']                          
        ...
        sage: catalog.show_ciphers(has_components=['sbox'], columns=['class_name', 'tags'], fmt='markdown')
        | class_name | tags |
        | --- | --- |
        | AESBlockCipher | ['block_ciphers', 'sbox_based'] |
        ...
    """

    def __init__(self, package_root=None):
        self._package_root = Path(package_root).resolve() if package_root is not None else _package_root()
        self._allowed_cipher_components = _allowed_cipher_component_names(self._package_root)
        self._cipher_categories = _cipher_categories(self._package_root)
        self._supported_cipher_filters = _supported_cipher_filters(self._cipher_categories)
        self._component_infos = self._discover_components()
        self._cipher_infos = self._discover_ciphers()
        self._base_methods = _base_component_methods(self._package_root)

    def _discover_components(self) -> list[ClassInfo]:
        components_dir = self._package_root / "components"
        infos: list[ClassInfo] = []

        for file_path in sorted(components_dir.glob("*.py")):
            if file_path.name == MODULE_INIT_FILE:
                continue

            module_name = _module_path_from_file(file_path, self._package_root)
            for class_node in _iter_classes_in_tree(file_path):
                class_name = class_node.name
                infos.append(
                    ClassInfo(
                        name=class_name,
                        qualified_name=f"{module_name}.{class_name}",
                        module_name=module_name,
                        source_file=file_path,
                        methods=frozenset(_public_methods_from_class(class_node)),
                    )
                )

        infos.sort(key=lambda info: info.name)
        return infos

    def _discover_ciphers(self) -> list[CipherInfo]:
        ciphers_dir = self._package_root / "ciphers"
        infos: list[CipherInfo] = []
        import_component_cache: dict[str, set[str]] = {}

        for file_path in sorted(ciphers_dir.rglob("*.py")):
            if not _is_python_source_file(file_path):
                continue
            infos.extend(
                _discover_cipher_infos_from_file(
                    file_path,
                    ciphers_dir,
                    self._package_root,
                    import_component_cache,
                    self._allowed_cipher_components,
                )
            )

        infos.sort(key=lambda info: info.name)
        return infos

    def components(
        self,
        include_abstract: bool = False,
        include_io_components: bool = False,
        qualified: bool = False,
    ) -> dict:
        """List CLAASP components as a table.

        By default this returns only real components (non-abstract) and excludes
        ``CipherOutput`` and ``IntermediateOutput``.

        INPUT:

        - ``include_abstract`` -- **boolean** (default: ``False``); include abstract component classes.
        - ``include_io_components`` -- **boolean** (default: ``False``); include output wrappers.
        - ``qualified`` -- **boolean** (default: ``False``); include full module path.

        EXAMPLES::

            sage: from claasp.catalog import Catalog
            sage: catalog = Catalog()

            sage: # Default view: abstract helpers excluded, rows sorted by class name.
            sage: catalog.components()['rows'][0]['class_name']
            'And'

            sage: # Enable abstract classes to see them listed.
            sage: abstract = [row['class_name'] for row in catalog.components(include_abstract=True)['rows'] if row['is_abstract']]
            sage: sorted(abstract)
            ['Modular', 'MultiInputNonlinearLogicalOperator']

            sage: # Full import paths with qualified=True.
            sage: catalog.components(qualified=True)['rows'][0]['qualified_name']
            'claasp.components.and_component.And'
        """
        rows = []

        for info in self._component_infos:
            class_name = info.name
            if not include_abstract and class_name in ABSTRACT_COMPONENT_CLASS_NAMES:
                continue
            if not include_io_components and class_name in IO_COMPONENT_CLASS_NAMES:
                continue

            row = {
                "class_name": class_name,
                "module_name": info.module_name,
                "qualified_name": info.qualified_name,
                "is_abstract": class_name in ABSTRACT_COMPONENT_CLASS_NAMES,
                "is_io_component": class_name in IO_COMPONENT_CLASS_NAMES,
            }
            if not qualified:
                row.pop("qualified_name")
            rows.append(row)

        rows.sort(key=lambda r: r["class_name"])
        columns = [
            "class_name",
            "module_name",
            "qualified_name",
            "is_abstract",
            "is_io_component",
        ]
        if not qualified:
            columns.remove("qualified_name")

        return _table("components", columns, rows)

    def ciphers(
        self,
        filters: str | list[str] | tuple[str, ...] | None = None,
        has_components: str | list[str] | tuple[str, ...] | None = None,
        include_metadata: bool = False,
        qualified: bool = False,
    ) -> dict:
        """List entries discovered under ``claasp/ciphers`` as a table.

        INPUT:

        - ``filters`` -- **string/list/tuple** (default: ``None``); category/tag filters.
          Category filters are retrieved automatically from subfolders under ``claasp/ciphers``
          such as ``block_ciphers``, ``permutations``, ``stream_ciphers``, ``hash_functions``,
          ``mac``, ``single_component_ciphers``, and ``toys``. Additional derived tags include
                    ``tweakable_block_cipher``, ``sbox_based``, ``fsr_based``, ``arx``, ``purearx``, ``andrx``,
                    and ``pureandrx``.
          Multiple filters are combined with logical AND.
        - ``has_components`` -- **string/list/tuple** (default: ``None``); keep only ciphers whose
          component set contains all requested components (logical AND), e.g. ``['sbox', 'xor']``.
        - ``include_metadata`` -- **boolean** (default: ``False``); include cipher runtime metadata.
        - ``qualified`` -- **boolean** (default: ``False``); include full module path.

        EXAMPLES::

            sage: from claasp.catalog import Catalog
            sage: catalog = Catalog()

            sage: # Category filters come directly from subfolders under claasp/ciphers.
            sage: catalog.ciphers(filters='mac')['rows'][0]['class_name']
            'SiphashMAC'

            sage: # Combine filters (AND logic): block ciphers that are sbox-based.
            sage: catalog.ciphers(filters=['block_ciphers', 'sbox_based'])['rows'][0]['class_name']
            'AESBlockCipher'

            sage: # Components lists all add_*_component calls (IO outputs removed).
            sage: catalog.ciphers(filters='mac')['rows'][0]['components']
            ['constant', 'modadd', 'rotate', 'xor']

            sage: # Filter by required components (AND logic).
            sage: rows = catalog.ciphers(filters='toys', has_components=['sbox', 'xor'])['rows']
            sage: rows[0]['class_name']
            'FancyBlockCipher'

            sage: # include_metadata=True adds runtime attributes from the default instance.
            sage: meta = catalog.ciphers(filters='stream_ciphers', include_metadata=True)
            sage: meta['columns'][-4:-1]
            ['output_bit_size', 'number_of_rounds', 'id']
            sage: meta['rows'][0]['cipher_type']
            'stream_cipher'
        """
        normalized_filters = _normalize_filters(filters, self._supported_cipher_filters)
        required_components = _normalize_components_filter(has_components)
        rows = []

        for info in self._cipher_infos:
            if not _matches_cipher_filters(info, normalized_filters, required_components):
                continue
            rows.append(_cipher_row(info, include_metadata, qualified))

        rows.sort(key=lambda r: r["class_name"])

        columns = ["class_name", "module_name", "qualified_name", "category", "components", "tags"]
        if include_metadata:
            columns.extend(
                [
                    "family_name",
                    "cipher_type",
                    "inputs",
                    "inputs_bit_size",
                    "output_bit_size",
                    "number_of_rounds",
                    "id",
                    "metadata_error",
                ]
            )
        if not qualified:
            columns.remove("qualified_name")

        return _table("ciphers", columns, rows)

    def solvers(
        self,
        include_internal: bool = True,
        include_external: bool = True,
        grouped: bool = False,
    ) -> dict | dict[str, dict]:
        """List SAT/SMT/MILP/CP solvers with availability status as table data.

        INPUT:

        - ``include_internal`` -- **boolean** (default: ``True``); include internal solver entries.
        - ``include_external`` -- **boolean** (default: ``True``); include external solver entries.
        - ``grouped`` -- **boolean** (default: ``False``); return one table per family.

        EXAMPLES::

            sage: from claasp.catalog import Catalog
            sage: catalog = Catalog()

            sage: # Flat list of all solvers across every family.
            sage: solvers = catalog.solvers()
            sage: solvers['columns']
            ['solver_name', 'solver_brand_name', 'family', 'source', 'executable', 'available']

            sage: # Grouped by family; each value is its own table.
            sage: grouped = catalog.solvers(grouped=True)
            sage: sorted(grouped)
            ['cp', 'milp', 'sat', 'smt']
            sage: grouped['cp']['rows'][0]['family']
            'cp'

            sage: # Restrict to external solvers only (those needing a local executable).
            sage: ext = catalog.solvers(include_internal=False)['rows']
            sage: ext[0]['source']
            'external'
        """
        from claasp.cipher_modules.models.cp.solvers import CP_SOLVERS_EXTERNAL, CP_SOLVERS_INTERNAL
        from claasp.cipher_modules.models.milp.solvers import MILP_SOLVERS_EXTERNAL, MILP_SOLVERS_INTERNAL
        from claasp.cipher_modules.models.sat.solvers import SAT_SOLVERS_EXTERNAL, SAT_SOLVERS_INTERNAL
        from claasp.cipher_modules.models.smt.solvers import SMT_SOLVERS_EXTERNAL, SMT_SOLVERS_INTERNAL

        grouped_rows = {
            "cp": _collect_solver_entries(
                "cp",
                CP_SOLVERS_INTERNAL,
                CP_SOLVERS_EXTERNAL,
                include_internal,
                include_external,
            ),
            "sat": _collect_solver_entries(
                "sat",
                SAT_SOLVERS_INTERNAL,
                SAT_SOLVERS_EXTERNAL,
                include_internal,
                include_external,
            ),
            "smt": _collect_solver_entries(
                "smt",
                SMT_SOLVERS_INTERNAL,
                SMT_SOLVERS_EXTERNAL,
                include_internal,
                include_external,
            ),
            "milp": _collect_solver_entries(
                "milp",
                MILP_SOLVERS_INTERNAL,
                MILP_SOLVERS_EXTERNAL,
                include_internal,
                include_external,
            ),
        }

        columns = ["solver_name", "solver_brand_name", "family", "source", "executable", "available"]
        if grouped:
            return {family: _table(f"solvers_{family}", columns, rows) for family, rows in grouped_rows.items()}

        rows = []
        for family in ("cp", "sat", "smt", "milp"):
            rows.extend(grouped_rows[family])

        return _table("solvers", columns, rows)

    def implemented_methods_per_component(
        self,
        include_abstract: bool = False,
        include_io_components: bool = False,
    ) -> dict:
        """Return a methods-per-component coverage table.

        The table has methods as rows and component class names as columns.

        Cell values:

        - ``X``: method implemented directly in component class
        - ``B``: inherited from base ``Component``
        - ``""``: not available

        INPUT:

        - ``include_abstract`` -- **boolean** (default: ``False``)
        - ``include_io_components`` -- **boolean** (default: ``False``)

        EXAMPLES::

            sage: from claasp.catalog import Catalog
            sage: table = Catalog().implemented_methods_per_component()

            sage: # First column is always 'method'; remaining columns are component class names.
            sage: table['columns'][:4]
            ['method', 'And', 'Constant', 'Fsr']

            sage: # X = implemented in that class, B = inherited from Component base.
            sage: sat_row = [row for row in table['rows'] if row['method'] == 'sat_constraints'][0]
            sage: sat_row['And']
            'X'

            sage: # Abstract classes are excluded by default.
            sage: 'Modular' in table['columns']
            False
        """
        component_infos = [
            info
            for info in self._component_infos
            if (include_abstract or info.name not in ABSTRACT_COMPONENT_CLASS_NAMES)
            and (include_io_components or info.name not in IO_COMPONENT_CLASS_NAMES)
        ]

        all_methods = sorted(set().union(*(set(info.methods) for info in component_infos), self._base_methods))

        columns = ["method"] + [info.name for info in component_infos]
        rows = []
        for method in all_methods:
            row = {"method": method}
            for info in component_infos:
                if method in info.methods:
                    row[info.name] = "X"
                elif method in self._base_methods:
                    row[info.name] = "B"
                else:
                    row[info.name] = ""
            rows.append(row)

        return _table("implemented_methods_per_component", columns, rows)

    def to_json(self, table: dict, indent: int = 2) -> str:
        """Serialize a table dictionary to JSON text.

        EXAMPLES::

            sage: from claasp.catalog import Catalog
            sage: import json
            sage: table = Catalog().components()
            sage: data = json.loads(Catalog().to_json(table))
            sage: data['name']
            'components'
            sage: data['columns']
            ['class_name', 'module_name', 'is_abstract', 'is_io_component']
            sage: data['rows'][0]['class_name']
            'And'
        """
        return json.dumps(table, indent=indent, default=str)

    def to_dataframe(self, table: dict):
        """Convert a table dictionary to a pandas DataFrame.

        EXAMPLES::

            sage: from claasp.catalog import Catalog
            sage: table = {'name': 'demo', 'columns': ['k', 'v'], 'rows': [{'k': 'alpha', 'v': 1}]}
            sage: df = Catalog().to_dataframe(table)
            sage: list(df.columns)
            ['k', 'v']
            sage: df.to_dict(orient='records')
            [{'k': 'alpha', 'v': 1}]
        """
        try:
            import pandas as pd
        except ImportError as error:  # pragma: no cover - environment dependent
            raise ImportError("pandas is required for to_dataframe().") from error

        columns = table["columns"]
        rows = [{column: row.get(column, "") for column in columns} for row in table["rows"]]
        return pd.DataFrame(rows, columns=columns)

    def to_markdown(self, table: dict) -> str:
        """Render a table dictionary as Markdown.

        EXAMPLES::

            sage: from claasp.catalog import Catalog
            sage: table = {'name': 'demo', 'columns': ['k', 'v'], 'rows': [{'k': 'alpha', 'v': 1}]}
            sage: md = Catalog().to_markdown(table)
            sage: '| k | v |' in md
            True
            sage: '| alpha | 1 |' in md
            True
        """
        columns = table["columns"]
        rows = table["rows"]
        lines = [
            "| " + " | ".join(columns) + " |",
            "| " + " | ".join(["---"] * len(columns)) + " |",
        ]

        for row in rows:
            lines.append("| " + " | ".join(str(row.get(column, "")) for column in columns) + " |")

        return "\n".join(lines)

    def to_csv(self, table: dict) -> str:
        """Render a table dictionary as CSV text.

        EXAMPLES::

            sage: from claasp.catalog import Catalog
            sage: table = {'name': 'demo', 'columns': ['k', 'v'], 'rows': [{'k': 'alpha', 'v': 1}]}
            sage: csv_text = Catalog().to_csv(table)
            sage: csv_text.splitlines()[0]
            'k,v'
            sage: csv_text.splitlines()[1]
            'alpha,1'
        """
        dataframe = self.to_dataframe(table)
        return dataframe.to_csv(index=False, lineterminator="\n")

    def to_terminal(self, table: dict) -> str:
        """Render a table dictionary as aligned plain text for terminal output.

        EXAMPLES::

            sage: from claasp.catalog import Catalog
            sage: table = {'name': 'demo', 'columns': ['k', 'v'], 'rows': [{'k': 'alpha', 'v': 1}]}
            sage: text = Catalog().to_terminal(table)
            sage: text.splitlines()[0]
            'k     | v'
            sage: text.splitlines()[2]
            'alpha | 1'
        """
        columns = table["columns"]
        rows = table["rows"]

        if not columns:
            return ""

        widths = []
        for column in columns:
            value_widths = [len(str(row.get(column, ""))) for row in rows]
            widths.append(max([len(column)] + value_widths))

        header = " | ".join(column.ljust(widths[i]) for i, column in enumerate(columns))
        separator = "-+-".join("-" * widths[i] for i in range(len(columns)))
        body = [
            " | ".join(str(row.get(column, "")).ljust(widths[i]) for i, column in enumerate(columns))
            for row in rows
        ]
        return "\n".join([header, separator] + body)

    def render(self, table: dict, fmt: str = "markdown") -> str:
        """Render a table to ``json``, ``markdown``, ``csv``, or ``terminal`` string.

        EXAMPLES::

            sage: from claasp.catalog import Catalog
            sage: table = {'name': 'demo', 'columns': ['k', 'v'], 'rows': [{'k': 'alpha', 'v': 1}]}
            sage: catalog = Catalog()
            sage: catalog.render(table, fmt='markdown').startswith('| k | v |')
            True
            sage: catalog.render(table, fmt='json').startswith('{')
            True
            sage: catalog.render(table, fmt='csv').splitlines()[0]
            'k,v'
            sage: catalog.render(table, fmt='terminal').splitlines()[0]
            'k     | v'
        """
        normalized = fmt.strip().lower()
        if normalized == "json":
            return self.to_json(table)
        if normalized == "markdown":
            return self.to_markdown(table)
        if normalized == "csv":
            return self.to_csv(table)
        if normalized == "terminal":
            return self.to_terminal(table)

        raise ValueError("Unknown output format. Use one of: json, markdown, csv, terminal")

    def write(self, table: dict, file_path: str | Path, fmt: str = "json") -> Path:
        """Write table data to file in ``json``, ``markdown``, ``csv``, or ``terminal`` format.

        EXAMPLES::

            sage: from claasp.catalog import Catalog
            sage: import tempfile
            sage: table = {'name': 'demo', 'columns': ['k', 'v'], 'rows': [{'k': 'alpha', 'v': 1}]}
            sage: with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as handle:
            ....:     out_path = handle.name
            sage: written = Catalog().write(table, out_path, fmt='csv')
            sage: open(written, 'r', encoding='utf-8').read().splitlines()[0]
            'k,v'
        """
        path = Path(file_path)
        path.write_text(self.render(table, fmt=fmt), encoding="utf-8")

        return path

    def show_ciphers(
        self,
        filters: str | list[str] | tuple[str, ...] | None = None,
        has_components: str | list[str] | tuple[str, ...] | None = None,
        columns: str | list[str] | tuple[str, ...] | None = None,
        exclude_columns: str | list[str] | tuple[str, ...] | None = None,
        include_metadata: bool = False,
        qualified: bool = False,
        fmt: str = "terminal",
    ) -> str:
        """Build and render ciphers in one command for terminal/file output.

        INPUT:

        - ``filters`` -- **string/list/tuple** (default: ``None``); forwarded to :meth:`ciphers`.
        - ``has_components`` -- **string/list/tuple** (default: ``None``); forwarded to :meth:`ciphers`.
        - ``columns`` -- **string/list/tuple** (default: ``None``); keep only selected columns.
        - ``exclude_columns`` -- **string/list/tuple** (default: ``None``); drop selected columns.
        - ``include_metadata`` -- **boolean** (default: ``False``); forwarded to :meth:`ciphers`.
        - ``qualified`` -- **boolean** (default: ``False``); forwarded to :meth:`ciphers`.
        - ``fmt`` -- **string** (default: ``"terminal"``); output format for :meth:`render`.

        EXAMPLES::

            sage: from claasp.catalog import Catalog
            sage: Catalog().show_ciphers(filters='toys', has_components=['sbox'], columns=['class_name', 'tags'], fmt='json')
            {
                "name": "ciphers",
                "columns": [
                    "class_name",
                    "tags"
                ],
                "rows": [
                    {
                        "class_name": "FancyBlockCipher",
                        "tags": [
                            "sbox_based",
                            "toys"
                        ]
                    },
            ...

            sage: Catalog().show_ciphers(filters='toys', include_metadata=True, exclude_columns=['module_name', 'category', 'components', 'tags'], fmt='csv')
            class_name,family_name,cipher_type,inputs,inputs_bit_size,output_bit_size,number_of_rounds,id,metadata_error
            FancyBlockCipher,...
            ...
        """
        table = self.ciphers(
            filters=filters,
            has_components=has_components,
            include_metadata=include_metadata,
            qualified=qualified,
        )
        table = _project_table_columns(table, columns=columns, exclude_columns=exclude_columns)
        return RenderedText(
            self.render(table, fmt=fmt)
        )

    def show_components(
        self,
        include_abstract: bool = False,
        include_io_components: bool = False,
        qualified: bool = False,
        columns: str | list[str] | tuple[str, ...] | None = None,
        exclude_columns: str | list[str] | tuple[str, ...] | None = None,
        fmt: str = "terminal",
    ) -> str:
        """Build and render components in one command for terminal/file output.

        INPUT:

        - ``include_abstract`` -- **boolean** (default: ``False``); forwarded to :meth:`components`.
        - ``include_io_components`` -- **boolean** (default: ``False``); forwarded to :meth:`components`.
        - ``qualified`` -- **boolean** (default: ``False``); forwarded to :meth:`components`.
        - ``columns`` -- **string/list/tuple** (default: ``None``); keep only selected columns.
        - ``exclude_columns`` -- **string/list/tuple** (default: ``None``); drop selected columns.
        - ``fmt`` -- **string** (default: ``"terminal"``); output format for :meth:`render`.

        EXAMPLES::

            sage: from claasp.catalog import Catalog
            sage: Catalog().show_components(qualified=True, columns=['class_name', 'qualified_name'], fmt='markdown')
            | class_name | qualified_name |
            | --- | --- |
            | And | claasp.components.and_component.And |
            ...
        """
        table = self.components(
            include_abstract=include_abstract,
            include_io_components=include_io_components,
            qualified=qualified,
        )
        table = _project_table_columns(table, columns=columns, exclude_columns=exclude_columns)
        return RenderedText(
            self.render(table, fmt=fmt)
        )

    def show_solvers(
        self,
        include_internal: bool = True,
        include_external: bool = True,
        columns: str | list[str] | tuple[str, ...] | None = None,
        exclude_columns: str | list[str] | tuple[str, ...] | None = None,
        fmt: str = "terminal",
    ) -> str:
        """Build and render solvers in one command for terminal/file output.

        INPUT:

        - ``include_internal`` -- **boolean** (default: ``True``); forwarded to :meth:`solvers`.
        - ``include_external`` -- **boolean** (default: ``True``); forwarded to :meth:`solvers`.
        - ``columns`` -- **string/list/tuple** (default: ``None``); keep only selected columns.
        - ``exclude_columns`` -- **string/list/tuple** (default: ``None``); drop selected columns.
        - ``fmt`` -- **string** (default: ``"terminal"``); output format for :meth:`render`.

        EXAMPLES::

            sage: from claasp.catalog import Catalog
            sage: Catalog().show_solvers(include_external=False, columns=['solver_name', 'family', 'source'], fmt='terminal')
            solver_name   | family | source  
            --------------+--------+---------
            ...           | ...    | ...
            ...
        """
        table = self.solvers(
            include_internal=include_internal,
            include_external=include_external,
            grouped=False,
        )
        table = _project_table_columns(table, columns=columns, exclude_columns=exclude_columns)
        return RenderedText(
            self.render(table, fmt=fmt)
        )

    def show_implemented_methods_per_component(
        self,
        include_abstract: bool = False,
        include_io_components: bool = False,
        columns: str | list[str] | tuple[str, ...] | None = None,
        exclude_columns: str | list[str] | tuple[str, ...] | None = None,
        fmt: str = "terminal",
    ) -> str:
        """Build and render methods-per-component coverage in one command.

        INPUT:

        - ``include_abstract`` -- **boolean** (default: ``False``); forwarded to
            :meth:`implemented_methods_per_component`.
        - ``include_io_components`` -- **boolean** (default: ``False``); forwarded to
            :meth:`implemented_methods_per_component`.
        - ``columns`` -- **string/list/tuple** (default: ``None``); keep only selected columns.
        - ``exclude_columns`` -- **string/list/tuple** (default: ``None``); drop selected columns.
        - ``fmt`` -- **string** (default: ``"terminal"``); output format for :meth:`render`.

        EXAMPLES::

            sage: from claasp.catalog import Catalog
            sage: Catalog().show_implemented_methods_per_component(include_abstract=True, columns=['method', 'Sbox'], fmt='csv')
            method,Sbox
            ...,...
            ...
        """
        table = self.implemented_methods_per_component(
            include_abstract=include_abstract,
            include_io_components=include_io_components,
        )
        table = _project_table_columns(table, columns=columns, exclude_columns=exclude_columns)
        return RenderedText(
            self.render(table, fmt=fmt)
        )
