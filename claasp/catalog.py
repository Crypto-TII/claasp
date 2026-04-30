"""CLAASP catalog and discovery helpers.

The Catalog class provides a compact API to discover ciphers, components,
solvers, and component-method coverage.

EXAMPLES::

    sage: from claasp.catalog import Catalog
    sage: catalog = Catalog()

    sage: # List block ciphers; rows are sorted alphabetically.
    sage: block_ciphers = catalog.ciphers(filters='block_ciphers')
    sage: block_ciphers['rows'][0]['class_name']
    'AESBlockCipher'

    sage: # Print the table as Markdown for quick terminal inspection.
    sage: print('\n'.join(catalog.render(block_ciphers, fmt='markdown').splitlines()[:2]))
    | class_name | module_name | category | paradigm | components | tags |
    | --- | --- | --- | --- | --- | --- |

    sage: # List components; abstract helpers are excluded by default.
    sage: catalog.components()['rows'][0]['class_name']
    'And'

    sage: # Check which solver families are catalogued.
    sage: sorted(catalog.solvers(grouped=True))
    ['cp', 'milp', 'sat', 'smt']
"""

from __future__ import annotations

import ast
import importlib
import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path


ABSTRACT_COMPONENT_CLASS_NAMES = frozenset({"MultiInputNonlinearLogicalOperator", "Modular"})
IO_COMPONENT_CLASS_NAMES = frozenset({"CipherOutput", "IntermediateOutput"})
SPECIAL_CIPHER_FILTERS = frozenset({"tweakable_block_cipher", "sbox_based", "arx", "andrx"})
FILTER_ALIASES = {
    "block_cipher": "block_ciphers",
    "block_ciphers": "block_ciphers",
    "hash_function": "hash_functions",
    "hash_functions": "hash_functions",
    "macs": "mac",
    "mac": "mac",
    "permutation": "permutations",
    "permutations": "permutations",
    "single_component_cipher": "single_component_ciphers",
    "single_component_ciphers": "single_component_ciphers",
    "spn": "sbox_based",
    "sbox-based": "sbox_based",
    "sbox_based": "sbox_based",
    "stream_cipher": "stream_ciphers",
    "stream_ciphers": "stream_ciphers",
    "toy": "toys",
    "toys": "toys",
    "tweakable_block_ciphers": "tweakable_block_cipher",
    "tweakable_block_cipher": "tweakable_block_cipher",
}
IGNORED_CIPHER_COMPONENTS = frozenset(
    {"cipher_output", "intermediate_output", "round_key_output", "round_output"}
)


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
    paradigm: str
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


def _cipher_components(source_text: str) -> set[str]:
    operations = set(re.findall(r"add_([a-z0-9_]+)_component", source_text.lower()))
    operations.difference_update(IGNORED_CIPHER_COMPONENTS)

    if "variable_rotate" in operations:
        operations.remove("variable_rotate")
        operations.add("rotate")

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

    module_init = package_root.joinpath(*module_parts, "__init__.py")
    if module_init.exists():
        return module_init

    return None


def _imported_cipher_modules(tree: ast.AST, current_module: str) -> set[str]:
    modules = set()
    current_parts = current_module.split(".")

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported = alias.name
                if imported.startswith("claasp.ciphers."):
                    modules.add(imported)

        if isinstance(node, ast.ImportFrom):
            if node.level > 0:
                if len(current_parts) <= node.level:
                    continue
                base_parts = current_parts[:-node.level]
                if node.module:
                    module_parts = node.module.split(".")
                    imported = ".".join(base_parts + module_parts)
                else:
                    imported = ".".join(base_parts)
            else:
                imported = node.module or ""

            if imported.startswith("claasp.ciphers."):
                modules.add(imported)

    return modules


def _collect_components_from_cipher_module(
    module_name: str,
    package_root: Path,
    cache: dict[str, set[str]],
    visiting: set[str],
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
        components = _cipher_components(source_text)
        tree = ast.parse(source_text, filename=str(source_file))
        for imported_module in _imported_cipher_modules(tree, module_name):
            components.update(
                _collect_components_from_cipher_module(imported_module, package_root, cache, visiting)
            )

        cache[module_name] = components
        return set(components)
    finally:
        visiting.remove(module_name)


def _infer_cipher_paradigm(operations: set[str]) -> str:
    if {"and", "rotate", "xor"}.issubset(operations) and len(operations) == 3:
        return "andrx"
    if {"modadd", "rotate", "xor"}.issubset(operations) and len(operations) == 3:
        return "arx"
    if "sbox" in operations:
        return "sbox-based"

    return "other"


def _cipher_tags(category: str, source_text: str, class_name: str, paradigm: str) -> set[str]:
    tags = {category}
    if category == "hash_functions":
        tags.add("hash_function")

    if paradigm in {"sbox-based", "arx", "andrx"}:
        tags.add(paradigm.replace("-", "_"))

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


class Catalog:
    """Facade class for CLAASP discovery and catalog helpers.

    Compact API:

    - :meth:`ciphers`
    - :meth:`components`
    - :meth:`solvers`
    - :meth:`implemented_methods_per_component`

    Rendering/export API:

    - :meth:`to_json`
    - :meth:`to_dataframe`
    - :meth:`to_markdown`
    - :meth:`to_terminal`
    - :meth:`to_csv`
    - :meth:`write`

    One-command terminal helpers:

    - :meth:`show_ciphers`
    - :meth:`show_components`
    - :meth:`show_solvers`
    - :meth:`show_implemented_methods_per_component`

    EXAMPLES::

        sage: from claasp.catalog import Catalog
        sage: catalog = Catalog()

        sage: # Filter ciphers by category and paradigm (AND logic).
        sage: sbox_blocks = catalog.ciphers(filters=['block_ciphers', 'sbox_based'])
        sage: sbox_blocks['rows'][0]['class_name']
        'AESBlockCipher'
        sage: sbox_blocks['rows'][0]['tags']
        ['block_ciphers', 'sbox_based']

        sage: # Inspect a component's full import path.
        sage: catalog.components(qualified=True)['rows'][0]['qualified_name']
        'claasp.components.and_component.And'

        sage: # See which solver families are available.
        sage: sorted(catalog.solvers(grouped=True))
        ['cp', 'milp', 'sat', 'smt']

        sage: # Display results as a Markdown table in the terminal.
        sage: print('\n'.join(catalog.render(sbox_blocks, fmt='markdown').splitlines()[:2]))
        | class_name | module_name | category | paradigm | components | tags |
        | --- | --- | --- | --- | --- | --- |

        sage: # Export the same data as CSV.
        sage: catalog.render(sbox_blocks, fmt='csv').splitlines()[0]
        'class_name,module_name,category,paradigm,components,tags'
    """

    def __init__(self, package_root=None):
        self._package_root = Path(package_root).resolve() if package_root is not None else _package_root()
        self._cipher_categories = _cipher_categories(self._package_root)
        self._supported_cipher_filters = _supported_cipher_filters(self._cipher_categories)
        self._component_infos = self._discover_components()
        self._cipher_infos = self._discover_ciphers()
        self._base_methods = _base_component_methods(self._package_root)

    def _discover_components(self) -> list[ClassInfo]:
        components_dir = self._package_root / "components"
        infos: list[ClassInfo] = []

        for file_path in sorted(components_dir.glob("*.py")):
            if file_path.name == "__init__.py":
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
            if file_path.name == "__init__.py" or file_path.name.startswith("_"):
                continue

            relative_parts = file_path.relative_to(ciphers_dir).parts
            category = relative_parts[0] if len(relative_parts) > 1 else "other"
            module_name = _module_path_from_file(file_path, self._package_root)
            source_text = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source_text, filename=str(file_path))
            class_nodes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
            static_components = _cipher_components(source_text)
            imported_components = set()
            for imported_module in _imported_cipher_modules(tree, module_name):
                imported_components.update(
                    _collect_components_from_cipher_module(
                        imported_module,
                        self._package_root,
                        import_component_cache,
                        set(),
                    )
                )

            discovered_components = static_components.union(imported_components)

            for class_node in class_nodes:
                if not _is_cipher_class(class_node):
                    continue

                class_name = class_node.name
                qualified_name = f"{module_name}.{class_name}"
                components = set(discovered_components)
                paradigm = _infer_cipher_paradigm(components)

                tags = set(_cipher_tags(category, source_text, class_name, paradigm))
                infos.append(
                    CipherInfo(
                        name=class_name,
                        qualified_name=qualified_name,
                        module_name=module_name,
                        category=category,
                        paradigm=paradigm,
                        components=tuple(sorted(components)),
                        tags=frozenset(tags),
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
          ``tweakable_block_cipher``, ``sbox_based``, ``arx``, and ``andrx``. Multiple filters are
          combined with logical AND.
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
            if normalized_filters and not normalized_filters.issubset(info.tags):
                continue
            if required_components and not required_components.issubset(set(info.components)):
                continue

            row = {
                "class_name": info.name,
                "module_name": info.module_name,
                "qualified_name": info.qualified_name,
                "category": info.category,
                "paradigm": info.paradigm,
                "components": list(info.components),
                "tags": sorted(info.tags),
            }

            if include_metadata:
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
                    instance = _load_cipher_instance(row["qualified_name"])
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

                row.update(metadata)

            if not qualified:
                row.pop("qualified_name")

            rows.append(row)

        rows.sort(key=lambda r: r["class_name"])

        columns = ["class_name", "module_name", "qualified_name", "category", "paradigm", "components", "tags"]
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

        EXAMPLES::

            sage: from claasp.catalog import Catalog
            sage: text = Catalog().show_ciphers(filters='block_ciphers', fmt='csv')
            sage: text.splitlines()[0]
            'class_name,module_name,category,paradigm,components,tags'
            sage: text = Catalog().show_ciphers(filters='block_ciphers', columns=['class_name', 'paradigm'], fmt='csv')
            sage: text.splitlines()[0]
            'class_name,paradigm'
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
        """Build and render components in one command for terminal/file output."""
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
        """Build and render solvers in one command for terminal/file output."""
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
        """Build and render methods-per-component coverage in one command."""
        table = self.implemented_methods_per_component(
            include_abstract=include_abstract,
            include_io_components=include_io_components,
        )
        table = _project_table_columns(table, columns=columns, exclude_columns=exclude_columns)
        return RenderedText(
            self.render(table, fmt=fmt)
        )
