"""CLAASP catalog and discovery helpers.

The Catalog class provides a compact API to discover ciphers, components,
solvers, and component-method coverage.

EXAMPLES::

    sage: from claasp.catalog import Catalog
    sage: catalog = Catalog()
    sage: ciphers = catalog.ciphers()
    sage: ciphers['name']
    'ciphers'
    sage: len(ciphers['rows']) > 0
    True

    sage: components = catalog.components()
    sage: all(r['class_name'] not in ('Modular', 'MultiInputNonlinearLogicalOperator') for r in components['rows'])
    True

    sage: solvers = catalog.solvers()
    sage: all('available' in row for row in solvers['rows'])
    True
"""

from __future__ import annotations

import ast
import csv
import importlib
import io
import json
import shutil
from dataclasses import dataclass
from pathlib import Path


ABSTRACT_COMPONENT_CLASS_NAMES = frozenset({"MultiInputNonlinearLogicalOperator", "Modular"})
IO_COMPONENT_CLASS_NAMES = frozenset({"CipherOutput", "IntermediateOutput"})
SUPPORTED_CIPHER_FILTERS = frozenset(
    {
        "block_ciphers",
        "permutations",
        "stream_ciphers",
        "hash_function",
        "tweakable_block_cipher",
        "spn",
        "arx",
        "andrx",
    }
)


@dataclass(frozen=True)
class ClassInfo:
    """Class metadata discovered from CLAASP source files."""

    name: str
    qualified_name: str
    module_name: str
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


def _normalize_filters(filters: str | list[str] | tuple[str, ...] | None) -> set[str]:
    if filters is None:
        return set()

    if isinstance(filters, str):
        items = [filters]
    else:
        items = list(filters)

    normalized = set()
    for item in items:
        token = str(item).strip().lower()
        if token == "hash_functions":
            token = "hash_function"
        normalized.add(token)

    unknown = normalized.difference(SUPPORTED_CIPHER_FILTERS)
    if unknown:
        allowed = ", ".join(sorted(SUPPORTED_CIPHER_FILTERS))
        raise ValueError(f"Unknown cipher filters: {sorted(unknown)}. Allowed values: {allowed}")

    return normalized


def _infer_cipher_paradigm(source_text: str) -> str:
    text = source_text.lower()
    has_and = "add_and_component" in text
    has_modadd = "add_modadd_component" in text
    has_rotate = "add_rotate_component" in text or "add_variable_rotate_component" in text
    has_xor = "add_xor_component" in text
    has_sbox = "add_sbox_component" in text

    if has_and and has_rotate and has_xor:
        return "andrx"
    if has_modadd and has_rotate and has_xor:
        return "arx"
    if has_sbox:
        return "spn"

    return "other"


def _cipher_tags(category: str, source_text: str, class_name: str) -> set[str]:
    tags = {category}
    if category == "hash_functions":
        tags.add("hash_function")

    paradigm = _infer_cipher_paradigm(source_text)
    if paradigm in {"spn", "arx", "andrx"}:
        tags.add(paradigm)

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
    - :meth:`to_markdown`
    - :meth:`to_csv`
    - :meth:`write`

    EXAMPLES::

        sage: from claasp.catalog import Catalog
        sage: catalog = Catalog()
        sage: len(catalog.ciphers()['rows']) > 0
        True
        sage: len(catalog.components()['rows']) > 0
        True
        sage: len(catalog.solvers()['rows']) > 0
        True
    """

    def __init__(self, package_root=None):
        self._package_root = Path(package_root).resolve() if package_root is not None else _package_root()

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
            sage: rows = Catalog().components()['rows']
            sage: all(r['class_name'] not in ('Modular', 'MultiInputNonlinearLogicalOperator') for r in rows)
            True
        """
        components_dir = self._package_root / "components"
        rows = []

        for file_path in sorted(components_dir.glob("*.py")):
            if file_path.name == "__init__.py":
                continue

            module_name = _module_path_from_file(file_path, self._package_root)
            for class_node in _iter_classes_in_tree(file_path):
                class_name = class_node.name
                if not include_abstract and class_name in ABSTRACT_COMPONENT_CLASS_NAMES:
                    continue
                if not include_io_components and class_name in IO_COMPONENT_CLASS_NAMES:
                    continue

                row = {
                    "class_name": class_name,
                    "module_name": module_name,
                    "qualified_name": f"{module_name}.{class_name}",
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
        include_metadata: bool = False,
        qualified: bool = False,
    ) -> dict:
        """List CLAASP ciphers/permutations as a table.

        INPUT:

        - ``filters`` -- **string/list/tuple** (default: ``None``); category/paradigm filters.
          Allowed values are: ``block_ciphers``, ``permutations``, ``stream_ciphers``,
          ``hash_function``, ``tweakable_block_cipher``, ``spn``, ``arx``, ``andrx``.
          Multiple filters are combined with logical AND.
        - ``include_metadata`` -- **boolean** (default: ``False``); include cipher runtime metadata.
        - ``qualified`` -- **boolean** (default: ``False``); include full module path.

        EXAMPLES::

            sage: from claasp.catalog import Catalog
            sage: block_spn = Catalog().ciphers(filters=['block_ciphers', 'spn'])
            sage: all('block_ciphers' in row['tags'] and 'spn' in row['tags'] for row in block_spn['rows'])
            True
        """
        normalized_filters = _normalize_filters(filters)
        ciphers_dir = self._package_root / "ciphers"
        rows = []

        for file_path in sorted(ciphers_dir.rglob("*.py")):
            if file_path.name == "__init__.py":
                continue

            relative_parts = file_path.relative_to(ciphers_dir).parts
            category = relative_parts[0] if len(relative_parts) > 1 else "other"
            module_name = _module_path_from_file(file_path, self._package_root)
            source_text = file_path.read_text(encoding="utf-8")

            for class_node in _iter_classes_in_tree(file_path):
                class_name = class_node.name
                if not (class_name.endswith("Cipher") or class_name.endswith("Permutation")):
                    continue

                tags = _cipher_tags(category, source_text, class_name)
                if normalized_filters and not normalized_filters.issubset(tags):
                    continue

                paradigm = _infer_cipher_paradigm(source_text)
                row = {
                    "class_name": class_name,
                    "module_name": module_name,
                    "qualified_name": f"{module_name}.{class_name}",
                    "category": category,
                    "paradigm": paradigm,
                    "tags": sorted(tags),
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

        columns = ["class_name", "module_name", "qualified_name", "category", "paradigm", "tags"]
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
            sage: solvers = Catalog().solvers()
            sage: all('available' in row for row in solvers['rows'])
            True
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
            sage: table['columns'][0]
            'method'
            sage: len(table['rows']) > 0
            True
        """
        components_dir = self._package_root / "components"
        component_infos: list[ClassInfo] = []

        for file_path in sorted(components_dir.glob("*.py")):
            if file_path.name == "__init__.py":
                continue

            module_name = _module_path_from_file(file_path, self._package_root)
            for class_node in _iter_classes_in_tree(file_path):
                class_name = class_node.name
                if not include_abstract and class_name in ABSTRACT_COMPONENT_CLASS_NAMES:
                    continue
                if not include_io_components and class_name in IO_COMPONENT_CLASS_NAMES:
                    continue

                component_infos.append(
                    ClassInfo(
                        name=class_name,
                        qualified_name=f"{module_name}.{class_name}",
                        module_name=module_name,
                        source_file=file_path,
                        methods=frozenset(_public_methods_from_class(class_node)),
                    )
                )

        component_infos.sort(key=lambda info: info.name)
        base_methods = _base_component_methods(self._package_root)
        all_methods = sorted(set().union(*(set(info.methods) for info in component_infos), base_methods))

        columns = ["method"] + [info.name for info in component_infos]
        rows = []
        for method in all_methods:
            row = {"method": method}
            for info in component_infos:
                if method in info.methods:
                    row[info.name] = "X"
                elif method in base_methods:
                    row[info.name] = "B"
                else:
                    row[info.name] = ""
            rows.append(row)

        return _table("implemented_methods_per_component", columns, rows)

    def to_json(self, table: dict, indent: int = 2) -> str:
        """Serialize a table dictionary to JSON text.

        EXAMPLES::

            sage: from claasp.catalog import Catalog
            sage: table = Catalog().components()
            sage: text = Catalog().to_json(table)
            sage: text.startswith('{')
            True
        """
        return json.dumps(table, indent=indent, default=str)

    def to_markdown(self, table: dict) -> str:
        """Render a table dictionary as Markdown."""
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
        """Render a table dictionary as CSV text."""
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=table["columns"], extrasaction="ignore")
        writer.writeheader()
        for row in table["rows"]:
            writer.writerow({column: row.get(column, "") for column in table["columns"]})

        return buffer.getvalue()

    def render(self, table: dict, fmt: str = "markdown") -> str:
        """Render a table to ``json``, ``markdown``, or ``csv`` string."""
        normalized = fmt.strip().lower()
        if normalized == "json":
            return self.to_json(table)
        if normalized == "markdown":
            return self.to_markdown(table)
        if normalized == "csv":
            return self.to_csv(table)

        raise ValueError("Unknown output format. Use one of: json, markdown, csv")

    def write(self, table: dict, file_path: str | Path, fmt: str = "json") -> Path:
        """Write table data to file in ``json``, ``markdown``, or ``csv`` format."""
        path = Path(file_path)
        path.write_text(self.render(table, fmt=fmt), encoding="utf-8")

        return path
