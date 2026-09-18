"""Metadata-backed discovery without implementation imports or source scanning."""

from __future__ import annotations

import json
import importlib.util
from importlib.resources import files
import shutil
import subprocess

from claasp_next.catalogue.records import (
    AnalysisRecord, ComponentRecord, DriverAvailabilityRecord, DriverRecord, InputRecord,
    ParameterSetRecord, PrimitiveRecord, RealizationRecord, RepresentationRecord,
)


FILTER_ALIASES = {
    "block_cipher": "block_ciphers",
    "hash_function": "functions",
    "hash_functions": "functions",
    "mac": "block_functions",
    "macs": "block_functions",
    "permutation": "permutations",
    "stream_cipher": "block_functions",
    "stream_ciphers": "block_functions",
    "toy": "toy_primitives",
    "toys": "toy_primitives",
    "tweakable_block_cipher": "tweakable_block_cipher",
    "sbox": "sbox_based",
    "sbox-based": "sbox_based",
    "fsr": "fsr_based",
    "fsr-based": "fsr_based",
    "pure-arx": "purearx",
    "pure_arx": "purearx",
    "pure-andrx": "pureandrx",
    "pure_andrx": "pureandrx",
}

COMPONENT_ALIASES = {
    "and": frozenset(("BitwiseAnd",)),
    "constant": frozenset(("Constant",)),
    "fsr": frozenset(("FeedbackRegister",)),
    "modadd": frozenset(("ModularAdd",)),
    "modmul": frozenset(("ModularMultiply",)),
    "modsub": frozenset(("ModularSubtract",)),
    "not": frozenset(("BitwiseNot",)),
    "or": frozenset(("BitwiseOr",)),
    "rotate": frozenset(("Rotate", "VariableRotate")),
    "sbox": frozenset(("BitVectorSBox", "SBox")),
    "shift": frozenset(("Shift", "VariableShift")),
    "xor": frozenset(("Xor",)),
}


def _tokens(value) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(value)


def _normalized_filter(value: str) -> str:
    token = value.strip().lower()
    return FILTER_ALIASES.get(token, token)


def _component_matches(components: frozenset[str], requested: str) -> bool:
    token = requested.strip()
    aliases = COMPONENT_ALIASES.get(token.lower().replace("-", "_"))
    if aliases is not None:
        return bool(components & aliases)
    compact = token.replace("_", "").replace("-", "").lower()
    return any(name.lower() == token.lower() or name.lower() == compact for name in components)


def _load_payload() -> dict:
    resource = files("claasp_next.catalogue").joinpath("data/catalogue.json")
    return json.loads(resource.read_text(encoding="utf-8"))


def _primitive_record(item: dict) -> PrimitiveRecord:
    name = item["name"]
    realizations = tuple(
        RealizationRecord(
            name, realization["name"], frozenset(realization["capabilities"]),
            frozenset(realization["structure"]), realization["maturity"],
            tuple(realization["provenance"]), realization["priority"],
        )
        for realization in item["realizations"]
    )
    parameter_sets = tuple(
        ParameterSetRecord.from_mapping(name, parameter_set["name"], parameter_set["values"])
        for parameter_set in item["parameter_sets"]
    )
    return PrimitiveRecord(
        name=name,
        official_name=item["official_name"],
        module=item["module"],
        category=item["category"],
        family=item["family"],
        kind=item["kind"],
        inputs=tuple(InputRecord(**input_) for input_ in item["inputs"]),
        classified_input_roles=tuple(item["input_roles"]),
        bijectivity_obligation=item["bijectivity_obligation"],
        components=frozenset(item["components"]),
        domains=frozenset(item["domains"]),
        tags=frozenset(item["tags"]),
        authenticity=item["authenticity"],
        labels=frozenset(item["labels"]),
        legacy_source=item["legacy_source"],
        classification_basis=item["classification_basis"],
        fixed_evidence=tuple(item["fixed_evidence"]),
        parameter_sets=parameter_sets,
        realizations=realizations,
    )


class Catalogue:
    """Query committed v5 metadata and return immutable records.

    Loading the catalogue reads one packaged JSON resource; it does not import
    primitive implementations or optional solver/framework dependencies.

    EXAMPLES::

        >>> from claasp_next.catalogue import Catalogue
        >>> catalogue = Catalogue()

        >>> # Primitive discovery returns immutable typed records.
        >>> aes = catalogue.primitive("AES")
        >>> (aes.name, aes.category, aes.kind)
        ('AES', 'block_ciphers', 'block_cipher')
        >>> len(catalogue.primitives())
        142

        >>> # Category, design, and component filters compose.
        >>> [item.name for item in catalogue.primitives(
        ...     category="permutations", filters="pure-arx", components="xor")]
        ['ChaCha', 'ChaskeyPi', 'Forro', 'Salsa', 'Speckey']

        >>> # Realizations, parameter sets, and drivers remain distinct records.
        >>> [item.name for item in catalogue.realizations(
        ...     primitive="AES", capabilities="algebraic_semantics")]
        ['algebraic']
        >>> catalogue.parameter_sets(primitive="AES")[0].values["key_bit_size"]
        128
        >>> [item.name for item in catalogue.drivers(kind="execution_engine")]
        ['python_scalar', 'python_batch', 'python_transposed_batch']

        >>> # Capability edges are queryable in both directions.
        >>> [item.name for item in catalogue.representations(component="BitVectorSBox")]
        ['boolean_cnf', 'boolean_smt', 'concrete_execution', 'primitive_diagram', 'sbox_transition_table']
        >>> [item.name for item in catalogue.drivers(representation="boolean_cnf")]
        ['minizinc', 'minisat', 'z3', 'glpk']
    """

    def __init__(self) -> None:
        payload = _load_payload()
        self._primitives = tuple(_primitive_record(item) for item in payload["primitives"])
        self._components = tuple(ComponentRecord(**item) for item in payload["components"])
        self._representations = tuple(
            RepresentationRecord(
                name=item["name"], kind=item["kind"], implementation=item["implementation"],
                components=frozenset(item["components"]), domains=frozenset(item["domains"]),
                drivers=frozenset(item["drivers"]), scope=item["scope"],
            )
            for item in payload["representations"]
        )
        self._analyses = tuple(
            AnalysisRecord(
                name=item["name"], entry_point=item["entry_point"], kind=item["kind"],
                evidence=item["evidence"], representations=frozenset(item["representations"]),
                drivers=frozenset(item["drivers"]),
                required_components=frozenset(item["required_components"]),
                primitives=frozenset(item["primitives"]), restriction=item["restriction"],
            )
            for item in payload["analyses"]
        )
        self._drivers = tuple(
            DriverRecord(
                name=item["name"], kind=item["kind"], availability=item["availability"],
                target=item["target"], implementation=item["implementation"],
                representations=frozenset(item["representations"]),
            )
            for item in payload["drivers"]
        )

    def primitives(
        self, *, category: str | None = None, filters=None, components=None,
        authenticity: str | None = None,
    ) -> tuple[PrimitiveRecord, ...]:
        """Return primitives matching category, design, and component filters."""

        requested = tuple(_normalized_filter(item) for item in _tokens(filters))
        if category is not None:
            requested += (_normalized_filter(category),)
        supported = frozenset(tag for record in self._primitives for tag in record.tags) | frozenset({
            "arx", "purearx", "andrx", "pureandrx", "sbox_based", "fsr_based",
        })
        unknown = frozenset(requested) - supported
        if unknown:
            raise ValueError(f"unknown primitive filters: {tuple(sorted(unknown))}")
        required_components = _tokens(components)
        rows = []
        for record in self._primitives:
            if any(token not in record.tags for token in requested):
                continue
            if any(not _component_matches(record.components, item) for item in required_components):
                continue
            if authenticity is not None and record.authenticity != authenticity:
                continue
            rows.append(record)
        return tuple(rows)

    def primitive(self, name: str) -> PrimitiveRecord:
        """Return one public primitive by official class name."""

        matches = tuple(record for record in self._primitives if record.name == name)
        if len(matches) != 1:
            raise KeyError(f"unknown primitive {name!r}")
        return matches[0]

    def components(self, *, names=None, representation: str | None = None) -> tuple[ComponentRecord, ...]:
        """Return components, optionally restricted by name or representation."""

        requested = frozenset(_tokens(names))
        supported = (
            None if representation is None else self.representation(representation).components
        )
        return tuple(
            record for record in self._components
            if (not requested or record.name in requested)
            and (supported is None or record.name in supported)
        )

    def representations(
        self, *, component: str | None = None, driver: str | None = None,
        kind: str | None = None, domain: str | None = None,
    ) -> tuple[RepresentationRecord, ...]:
        """Return representations matching component, driver, kind, and domain.

        EXAMPLES::

            >>> from claasp_next.catalogue import catalogue
            >>> [item.name for item in catalogue.representations(component="Power")]
            ['concrete_execution', 'msolve_input', 'prime_field_polynomial', 'primitive_diagram', 'singular_program']
            >>> [item.name for item in catalogue.components(representation="boolean_cnf")][:3]
            ['Add', 'BitVectorSBox', 'BitwiseAnd']
        """

        if component is not None and not self.components(names=component):
            raise KeyError(f"unknown component {component!r}")
        if driver is not None:
            self.driver(driver)
        return tuple(
            record for record in self._representations
            if (component is None or component in record.components)
            and (driver is None or driver in record.drivers)
            and (kind is None or kind == record.kind)
            and (domain is None or domain in record.domains)
        )

    def representation(self, name: str) -> RepresentationRecord:
        """Return one declared representation by stable name.

        EXAMPLES::

            >>> from claasp_next.catalogue import catalogue
            >>> sorted(catalogue.representation("boolean_cnf").domains)
            ['Bit', 'Word']
        """

        matches = tuple(record for record in self._representations if record.name == name)
        if len(matches) != 1:
            raise KeyError(f"unknown representation {name!r}")
        return matches[0]

    def analyses(
        self, *, primitive: str | None = None, representation: str | None = None,
        driver: str | None = None, kind: str | None = None,
    ) -> tuple[AnalysisRecord, ...]:
        """Return analyses whose declared requirements match a primitive.

        Parameter-restricted analyses remain visible, with the restriction
        carried explicitly by their immutable record.

        EXAMPLES::

            >>> from claasp_next.catalogue import catalogue
            >>> names = {item.name for item in catalogue.analyses(primitive="Speck")}
            >>> "enumerate_xor_linear_trails" in names
            True
            >>> "solve" in {item.name for item in catalogue.analyses(primitive="AES")}
            False
        """

        primitive_record = None if primitive is None else self.primitive(primitive)
        if representation is not None:
            self.representation(representation)
        if driver is not None:
            self.driver(driver)
        rows = []
        for record in self._analyses:
            if representation is not None and representation not in record.representations:
                continue
            if driver is not None and driver not in record.drivers:
                continue
            if kind is not None and kind != record.kind:
                continue
            if primitive_record is not None:
                if record.primitives and primitive_record.name not in record.primitives:
                    continue
                if not record.required_components <= primitive_record.components:
                    continue
                if record.representations and not any(
                    (
                        candidate.scope == "component"
                        and record.required_components <= primitive_record.components
                    ) or (
                        primitive_record.components <= candidate.components
                        and primitive_record.domains <= candidate.domains
                    )
                    for candidate in self._representations
                    if candidate.name in record.representations
                ):
                    continue
            rows.append(record)
        return tuple(rows)

    def realizations(
        self, *, primitive: str | None = None, capabilities=None,
        structure=None, maturity: str | None = None,
    ) -> tuple[RealizationRecord, ...]:
        """Return realization records satisfying all requested features."""

        requested_capabilities = frozenset(_tokens(capabilities))
        requested_structure = frozenset(_tokens(structure))
        records = (
            realization
            for item in self._primitives
            if primitive is None or item.name == primitive
            for realization in item.realizations
        )
        return tuple(
            record for record in records
            if requested_capabilities <= record.capabilities
            and requested_structure <= record.structure
            and (maturity is None or record.maturity == maturity)
        )

    def parameter_sets(
        self, *, primitive: str | None = None, parameters=None,
    ) -> tuple[ParameterSetRecord, ...]:
        """Return named parameter sets containing the requested values."""

        requested = dict(parameters or {})
        records = (
            parameter_set
            for item in self._primitives
            if primitive is None or item.name == primitive
            for parameter_set in item.parameter_sets
        )
        return tuple(
            record for record in records
            if all(record.values.get(name) == value for name, value in requested.items())
        )

    def drivers(
        self, *, kind: str | None = None, representation: str | None = None,
    ) -> tuple[DriverRecord, ...]:
        """Return drivers, optionally restricted to a consumed representation."""

        if representation is not None:
            self.representation(representation)
        return tuple(
            record for record in self._drivers
            if kind is None or record.kind == kind
            if representation is None or representation in record.representations
        )

    def driver(self, name: str) -> DriverRecord:
        """Return one declared driver by stable name."""

        matches = tuple(record for record in self._drivers if record.name == name)
        if len(matches) != 1:
            raise KeyError(f"unknown driver {name!r}")
        return matches[0]

    def driver_availability(self, driver: str | DriverRecord) -> DriverAvailabilityRecord:
        """Probe one driver lazily without importing its implementation."""

        record = self.driver(driver) if isinstance(driver, str) else driver
        if not isinstance(record, DriverRecord):
            raise TypeError("driver must be a driver name or DriverRecord")
        if record.availability == "builtin":
            return DriverAvailabilityRecord(record, True, detail="part of the dependency-free core")
        if record.availability == "executable":
            resolved = shutil.which(record.target or "")
            return DriverAvailabilityRecord(record, resolved is not None, resolved=resolved)
        if record.availability == "python_module":
            available = importlib.util.find_spec(record.target or "") is not None
            return DriverAvailabilityRecord(record, available, resolved=record.target if available else None)
        if record.availability == "minizinc_solver":
            executable_name, solver_name = (record.target or "").split(":", 1)
            resolved = shutil.which(executable_name)
            if resolved is None:
                return DriverAvailabilityRecord(record, False, detail="MiniZinc executable not found")
            completed = subprocess.run(
                (resolved, "--solvers"), text=True, capture_output=True, check=False,
                timeout=10,
            )
            available = completed.returncode == 0 and solver_name.lower() in completed.stdout.lower()
            detail = None if available else f"MiniZinc solver {solver_name!r} not registered"
            return DriverAvailabilityRecord(record, available, resolved=resolved, detail=detail)
        raise ValueError(f"unknown availability probe {record.availability!r}")

    def available_drivers(self, *, kind: str | None = None) -> tuple[DriverAvailabilityRecord, ...]:
        """Return successful explicit availability probes in declaration order."""

        probes = tuple(self.driver_availability(record) for record in self.drivers(kind=kind))
        return tuple(probe for probe in probes if probe.available)


__all__ = ["Catalogue"]
