"""Metadata-backed discovery without implementation imports or source scanning."""

from __future__ import annotations

import json
import importlib.util
from importlib.resources import files
import shutil
import subprocess

from claasp_next.catalogue.records import (
    ComponentRecord, DriverAvailabilityRecord, DriverRecord, InputRecord, ParameterSetRecord,
    PrimitiveRecord, RealizationRecord,
)


FILTER_ALIASES = {
    "block_cipher": "block_ciphers",
    "hash_function": "functions",
    "mac": "block_functions",
    "permutation": "permutations",
    "stream_cipher": "block_functions",
    "toy": "toy_primitives",
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
    """

    def __init__(self) -> None:
        payload = _load_payload()
        self._primitives = tuple(_primitive_record(item) for item in payload["primitives"])
        self._components = tuple(ComponentRecord(**item) for item in payload["components"])
        self._drivers = tuple(DriverRecord(**item) for item in payload["drivers"])

    def primitives(
        self, *, category: str | None = None, filters=None, components=None,
        authenticity: str | None = None,
    ) -> tuple[PrimitiveRecord, ...]:
        """Return primitives matching category, design, and component filters."""

        requested = tuple(_normalized_filter(item) for item in _tokens(filters))
        if category is not None:
            requested += (_normalized_filter(category),)
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

    def components(self, *, names=None) -> tuple[ComponentRecord, ...]:
        """Return public base components, optionally restricted by name."""

        requested = frozenset(_tokens(names))
        return tuple(
            record for record in self._components
            if not requested or record.name in requested
        )

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

    def drivers(self, *, kind: str | None = None) -> tuple[DriverRecord, ...]:
        """Return declared drivers without probing or importing implementations."""

        return tuple(
            record for record in self._drivers
            if kind is None or record.kind == kind
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
