"""Metadata-backed discovery without implementation imports or source scanning."""

from __future__ import annotations

import json
from importlib.resources import files

from claasp_next.catalogue.records import (
    ComponentRecord, DriverRecord, InputRecord, ParameterSetRecord,
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


__all__ = ["Catalogue"]
