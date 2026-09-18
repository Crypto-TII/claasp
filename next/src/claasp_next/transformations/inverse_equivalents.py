"""Reviewed equivalent graph realizations used for primitive inversion."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType

from claasp_next.graph import Primitive
from claasp_next.transformations.contracts import (
    TransformationError, TransformationFailureReason,
)


EquivalentFactory = Callable[[Primitive], Primitive]


@dataclass(frozen=True, slots=True)
class PrimitiveInverseEquivalent:
    """One reviewed replacement graph for inversion of a public realization."""

    source_type: str
    replacement_type: str
    factory: EquivalentFactory
    rationale: str


def _round_count(primitive: Primitive) -> int:
    return len(primitive.rounds)


def _aradi(primitive):
    from claasp_next.primitives.block_ciphers.aradi import AradiSBoxCompactLinearMap

    return AradiSBoxCompactLinearMap(number_of_rounds=_round_count(primitive))


def _ascon(primitive):
    from claasp_next.primitives.permutations.ascon import AsconSboxSigma

    return AsconSboxSigma(number_of_rounds=_round_count(primitive))


def _gaston(primitive):
    from claasp_next.primitives.permutations.gaston import GastonSboxTheta

    return GastonSboxTheta(number_of_rounds=_round_count(primitive))


_EQUIVALENTS = (
    PrimitiveInverseEquivalent(
        "claasp_next.primitives.block_ciphers.aradi.sbox.AradiSBox",
        "claasp_next.primitives.block_ciphers.aradi.sbox_compact_linear_map.AradiSBoxCompactLinearMap",
        _aradi,
        "the compact linear map replaces an equivalent reversible XOR/rotation network",
    ),
    PrimitiveInverseEquivalent(
        "claasp_next.primitives.permutations.ascon.primitive.Ascon",
        "claasp_next.primitives.permutations.ascon.sbox_sigma.AsconSboxSigma",
        _ascon,
        "the S-box/sigma graph is the reviewed equivalent Ascon realization",
    ),
    PrimitiveInverseEquivalent(
        "claasp_next.primitives.permutations.ascon.sbox_sigma_no_matrix.AsconSboxSigmaNoMatrix",
        "claasp_next.primitives.permutations.ascon.sbox_sigma.AsconSboxSigma",
        _ascon,
        "the sigma component replaces an equivalent reversible XOR/rotation network",
    ),
    PrimitiveInverseEquivalent(
        "claasp_next.primitives.permutations.gaston.primitive.Gaston",
        "claasp_next.primitives.permutations.gaston.sbox_theta.GastonSboxTheta",
        _gaston,
        "the S-box/theta graph is the reviewed equivalent Gaston realization",
    ),
    PrimitiveInverseEquivalent(
        "claasp_next.primitives.permutations.gaston.sbox.GastonSbox",
        "claasp_next.primitives.permutations.gaston.sbox_theta.GastonSboxTheta",
        _gaston,
        "the theta component replaces an equivalent reversible XOR/rotation network",
    ),
)

DEFAULT_PRIMITIVE_INVERSE_EQUIVALENTS = MappingProxyType({
    item.source_type: item for item in _EQUIVALENTS
})


def _qualified_type(value) -> str:
    return f"{type(value).__module__}.{type(value).__qualname__}"


def inversion_equivalent(primitive: Primitive):
    """Return a validated reviewed equivalent graph, when one is registered."""

    contract = DEFAULT_PRIMITIVE_INVERSE_EQUIVALENTS.get(_qualified_type(primitive))
    if contract is None:
        return None, None
    replacement = contract.factory(primitive)
    if _qualified_type(replacement) != contract.replacement_type:
        raise AssertionError("inverse-equivalent factory returned the wrong primitive type")
    if primitive.input_descriptors != replacement.input_descriptors:
        raise TransformationError(
            TransformationFailureReason.AMBIGUOUS_BOUNDARY,
            "inverse-equivalent graph has a different input contract",
        )
    if primitive.output is None or replacement.output is None:
        raise TransformationError(
            TransformationFailureReason.AMBIGUOUS_BOUNDARY,
            "inverse-equivalent graph requires declared outputs",
        )
    if primitive.output.value_type != replacement.output.value_type:
        raise TransformationError(
            TransformationFailureReason.AMBIGUOUS_BOUNDARY,
            "inverse-equivalent graph has a different output contract",
        )
    return replacement, contract


__all__ = [
    "DEFAULT_PRIMITIVE_INVERSE_EQUIVALENTS", "PrimitiveInverseEquivalent",
    "inversion_equivalent",
]
