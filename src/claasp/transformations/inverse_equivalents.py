"""Reviewed equivalent graph realizations used for primitive inversion."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType

from claasp.graph import Primitive
from claasp.transformations.contracts import (
    TransformationError,
    TransformationFailureReason,
)

EquivalentFactory = Callable[[Primitive], Primitive]


@dataclass(frozen=True, slots=True)
class PrimitiveInverseEquivalent:
    """One reviewed replacement graph for inversion of a public realization.

    EXAMPLES::

        >>> from claasp.primitives import Aradi
        >>> from claasp.transformations.inverse_equivalents import inversion_equivalent
        >>> replacement, contract = inversion_equivalent(Aradi(number_of_rounds=1))
        >>> (replacement.family_name, contract.source_type.rsplit(".", 1)[-1])
        ('aradi', 'Aradi')
    """

    source_type: str
    replacement_type: str
    factory: EquivalentFactory
    rationale: str


def _round_count(primitive: Primitive) -> int:
    return len(primitive.graph.rounds)


def _aradi(primitive):
    from claasp.primitives.block_ciphers.aradi import AradiSBoxCompactLinearMap

    return AradiSBoxCompactLinearMap(number_of_rounds=_round_count(primitive))


def _aradi_word(primitive):
    from claasp.transformations._inverse_realizations import AradiCompactWord

    return AradiCompactWord(number_of_rounds=_round_count(primitive))


def _ascon(primitive):
    from claasp.primitives.permutations.ascon import AsconSboxSigma

    return AsconSboxSigma(number_of_rounds=_round_count(primitive))


def _gaston(primitive):
    from claasp.primitives.permutations.gaston import GastonSboxTheta

    return GastonSboxTheta(number_of_rounds=_round_count(primitive))


def _keccak(primitive):
    from claasp.transformations._inverse_realizations import KeccakSboxTheta

    return KeccakSboxTheta(
        number_of_rounds=_round_count(primitive),
        word_size=primitive.word_bit_size,
    )


def _xoodoo(primitive):
    from claasp.transformations._inverse_realizations import XoodooSboxTheta

    return XoodooSboxTheta(number_of_rounds=_round_count(primitive))


def _qarmav2(primitive):
    from claasp.transformations._inverse_realizations import QARMAv2Compact

    return QARMAv2Compact(
        number_of_rounds=primitive.nrounds,
        number_of_layers=primitive.number_of_layers,
        key_bit_size=primitive.graph.input("key").array_type.encoded_bit_size,
        tweak_bit_size=primitive.graph.input("input_tweak").array_type.encoded_bit_size,
    )


def _gimli(primitive):
    from claasp.transformations._inverse_realizations import GimliTriangular

    return GimliTriangular(
        number_of_rounds=_round_count(primitive),
        word_size=primitive.word_bit_size,
    )


def _norx(primitive):
    from claasp.transformations._inverse_realizations import NorxTriangular

    return NorxTriangular(
        number_of_rounds=_round_count(primitive),
        word_size=primitive.word_bit_size,
        rotations=primitive.rotations,
    )


def _tinyjambu_fsr(primitive):
    from claasp.primitives.block_ciphers.tinyjambu import TinyJambuWordBased

    return TinyJambuWordBased(
        key_bit_size=primitive.graph.input("key").array_type.encoded_bit_size,
        number_of_rounds=_round_count(primitive) * 32,
    )


_EQUIVALENTS = (
    PrimitiveInverseEquivalent(
        "claasp.primitives.block_ciphers.aradi.primitive.Aradi",
        "claasp.transformations._inverse_realizations.AradiCompactWord",
        _aradi_word,
        "compact S-box and linear-map semantics retain the canonical word boundary",
    ),
    PrimitiveInverseEquivalent(
        "claasp.primitives.block_ciphers.aradi.sbox.AradiSBox",
        "claasp.primitives.block_ciphers.aradi.sbox_compact_linear_map.AradiSBoxCompactLinearMap",
        _aradi,
        "the compact linear map replaces an equivalent reversible XOR/rotation network",
    ),
    PrimitiveInverseEquivalent(
        "claasp.primitives.permutations.ascon.primitive.Ascon",
        "claasp.primitives.permutations.ascon.sbox_sigma.AsconSboxSigma",
        _ascon,
        "the S-box/sigma graph is the reviewed equivalent Ascon realization",
    ),
    PrimitiveInverseEquivalent(
        "claasp.primitives.permutations.ascon.sbox_sigma_no_matrix.AsconSboxSigmaNoMatrix",
        "claasp.primitives.permutations.ascon.sbox_sigma.AsconSboxSigma",
        _ascon,
        "the sigma component replaces an equivalent reversible XOR/rotation network",
    ),
    PrimitiveInverseEquivalent(
        "claasp.primitives.permutations.gaston.primitive.Gaston",
        "claasp.primitives.permutations.gaston.sbox_theta.GastonSboxTheta",
        _gaston,
        "the S-box/theta graph is the reviewed equivalent Gaston realization",
    ),
    PrimitiveInverseEquivalent(
        "claasp.primitives.permutations.gaston.sbox.GastonSbox",
        "claasp.primitives.permutations.gaston.sbox_theta.GastonSboxTheta",
        _gaston,
        "the theta component replaces an equivalent reversible XOR/rotation network",
    ),
    PrimitiveInverseEquivalent(
        "claasp.primitives.permutations.gimli.primitive.Gimli",
        "claasp.transformations._inverse_realizations.GimliTriangular",
        _gimli,
        "the published triangular SP recurrence exposes exact predecessor order",
    ),
    PrimitiveInverseEquivalent(
        "claasp.primitives.permutations.gimli.sbox.GimliSbox",
        "claasp.transformations._inverse_realizations.GimliTriangular",
        _gimli,
        "the published triangular SP recurrence replaces the non-bijective local table network",
    ),
    PrimitiveInverseEquivalent(
        "claasp.primitives.permutations.keccak.primitive.Keccak",
        "claasp.transformations._inverse_realizations.KeccakSboxTheta",
        _keccak,
        "reviewed S-box and compact-theta semantics replace the boolean gate network",
    ),
    PrimitiveInverseEquivalent(
        "claasp.primitives.permutations.keccak.invertible.KeccakInvertible",
        "claasp.transformations._inverse_realizations.KeccakSboxTheta",
        _keccak,
        "compact theta avoids expanding a reversible linear region during inversion",
    ),
    PrimitiveInverseEquivalent(
        "claasp.primitives.permutations.keccak.sbox.KeccakSbox",
        "claasp.transformations._inverse_realizations.KeccakSboxTheta",
        _keccak,
        "compact theta avoids expanding a reversible linear region during inversion",
    ),
    PrimitiveInverseEquivalent(
        "claasp.primitives.permutations.xoodoo.primitive.Xoodoo",
        "claasp.transformations._inverse_realizations.XoodooSboxTheta",
        _xoodoo,
        "reviewed S-box and compact-theta semantics replace the boolean gate network",
    ),
    PrimitiveInverseEquivalent(
        "claasp.primitives.permutations.xoodoo.invertible.XoodooInvertible",
        "claasp.transformations._inverse_realizations.XoodooSboxTheta",
        _xoodoo,
        "compact theta avoids expanding a reversible linear region during inversion",
    ),
    PrimitiveInverseEquivalent(
        "claasp.primitives.permutations.xoodoo.sbox.XoodooSbox",
        "claasp.transformations._inverse_realizations.XoodooSboxTheta",
        _xoodoo,
        "compact theta avoids expanding a reversible linear region during inversion",
    ),
    PrimitiveInverseEquivalent(
        "claasp.primitives.permutations.norx.Norx",
        "claasp.transformations._inverse_realizations.NorxTriangular",
        _norx,
        "the triangular bit recurrence preserves NORX H while exposing exact recovery order",
    ),
    PrimitiveInverseEquivalent(
        "claasp.primitives.tweakable_block_ciphers.qarmav2.primitive.QARMAv2",
        "claasp.transformations._inverse_realizations.QARMAv2Compact",
        _qarmav2,
        "compact linear maps preserve the canonical rotation-based M function",
    ),
    PrimitiveInverseEquivalent(
        "claasp.primitives.block_ciphers.tinyjambu.fsr_word.TinyJambuFSRWordBased",
        "claasp.primitives.block_ciphers.tinyjambu.word.TinyJambuWordBased",
        _tinyjambu_fsr,
        "the reviewed word graph preserves the same keyed feedback transition",
    ),
)

DEFAULT_PRIMITIVE_INVERSE_EQUIVALENTS = MappingProxyType(
    {item.source_type: item for item in _EQUIVALENTS}
)

_DIRECT_INVERSES = MappingProxyType(
    {
        "claasp.primitives.tweakable_block_ciphers.chilow.Chilow": (
            "claasp.transformations._inverse_realizations.chilow_inverse",
            "the published ChiChi boundary formulas give an exact retained-tweak/key inverse",
        ),
        "claasp.primitives.block_ciphers.subterranean.Subterranean": (
            "claasp.transformations._inverse_realizations.subterranean_inverse",
            "the published odd-width chi recurrence gives an exact keyed round inverse",
        ),
    }
)


def _qualified_type(value) -> str:
    return f"{type(value).__module__}.{type(value).__qualname__}"


def inversion_equivalent(primitive: Primitive):
    """Return a validated reviewed equivalent graph, when one is registered.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> from claasp.transformations.inverse_equivalents import inversion_equivalent
        >>> inversion_equivalent(Speck(number_of_rounds=1))
        (None, None)
    """

    contract = DEFAULT_PRIMITIVE_INVERSE_EQUIVALENTS.get(_qualified_type(primitive))
    if contract is None:
        return None, None
    replacement = contract.factory(primitive)
    if _qualified_type(replacement) != contract.replacement_type:
        raise AssertionError("inverse-equivalent factory returned the wrong primitive type")
    if primitive.graph.input_descriptors != replacement.graph.input_descriptors:
        raise TransformationError(
            TransformationFailureReason.AMBIGUOUS_BOUNDARY,
            "inverse-equivalent graph has a different input contract",
        )
    if primitive.graph.output is None or replacement.graph.output is None:
        raise TransformationError(
            TransformationFailureReason.AMBIGUOUS_BOUNDARY,
            "inverse-equivalent graph requires declared outputs",
        )
    if primitive.graph.output.array_type != replacement.graph.output.array_type:
        raise TransformationError(
            TransformationFailureReason.AMBIGUOUS_BOUNDARY,
            "inverse-equivalent graph has a different output contract",
        )
    return replacement, contract


def direct_inversion_equivalent(primitive: Primitive, output_name: str):
    """Return a reviewed directly authored primitive inverse, when registered.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> from claasp.transformations.inverse_equivalents import direct_inversion_equivalent
        >>> direct_inversion_equivalent(Speck(number_of_rounds=1), "output")
        (None, None)
    """

    contract = _DIRECT_INVERSES.get(_qualified_type(primitive))
    if contract is None:
        return None, None
    if contract[0].endswith("chilow_inverse"):
        if tuple(primitive.graph.input_ports) != ("plaintext", "input_tweak", "key"):
            return None, None
        from claasp.transformations._inverse_realizations import chilow_inverse

        return chilow_inverse(primitive, output_name), contract
    if tuple(primitive.graph.input_ports) == ("plaintext", "key"):
        from claasp.transformations._inverse_realizations import subterranean_inverse

        return subterranean_inverse(primitive, output_name), contract
    return None, None


__all__ = [
    "DEFAULT_PRIMITIVE_INVERSE_EQUIVALENTS",
    "PrimitiveInverseEquivalent",
    "direct_inversion_equivalent",
    "inversion_equivalent",
]
