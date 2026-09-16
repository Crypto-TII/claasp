"""Versioned Poseidon parameter sets with explicit provenance."""

from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
import json

from .primitive import Poseidon


@dataclass(frozen=True, slots=True)
class PoseidonParameterSet:
    """A complete parameter set for a Poseidon permutation.

    EXAMPLES::

        >>> from claasp_next.representations.execution import ScalarEvaluator
        >>> from claasp_next.parameters import poseidon_bn254_width3
        >>> parameters = poseidon_bn254_width3()
        >>> parameters.source_commit
        '5194eadce26b3fe4b1c4fe2a5ca9f6436f3b0e3d'
        >>> result = ScalarEvaluator().evaluate(
        ...     parameters.permutation(),
        ...     {"state": parameters.reference_input},
        ... )
        >>> hex(result.output[parameters.reference_output_position])
        '0xfca49b798923ab0239de1c9e7a4a9a2210312b6a2f616d18b5a87f9b628ae29'
    """

    name: str
    schema_version: int
    source_url: str
    source_commit: str
    source_license: str
    modulus: int
    width: int
    exponent: int
    full_rounds: int
    partial_rounds: int
    round_constants: tuple[tuple[int, ...], ...]
    linear_layer: tuple[tuple[int, ...], ...]
    reference_input: tuple[int, ...]
    reference_output_position: int
    reference_output: int

    def permutation(self) -> Poseidon:
        """Construct a typed permutation graph from this parameter set."""

        return Poseidon(
            modulus=self.modulus,
            exponent=self.exponent,
            full_rounds=self.full_rounds,
            partial_rounds=self.partial_rounds,
            round_constants=self.round_constants,
            linear_layer=self.linear_layer,
        )


@lru_cache(maxsize=1)
def poseidon_bn254_width3() -> PoseidonParameterSet:
    """Load the bundled BN254 scalar-field, width-3 Poseidon parameters."""

    resource = files(__package__).joinpath("data/poseidon_bn254_width3.json")
    payload = json.loads(resource.read_text(encoding="utf-8"))
    source = payload["source"]
    reference = payload["reference"]
    return PoseidonParameterSet(
        name=payload["name"],
        schema_version=payload["schema_version"],
        source_url=source["url"],
        source_commit=source["commit"],
        source_license=source["license"],
        modulus=payload["modulus"],
        width=payload["width"],
        exponent=payload["exponent"],
        full_rounds=payload["full_rounds"],
        partial_rounds=payload["partial_rounds"],
        round_constants=tuple(tuple(row) for row in payload["round_constants"]),
        linear_layer=tuple(tuple(row) for row in payload["linear_layer"]),
        reference_input=tuple(reference["input"]),
        reference_output_position=reference["output_position"],
        reference_output=reference["output"],
    )
