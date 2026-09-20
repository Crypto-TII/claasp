"""Ascon permutation family and retained realizations."""

from claasp.primitives._realizations import realization, register_realizations

from .primitive import Ascon
from .sbox_sigma import AsconSboxSigma
from .sbox_sigma_no_matrix import AsconSboxSigmaNoMatrix

register_realizations(
    Ascon,
    (
        (
            realization(
                "bitsliced",
                "boolean_semantics",
                structure=("bit", "logical_sbox", "rotations"),
                description="bitsliced Ascon graph",
                priority=0,
                provenance=("Ascon specification",),
            ),
            Ascon,
        ),
        (
            realization(
                "sbox_sigma",
                "sbox_semantics",
                "linear_map_semantics",
                structure=("bit", "lookup_sbox", "sigma_matrix"),
                description="S-box and matrix-Sigma Ascon graph",
                priority=10,
                provenance=("Ascon specification", "legacy CLAASP regression"),
            ),
            AsconSboxSigma,
        ),
        (
            realization(
                "sbox_sigma_no_matrix",
                "sbox_semantics",
                structure=("bit", "lookup_sbox", "sigma_rotations"),
                description="S-box and rotation-Sigma Ascon graph",
                priority=20,
                provenance=("Ascon specification", "legacy CLAASP regression"),
            ),
            AsconSboxSigmaNoMatrix,
        ),
    ),
)

__all__ = ["Ascon", "AsconSboxSigma", "AsconSboxSigmaNoMatrix"]
