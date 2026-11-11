"""Serialize polynomial systems for optional open-source drivers."""

from claasp._catalogue_metadata import _entry
from claasp.representations.constraints.polynomial.exporters.msolve import MsolveExporter
from claasp.representations.constraints.polynomial.exporters.singular import SingularExporter

__all__ = ["MsolveExporter", "SingularExporter"]


__catalogue__ = (
    _entry(
        "representation",
        MsolveExporter,
        name="msolve_input",
        kind="serialization",
        components=("Add", "Constant", "Identity", "LinearMap", "Multiply", "Permutation", "Power"),
        domains=("PrimeField",),
        drivers=("msolve",),
        scope="generic_graph",
    ),
    _entry(
        "representation",
        SingularExporter,
        name="singular_program",
        kind="serialization",
        components=("Add", "Constant", "Identity", "LinearMap", "Multiply", "Permutation", "Power"),
        domains=("PrimeField",),
        drivers=("singular",),
        scope="generic_graph",
    ),
)
