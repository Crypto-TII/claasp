"""Optional execution drivers for typed component-property requests."""

from claasp._catalogue_metadata import _entry
from claasp.drivers.analysis.branch_number import (
    BoundedBranchNumberDriver,
    MiniZincBranchNumberDriver,
)

__all__ = ["BoundedBranchNumberDriver", "MiniZincBranchNumberDriver"]


__catalogue__ = (
    _entry(
        "driver",
        BoundedBranchNumberDriver,
        name="component_bounded",
        kind="analysis_driver",
        availability="builtin",
    ),
    _entry(
        "driver",
        MiniZincBranchNumberDriver,
        name="component_minizinc",
        kind="analysis_driver",
        availability="executable",
        target_parameter="executable",
    ),
)
