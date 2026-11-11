"""Public lowmc primitive package."""

from claasp._catalogue_metadata import _entry

from .primitive import LowMC

__all__ = ["LowMC"]


__catalogue__ = (_entry("primitive", LowMC),)
