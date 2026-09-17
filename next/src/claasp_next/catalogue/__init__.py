"""Typed catalogue discovery over committed v5 metadata."""

from claasp_next.catalogue.catalogue import Catalogue
from claasp_next.catalogue.records import (
    ComponentRecord, DriverAvailabilityRecord, DriverRecord, InputRecord, ParameterSetRecord,
    PrimitiveRecord, RealizationRecord,
)


catalogue = Catalogue()

__all__ = [
    "Catalogue", "ComponentRecord", "DriverAvailabilityRecord", "DriverRecord", "InputRecord",
    "ParameterSetRecord", "PrimitiveRecord", "RealizationRecord", "catalogue",
]
