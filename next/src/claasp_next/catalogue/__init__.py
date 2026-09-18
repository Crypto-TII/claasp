"""Typed catalogue discovery over committed v5 metadata."""

from claasp_next.catalogue.catalogue import Catalogue
from claasp_next.catalogue.records import (
    AnalysisRecord, ComponentRecord, DriverAvailabilityRecord, DriverRecord, InputRecord,
    ParameterSetRecord, PrimitiveRecord, RealizationRecord, RepresentationRecord,
)


catalogue = Catalogue()

__all__ = [
    "AnalysisRecord", "Catalogue", "ComponentRecord", "DriverAvailabilityRecord", "DriverRecord",
    "InputRecord", "ParameterSetRecord", "PrimitiveRecord", "RealizationRecord",
    "RepresentationRecord", "catalogue",
]
