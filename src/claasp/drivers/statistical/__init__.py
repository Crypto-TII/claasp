"""Dependency-free parsers and optional drivers for statistical suites."""

from claasp.drivers.statistical.dieharder import DieharderDriver
from claasp.drivers.statistical.nist import NistStsDriver
from claasp.drivers.statistical.parsers import (
    parse_dieharder_report,
    parse_nist_final_report,
)

__all__ = [
    "DieharderDriver",
    "NistStsDriver",
    "parse_dieharder_report",
    "parse_nist_final_report",
]
