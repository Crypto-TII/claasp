"""Dependency-free parsers and optional drivers for statistical suites."""

from claasp_next.drivers.statistical.parsers import (
    parse_dieharder_report,
    parse_nist_final_report,
)

__all__ = ["parse_dieharder_report", "parse_nist_final_report"]

