"""Portable results produced by external statistical test suites."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class StatisticalAssessment(str, Enum):
    """Portable assessment labels shared by statistical suite adapters."""

    PASSED = "passed"
    WEAK = "weak"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class DieharderObservation:
    """One row from Dieharder's pipe-delimited output."""

    test_id: int
    test_name: str
    ntuple: int
    test_samples: int
    pvalue_samples: int
    p_value: float
    assessment: StatisticalAssessment


@dataclass(frozen=True, slots=True)
class DieharderReport:
    """Parsed Dieharder rows with explicit aggregate counts."""

    observations: tuple[DieharderObservation, ...]

    def count(self, assessment: StatisticalAssessment) -> int:
        return sum(item.assessment is assessment for item in self.observations)

    @property
    def passed_count(self) -> int:
        return self.count(StatisticalAssessment.PASSED)

    @property
    def weak_count(self) -> int:
        return self.count(StatisticalAssessment.WEAK)

    @property
    def failed_count(self) -> int:
        return self.count(StatisticalAssessment.FAILED)

    @property
    def passed_proportion(self) -> float:
        return self.passed_count / len(self.observations)


@dataclass(frozen=True, slots=True)
class NISTSummaryRow:
    """One row from a NIST STS ``finalAnalysisReport.txt`` artifact."""

    test_name: str
    normalized_name: str
    bin_counts: tuple[int, ...]
    uniformity_p_value: float | None
    passed_sequences: int
    total_sequences: int

    @property
    def proportion(self) -> float:
        return self.passed_sequences / self.total_sequences if self.total_sequences else 0.0


@dataclass(frozen=True, slots=True)
class NISTFinalReport:
    """Parsed NIST STS summary rows, including repeated subtests."""

    rows: tuple[NISTSummaryRow, ...]

