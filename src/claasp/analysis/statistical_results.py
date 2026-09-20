"""Portable results produced by external statistical test suites."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Generic, TypeVar


class StatisticalAssessment(str, Enum):
    """Portable assessment labels shared by statistical suite adapters.

    EXAMPLES::

        >>> tuple(member.value for member in StatisticalAssessment)
        ('passed', 'weak', 'failed')
    """

    PASSED = "passed"
    WEAK = "weak"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class DieharderObservation:
    """One row from Dieharder's pipe-delimited output.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (DieharderObservation.__dataclass_params__.frozen, tuple(field.name for field in fields(DieharderObservation)))
        (True, ('test_id', 'test_name', 'ntuple', 'test_samples', 'pvalue_samples', 'p_value', 'assessment'))
    """

    test_id: int
    test_name: str
    ntuple: int
    test_samples: int
    pvalue_samples: int
    p_value: float
    assessment: StatisticalAssessment


@dataclass(frozen=True, slots=True)
class DieharderReport:
    """Parsed Dieharder rows with explicit aggregate counts.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (DieharderReport.__dataclass_params__.frozen, tuple(field.name for field in fields(DieharderReport)))
        (True, ('observations',))
    """

    observations: tuple[DieharderObservation, ...]

    def count(self, assessment: StatisticalAssessment) -> int:
        """Return the count for this public typed contract."""

        return sum(item.assessment is assessment for item in self.observations)

    @property
    def passed_count(self) -> int:
        """Return the passed count for this public typed contract."""

        return self.count(StatisticalAssessment.PASSED)

    @property
    def weak_count(self) -> int:
        """Return the weak count for this public typed contract."""

        return self.count(StatisticalAssessment.WEAK)

    @property
    def failed_count(self) -> int:
        """Return the failed count for this public typed contract."""

        return self.count(StatisticalAssessment.FAILED)

    @property
    def passed_proportion(self) -> float:
        """Return the passed proportion for this public typed contract."""

        return self.passed_count / len(self.observations)


@dataclass(frozen=True, slots=True)
class NISTSummaryRow:
    """One row from a NIST STS ``finalAnalysisReport.txt`` artifact.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (NISTSummaryRow.__dataclass_params__.frozen, tuple(field.name for field in fields(NISTSummaryRow)))
        (True, ('test_name', 'normalized_name', 'bin_counts', 'uniformity_p_value', 'passed_sequences', 'total_sequences'))
    """

    test_name: str
    normalized_name: str
    bin_counts: tuple[int, ...]
    uniformity_p_value: float | None
    passed_sequences: int
    total_sequences: int

    @property
    def proportion(self) -> float:
        """Return the proportion for this public typed contract."""

        return self.passed_sequences / self.total_sequences if self.total_sequences else 0.0


@dataclass(frozen=True, slots=True)
class NISTFinalReport:
    """Parsed NIST STS summary rows, including repeated subtests.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (NISTFinalReport.__dataclass_params__.frozen, tuple(field.name for field in fields(NISTFinalReport)))
        (True, ('rows',))
    """

    rows: tuple[NISTSummaryRow, ...]


StatisticalReport = TypeVar("StatisticalReport")


@dataclass(frozen=True, slots=True)
class StatisticalTestRun(Generic[StatisticalReport]):
    """One reproducible execution of an optional statistical program.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (StatisticalTestRun.__dataclass_params__.frozen, tuple(field.name for field in fields(StatisticalTestRun)))
        (True, ('suite', 'suite_version', 'dataset_sha256', 'command', 'runtime_seconds', 'report', 'stdout', 'stderr'))
    """

    suite: str
    suite_version: str
    dataset_sha256: str
    command: tuple[str, ...]
    runtime_seconds: float
    report: StatisticalReport
    stdout: str
    stderr: str
