from collections import Counter
from pathlib import Path

import pytest

from claasp_next.analysis.statistical_results import StatisticalAssessment
from claasp_next.drivers.statistical import parse_dieharder_report, parse_nist_final_report

ROOT = Path(__file__).resolve().parents[3]
NIST_FIXTURES = ROOT / "tests/unit/cipher_modules/statistical_tests/test_data/assess_output"


def test_dieharder_parser_preserves_rows_and_aggregates():
    report = parse_dieharder_report("""
#=============================================================================#
 diehard_birthdays | 0 | 100 | 100 | 0.50000000 | PASSED
 diehard_operm5     | 0 | 100 | 100 | 0.00000001 | WEAK
 diehard_rank_32x32 | 0 | 100 | 100 | 0.99999999 | FAILED
""")

    assert [item.test_id for item in report.observations] == [1, 2, 3]
    assert report.observations[0].test_name == "diehard_birthdays"
    assert report.observations[1].assessment is StatisticalAssessment.WEAK
    assert (report.passed_count, report.weak_count, report.failed_count) == (1, 1, 1)
    assert report.passed_proportion == pytest.approx(1 / 3)


def test_dieharder_parser_rejects_empty_or_malformed_results():
    with pytest.raises(ValueError, match="no result rows"):
        parse_dieharder_report("")
    with pytest.raises(ValueError, match="malformed"):
        parse_dieharder_report("diehard_birthdays|x|100|100|0.5|PASSED")


def test_nist_parser_preserves_failure_markers_and_not_applicable_rows():
    report = parse_nist_final_report("""
  0 0 0 0 0 0 0 0 0 10  0.000000 * 10/10 Frequency
  0 0 0 0 0 0 0 0 0  0  ----       ------ RandomExcursions
""")

    frequency, unavailable = report.rows
    assert frequency.uniformity_p_value == 0.0
    assert frequency.proportion == 1.0
    assert unavailable.uniformity_p_value is None
    assert unavailable.total_sequences == 0
    assert unavailable.proportion == 0.0


@pytest.mark.parametrize(
    "path", sorted(NIST_FIXTURES.glob("*/experiments/AlgorithmTesting/finalAnalysisReport.txt"))
)
def test_nist_parser_preserves_all_committed_reference_suite_rows(path):
    report = parse_nist_final_report(path.read_text(encoding="utf-8"))
    counts = Counter(row.normalized_name for row in report.rows)

    assert len(report.rows) == 188
    assert counts == {
        "frequency": 1,
        "blockfrequency": 1,
        "cumulativesums": 2,
        "runs": 1,
        "longestrun": 1,
        "rank": 1,
        "fft": 1,
        "nonoverlappingtemplate": 148,
        "overlappingtemplate": 1,
        "universal": 1,
        "approximateentropy": 1,
        "randomexcursions": 8,
        "randomexcursionsvariant": 18,
        "serial": 2,
        "linearcomplexity": 1,
    }
    assert all(len(row.bin_counts) == 10 for row in report.rows)
