import shutil

import pytest

from claasp.analysis import correlation_dataset
from claasp.drivers.statistical import NistStsDriver
from claasp.primitives import Speck

pytestmark = pytest.mark.external


@pytest.mark.skipif(shutil.which("niststs") is None, reason="NIST STS is not installed")
def test_niststs_driver_executes_one_bounded_smoke_run():
    # NIST STS's individual tests are only statistically meaningful on much
    # larger streams (Rank alone needs 38,912+ bits), but a tiny stream is a
    # legitimate *process-integration* smoke check: it exercises the real
    # five-argument invocation contract, the fixed-report-path read, and the
    # parser end to end in well under the routine-integration-test budget,
    # without asserting anything about the (statistically meaningless)
    # pass/fail outcome itself.
    dataset = correlation_dataset(
        Speck(number_of_rounds=1),
        "plaintext",
        4,
        8,
        seed=9,
        fixed_inputs={"key": 0},
    )
    result = NistStsDriver(timeout_seconds=10).run(dataset, number_of_bit_streams=1)

    assert result.suite == "nist_sts"
    assert result.suite_version != "unknown"
    assert result.dataset_sha256 == dataset.digest()
    assert result.report.rows
    assert result.runtime_seconds < 10


@pytest.mark.skipif(shutil.which("niststs") is None, reason="NIST STS is not installed")
def test_niststs_supplied_non_aligned_sequences_preserve_boundaries():
    from claasp.analysis import SuppliedStatisticalDataset

    # The binary reader consumes 32-bit chunks; 100-bit sequences must use
    # ASCII transport, otherwise it discards bits between sequences.
    dataset = SuppliedStatisticalDataset.from_bits([0, 1] * 500)
    result = NistStsDriver(timeout_seconds=10).run(
        dataset,
        number_of_bit_streams=10,
        bits_per_sequence=100,
        test_selection="100000000000000",
    )
    row = result.report.rows[0]
    assert (row.passed_sequences, row.total_sequences) == (10, 10)
    assert result.command[4] == "0"
