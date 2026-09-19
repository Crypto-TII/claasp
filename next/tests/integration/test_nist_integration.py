import shutil

import pytest

from claasp_next.analysis import correlation_dataset
from claasp_next.drivers.statistical import NistStsDriver
from claasp_next.primitives import Speck

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
