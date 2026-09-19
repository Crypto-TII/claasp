import shutil

import pytest

from claasp_next.analysis import correlation_dataset
from claasp_next.drivers.statistical import DieharderDriver
from claasp_next.primitives import Speck

pytestmark = pytest.mark.external


@pytest.mark.skipif(shutil.which("dieharder") is None, reason="Dieharder is not installed")
def test_dieharder_driver_executes_one_bounded_test():
    dataset = correlation_dataset(
        Speck(number_of_rounds=1),
        "plaintext",
        1,
        1024,
        seed=9,
        fixed_inputs={"key": 0},
    )
    result = DieharderDriver(timeout_seconds=10).run(dataset, test=0)

    assert result.suite == "dieharder"
    assert result.suite_version != "unknown"
    assert result.dataset_sha256 == dataset.digest()
    assert result.report.observations
    assert result.runtime_seconds < 10
