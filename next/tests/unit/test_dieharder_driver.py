from pathlib import Path

import pytest

from claasp_next.analysis import cbc_dataset
from claasp_next.ciphers import SpeckBlockCipher
from claasp_next.drivers.statistical import DieharderDriver


SCRIPT = """#!/bin/sh
if [ "$1" = "-h" ]; then
  echo "dieharder version 3.test"
  exit 0
fi
printf '%s\\n' "$@" >&2
echo 'diehard_birthdays|0|100|100|0.50000000|PASSED'
"""


def _fake_dieharder(tmp_path: Path) -> Path:
    executable = tmp_path / "dieharder"
    executable.write_text(SCRIPT, encoding="utf-8")
    executable.chmod(0o755)
    return executable


def test_driver_uses_raw_generator_and_records_reproducibility(tmp_path):
    dataset = cbc_dataset(
        SpeckBlockCipher(number_of_rounds=1),
        "plaintext",
        1,
        3,
        fixed_inputs={"key": 0},
    )
    run = DieharderDriver(str(_fake_dieharder(tmp_path)), timeout_seconds=2).run(
        dataset, test=100
    )

    assert run.suite == "dieharder"
    assert run.suite_version == "dieharder version 3.test"
    assert run.dataset_sha256 == dataset.digest()
    assert run.command == (str(tmp_path / "dieharder"), "-g", "201", "-f", "{dataset}", "-d", "100")
    assert run.report.passed_count == 1
    assert "-g\n201\n-f\n" in run.stderr


def test_driver_validates_options_and_external_failures(tmp_path):
    dataset = cbc_dataset(
        SpeckBlockCipher(number_of_rounds=1), "plaintext", 1, 1, fixed_inputs={"key": 0}
    )
    with pytest.raises(ValueError, match="non-negative"):
        DieharderDriver(str(_fake_dieharder(tmp_path))).run(dataset, test=-1)
    with pytest.raises(FileNotFoundError, match="was not found"):
        DieharderDriver("definitely-not-a-real-dieharder").run(dataset)

    failing = tmp_path / "failing-dieharder"
    failing.write_text("#!/bin/sh\necho broken >&2\nexit 7\n", encoding="utf-8")
    failing.chmod(0o755)
    with pytest.raises(RuntimeError, match="exit code 7: broken"):
        DieharderDriver(str(failing)).run(dataset)
