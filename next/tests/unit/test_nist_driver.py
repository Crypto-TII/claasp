from pathlib import Path

import pytest

from claasp_next.analysis import cbc_dataset
from claasp_next.primitives import Speck
from claasp_next.drivers.statistical import NistStsDriver
from claasp_next.drivers.statistical.nist import _REPORT_RELATIVE_PATH


REPORT_BODY = (
    "------------------------------------------------------------------------------\n"
    "RESULTS FOR THE UNIFORMITY OF P-VALUES AND THE PROPORTION OF PASSING SEQUENCES\n"
    "------------------------------------------------------------------------------\n"
    "   generator is <fake>\n"
    "------------------------------------------------------------------------------\n"
    " C1  C2  C3  C4  C5  C6  C7  C8  C9 C10  P-VALUE  PROPORTION  STATISTICAL TEST\n"
    "------------------------------------------------------------------------------\n"
    "  0   0   2   0   2   3   1   0   2   0  0.213309     10/10      Frequency\n"
)

# Starting a temporary shell executable can occasionally exceed two seconds
# under macOS endpoint-security scanning. This remains below the routine
# integration-test budget and does not change the expected fast success path.
FAKE_EXECUTABLE_TIMEOUT_SECONDS = 10


def _report_path(working_dir: Path) -> Path:
    return working_dir / _REPORT_RELATIVE_PATH


def _fake_assess(tmp_path: Path, *, body: str | None, exit_code: int = 1) -> Path:
    """A fake ``assess`` whose install path mirrors ``.../sts-2.1.2/assess``.

    It never reads stdin/writes stdout the way the real tool would; it only
    (re)writes ``experiments/AlgorithmTesting/finalAnalysisReport.txt``
    beneath the directory it was told to treat as ``WORKING_DIR`` via the
    ``NIST_STS_FAKE_WORKING_DIR`` environment variable baked into the script
    below, and echoes its arguments to stderr so tests can inspect the exact
    five-argument invocation contract.
    """

    working_dir = tmp_path / "working"
    script_dir = tmp_path / "sts-2.1.2"
    script_dir.mkdir(parents=True, exist_ok=True)
    executable = script_dir / "assess"
    report_path = _report_path(working_dir)
    write_report = "" if body is None else (
        f'mkdir -p "{report_path.parent}"\n'
        f'cat > "{report_path}" <<\'EOF\'\n{body}EOF\n'
    )
    executable.write_text(
        "#!/bin/sh\n"
        'printf \'%s\\n\' "$@" >&2\n'
        f"{write_report}"
        f"exit {exit_code}\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return executable


def _dataset():
    return cbc_dataset(
        Speck(number_of_rounds=1), "plaintext", 1, 3, fixed_inputs={"key": 0}
    )


def test_driver_reads_fixed_report_path_despite_inverted_exit_code(tmp_path):
    dataset = _dataset()
    executable = _fake_assess(tmp_path, body=REPORT_BODY, exit_code=1)
    working_dir = tmp_path / "working"

    run = NistStsDriver(
        str(executable), working_dir=str(working_dir),
        timeout_seconds=FAKE_EXECUTABLE_TIMEOUT_SECONDS,
    ).run(
        dataset, number_of_bit_streams=1
    )

    assert run.suite == "nist_sts"
    assert run.suite_version == "NIST STS 2.1.2"
    assert run.dataset_sha256 == dataset.digest()
    assert run.command[0] == str(executable)
    assert run.command[1] == "{dataset}"  # the volatile temp-file input path is replaced
    assert run.command[3] == "1"  # number of bit streams
    assert run.command[4] == "1"  # input file format: 1 == binary
    assert run.command[5] == "1" * 15  # test-selection bitmask: every test selected
    assert run.runtime_seconds >= 0
    assert len(run.report.rows) == 1
    assert run.report.rows[0].test_name == "Frequency"
    assert run.report.rows[0].passed_sequences == 10
    # The fake script echoes its argv to stderr; confirm the real invocation
    # (not the stable command above) carried the actual temp-file input path
    # and the same five-argument shape as the stable command.
    argv = run.stderr.strip().splitlines()
    assert argv[0].endswith("dataset.bin")
    assert argv[1:] == list(run.command[2:])


def test_driver_computes_stream_length_from_dataset_bit_count(tmp_path):
    dataset = _dataset()
    executable = _fake_assess(tmp_path, body=REPORT_BODY, exit_code=1)
    working_dir = tmp_path / "working"
    expected_total_bits = dataset.manifest().byte_count * 8

    run = NistStsDriver(
        str(executable), working_dir=str(working_dir),
        timeout_seconds=FAKE_EXECUTABLE_TIMEOUT_SECONDS,
    ).run(
        dataset, number_of_bit_streams=1
    )

    assert run.command[2] == str(expected_total_bits)

    run_split = NistStsDriver(
        str(executable), working_dir=str(working_dir),
        timeout_seconds=FAKE_EXECUTABLE_TIMEOUT_SECONDS,
    ).run(
        dataset, number_of_bit_streams=2
    )

    assert run_split.command[2] == str(expected_total_bits // 2)


def test_driver_raises_when_report_is_never_produced(tmp_path):
    dataset = _dataset()
    executable = _fake_assess(tmp_path, body=None, exit_code=0)
    working_dir = tmp_path / "working"

    with pytest.raises(RuntimeError, match="did not produce a report"):
        NistStsDriver(
            str(executable), working_dir=str(working_dir),
            timeout_seconds=FAKE_EXECUTABLE_TIMEOUT_SECONDS,
        ).run(dataset)


def test_driver_refuses_a_stale_report_left_by_a_previous_run(tmp_path):
    dataset = _dataset()
    working_dir = tmp_path / "working"
    stale_report = _report_path(working_dir)
    stale_report.parent.mkdir(parents=True, exist_ok=True)
    stale_report.write_text(REPORT_BODY, encoding="utf-8")

    # This fake tool never touches the report file, simulating a run that
    # crashed (or hit the usage-error branch) before rewriting it.
    executable = _fake_assess(tmp_path, body=None, exit_code=0)

    with pytest.raises(RuntimeError, match="did not refresh its report"):
        NistStsDriver(
            str(executable), working_dir=str(working_dir),
            timeout_seconds=FAKE_EXECUTABLE_TIMEOUT_SECONDS,
        ).run(dataset)


def test_driver_validates_options_and_missing_executable(tmp_path):
    dataset = _dataset()
    executable = _fake_assess(tmp_path, body=REPORT_BODY, exit_code=1)
    working_dir = tmp_path / "working"
    driver = NistStsDriver(
        str(executable), working_dir=str(working_dir),
        timeout_seconds=FAKE_EXECUTABLE_TIMEOUT_SECONDS,
    )

    with pytest.raises(ValueError, match="number_of_bit_streams"):
        driver.run(dataset, number_of_bit_streams=0)
    with pytest.raises(ValueError, match="test_selection"):
        driver.run(dataset, test_selection="1" * 14)
    with pytest.raises(ValueError, match="test_selection"):
        driver.run(dataset, test_selection="2" * 15)
    with pytest.raises(FileNotFoundError, match="was not found"):
        NistStsDriver("definitely-not-a-real-niststs", working_dir=str(working_dir)).run(dataset)


def test_version_falls_back_to_unknown_without_an_sts_version_hint(tmp_path):
    dataset = _dataset()
    working_dir = tmp_path / "working"
    unversioned = tmp_path / "unversioned-assess"
    report_path = _report_path(working_dir)
    unversioned.write_text(
        "#!/bin/sh\n"
        f'mkdir -p "{report_path.parent}"\n'
        f'cat > "{report_path}" <<\'EOF\'\n{REPORT_BODY}EOF\n'
        "exit 1\n",
        encoding="utf-8",
    )
    unversioned.chmod(0o755)

    run = NistStsDriver(
        str(unversioned), working_dir=str(working_dir),
        timeout_seconds=FAKE_EXECUTABLE_TIMEOUT_SECONDS,
    ).run(dataset)

    assert run.suite_version == "unknown"
