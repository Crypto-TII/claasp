"""Optional command-line driver for the NIST Statistical Test Suite (STS).

Unlike Dieharder, the patched, non-interactive ``assess`` build described
under ``required_dependencies/`` (``assess.c``, ``utilities.c``,
``utilities.h``, applied on top of the official ``sts-2_1_2.zip`` release per
``docker/Dockerfile``) never prints its report to stdout. Its ``main``
requires exactly five arguments (``<input file> <stream length> <number of
bit streams> <input file format 0|1> <15-char test-selection bitmask>``),
``chdir``s into a compile-time constant ``WORKING_DIR``
(``/usr/local/bin/sts-2.1.2`` per ``required_dependencies/utilities.h``), and
(re)writes a single fixed report file for every run at
``<WORKING_DIR>/experiments/AlgorithmTesting/finalAnalysisReport.txt`` --
``"AlgorithmTesting"`` is ``generatorDir[0]`` in the upstream NIST
``decls.h``, always selected when the input is an externally supplied file
rather than one of NIST's built-in PRNGs (see ``generatorOptions`` in
``required_dependencies/utilities.c``). ``openOutputStreams`` opens that file
with ``fopen(..., "w")``, so each run truncates and fully rewrites it rather
than appending.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import re
import shutil
import subprocess
import threading
from tempfile import TemporaryDirectory
from time import monotonic

from claasp_next.analysis.statistical_datasets import StatisticalDataset
from claasp_next.analysis.statistical_results import NISTFinalReport, StatisticalTestRun
from claasp_next.drivers.statistical.parsers import parse_nist_final_report

try:
    import fcntl
except ImportError:  # pragma: no cover - POSIX-only interprocess guard
    fcntl = None


#: ``experiments/<generatorDir[0]>/finalAnalysisReport.txt`` relative to WORKING_DIR.
_REPORT_RELATIVE_PATH = Path("experiments") / "AlgorithmTesting" / "finalAnalysisReport.txt"

#: The ``WORKING_DIR`` compiled into ``required_dependencies/utilities.h`` and
#: the install location used by ``docker/Dockerfile``'s "Installing nist sts"
#: step. Override the constructor argument for a build with a different
#: compiled-in ``WORKING_DIR``.
_DEFAULT_WORKING_DIR = "/usr/local/bin/sts-2.1.2"

#: All fifteen tests selected, matching ``chooseTests``' one-bit-per-test bitmask.
_DEFAULT_TEST_SELECTION = "1" * 15

_LOCKS_GUARD = threading.Lock()
_LOCKS: dict[str, threading.Lock] = {}


def _lock_for(working_dir: str) -> threading.Lock:
    """Return a process-wide lock shared by every driver targeting ``working_dir``."""

    with _LOCKS_GUARD:
        lock = _LOCKS.get(working_dir)
        if lock is None:
            lock = threading.Lock()
            _LOCKS[working_dir] = lock
        return lock


@contextmanager
def _process_lock(report_path: Path):
    """Best-effort POSIX ``flock`` serializing invocations across OS processes.

    ``assess`` always (re)writes the very same fixed report file for a given
    ``working_dir`` (see the module docstring), so concurrent invocations
    from separate OS processes -- not just separate threads of this
    interpreter -- could interleave and clobber one another. This extends
    the in-process :func:`_lock_for` guard across processes on POSIX
    systems; it is silently skipped where ``fcntl`` is unavailable, which is
    an accepted, documented gap rather than a silent correctness claim.
    """

    if fcntl is None:  # pragma: no cover - POSIX-only interprocess guard
        yield
        return
    report_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = report_path.parent / ".claasp-next-nist-sts.lock"
    with lock_path.open("a+") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


class NistStsDriver:
    """Run NIST STS ``assess`` against a canonical CLAASP statistical byte stream.

    ``assess``'s own exit-code convention is inverted from the Unix norm: a
    fully successful run's ``main`` explicitly ``return``s ``1`` while a
    bad-usage invocation (wrong argument count) ``return``s ``0``, and
    internal I/O failures call ``exit(-1)`` (exit status 255). This driver
    therefore never treats a non-zero process exit status as failure by
    itself and never assumes stdout carries the report; the authoritative
    success signal is a freshly (re)written, parseable report file at the
    fixed ``WORKING_DIR``-relative path, detected by comparing the report
    file's modification time immediately before and after the run.
    """

    def __init__(
        self,
        executable: str = "niststs",
        *,
        working_dir: str = _DEFAULT_WORKING_DIR,
        timeout_seconds: float | None = None,
    ) -> None:
        if not isinstance(executable, str) or not executable:
            raise ValueError("executable must be a non-empty string")
        if not isinstance(working_dir, str) or not working_dir:
            raise ValueError("working_dir must be a non-empty string")
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.executable = executable
        self.working_dir = working_dir
        self.timeout_seconds = timeout_seconds

    def run(
        self,
        dataset: StatisticalDataset,
        *,
        number_of_bit_streams: int = 1,
        test_selection: str = _DEFAULT_TEST_SELECTION,
    ) -> StatisticalTestRun[NISTFinalReport]:
        """Execute ``assess`` on one dataset and parse its fixed report file."""

        if not isinstance(dataset, StatisticalDataset):
            raise TypeError("dataset must be a StatisticalDataset")
        if (
            not isinstance(number_of_bit_streams, int)
            or isinstance(number_of_bit_streams, bool)
            or number_of_bit_streams <= 0
        ):
            raise ValueError("number_of_bit_streams must be a positive integer")
        if (
            not isinstance(test_selection, str)
            or len(test_selection) != 15
            or any(character not in "01" for character in test_selection)
        ):
            raise ValueError("test_selection must be a 15-character string of '0'/'1'")
        executable = shutil.which(self.executable)
        if executable is None:
            raise FileNotFoundError(f"NIST STS executable {self.executable!r} was not found")

        report_path = Path(self.working_dir) / _REPORT_RELATIVE_PATH

        with TemporaryDirectory(prefix="claasp-next-niststs-") as directory:
            input_path = Path(directory) / "dataset.bin"
            with input_path.open("wb") as stream:
                byte_count = dataset.write_binary(stream)
            total_bits = byte_count * 8
            if total_bits < number_of_bit_streams:
                raise ValueError("dataset does not contain enough bits for number_of_bit_streams")
            stream_length = total_bits // number_of_bit_streams
            tool_arguments = (
                str(input_path), str(stream_length), str(number_of_bit_streams), "1", test_selection,
            )

            with _lock_for(self.working_dir), _process_lock(report_path):
                previous_mtime = report_path.stat().st_mtime if report_path.exists() else None
                start = monotonic()
                completed = subprocess.run(
                    (executable, *tool_arguments),
                    text=True,
                    capture_output=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
                elapsed = monotonic() - start

                if not report_path.exists():
                    diagnostic = completed.stderr.strip() or completed.stdout.strip()
                    raise RuntimeError(
                        f"NIST STS did not produce a report at {report_path} "
                        f"(exit code {completed.returncode}): {diagnostic or 'no diagnostic output'}"
                    )
                if previous_mtime is not None and report_path.stat().st_mtime <= previous_mtime:
                    diagnostic = completed.stderr.strip() or completed.stdout.strip()
                    raise RuntimeError(
                        f"NIST STS did not refresh its report at {report_path} "
                        f"(exit code {completed.returncode}); refusing to read a stale report "
                        f"from a previous run: {diagnostic or 'no diagnostic output'}"
                    )
                report_text = report_path.read_text(encoding="utf-8")

        report = parse_nist_final_report(report_text)
        version = self._version(executable)
        stable_arguments = tuple(
            "{dataset}" if argument == str(input_path) else argument
            for argument in tool_arguments
        )
        return StatisticalTestRun(
            suite="nist_sts",
            suite_version=version,
            dataset_sha256=dataset.digest(),
            command=(self.executable, *stable_arguments),
            runtime_seconds=elapsed,
            report=report,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    def _version(self, executable: str) -> str:
        """Derive a version string from the resolved install path.

        NIST STS 2.1.2's ``assess`` exposes no ``--version``/``-V`` flag (its
        only recognized invocation shape is the fixed five-argument one; any
        other invocation just prints usage and exits). Reliable version
        provenance for this driver is therefore the compiled-in
        ``WORKING_DIR``/install layout the canonical build recipe produces:
        ``docker/Dockerfile`` and this project's dedicated CI job both build
        from ``sts-2_1_2.zip`` and install so that the resolved executable
        path contains ``sts-2.1.2`` (``/usr/local/bin/sts-2.1.2/assess``,
        symlinked to ``/usr/local/bin/niststs``). When that pattern is not
        present -- a differently laid out build -- version is honestly
        reported as ``"unknown"`` rather than guessed.
        """

        resolved = str(Path(executable).resolve())
        match = re.search(r"sts-(\d+\.\d+\.\d+)", resolved)
        return f"NIST STS {match.group(1)}" if match else "unknown"
