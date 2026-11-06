"""A time limit must also stop a spawned solver that holds the output pipe."""

import os
import subprocess
import sys
from time import monotonic

import pytest

from claasp.drivers.solvers.minizinc import _run_process


@pytest.mark.skipif(os.name != "posix", reason="process-group cleanup is POSIX-specific")
def test_timeout_stops_solver_descendants_and_keeps_complete_partial_output():
    script = (
        "import subprocess,sys,time\n"
        'subprocess.Popen([sys.executable,"-c","import time;time.sleep(30)"])\n'
        "print('{\"candidate\": 1}\\n----------',flush=True)\n"
        "time.sleep(30)\n"
    )
    started = monotonic()
    with pytest.raises(subprocess.TimeoutExpired) as error:
        _run_process([sys.executable, "-c", script], timeout=2)
    assert monotonic() - started < 10
    output: str | bytes | None = error.value.stdout
    if isinstance(output, bytes):
        output = output.decode()
    assert output is not None
    assert '{"candidate": 1}\n----------' in output
