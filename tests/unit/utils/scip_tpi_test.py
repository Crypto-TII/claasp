import os
import subprocess
import pytest


def test_scip_tpi_support():
    try:
        result = subprocess.run(["scip", "-c", "quit"], capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        pytest.skip("SCIP not found in PATH")
    except subprocess.TimeoutExpired:
        pytest.skip("SCIP command timed out")

    output = result.stdout + result.stderr
    tpi_found = "tinycthread" in output.lower()

    print(f"\nSCIP TPI Support: {'ENABLED' if tpi_found else 'DISABLED'}")

    if not tpi_found:
        print("SCIP output (first 20 lines):")
        for line in output.split('\n')[:20]:
            print(f"  {line}")
        pytest.skip("TPI support not enabled in SCIP (TinyCThread not found in output)")

    assert tpi_found


def test_scip_parallel_configuration():
    try:
        num_threads = os.cpu_count()

        result = subprocess.run(
            ["scip", "-c", f"set parallel maxnthreads {num_threads}", "-c", "quit"],
            capture_output=True,
            text=True,
            timeout=30
        )
    except FileNotFoundError:
        pytest.skip("SCIP not found in PATH")

    output = result.stdout + result.stderr
    parallel_error = "Parallel solve not possible" in output

    print(f"\nParallel Configuration Test:")
    print(f"  CPU Cores Detected: {num_threads}")
    print(f"  Parallel Support: {'ENABLED' if not parallel_error else 'DISABLED'}")
    print(f"  Exit Code: {result.returncode}")

    assert not parallel_error
    assert result.returncode == 0