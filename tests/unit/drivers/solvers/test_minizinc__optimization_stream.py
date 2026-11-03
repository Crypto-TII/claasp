"""Optimization must select the last incumbent, not the first feasible point."""

from claasp.drivers.solvers.minizinc import CPStatus, _parse_output


def test_optimization_stream_keeps_the_latest_incumbent():
    status, values = _parse_output(
        '{"weight":5}\n----------\n{"weight":2}\n----------\n==========\n'
    )
    assert status is CPStatus.SATISFIED and values == {"weight": 2}


def test_unknown_stream_retains_its_incumbent_and_unknown_status():
    status, values = _parse_output('{"weight":5}\n----------\n=====UNKNOWN=====\n')
    assert status is CPStatus.UNKNOWN and values == {"weight": 5}
