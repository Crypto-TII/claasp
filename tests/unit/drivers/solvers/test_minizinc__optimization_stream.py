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


def test_gecode_failure_comment_does_not_hide_unsatisfiability():
    status, values = _parse_output("=====UNSATISFIABLE=====\n% Top level failure!\n")
    assert status is CPStatus.UNSATISFIABLE and values is None


def test_gecode_diagnostic_unknown_is_not_an_unknown_termination():
    status, values = _parse_output('{"weight":2}\n----------\n==========\n% [<UNKNOWN>]\n')
    assert status is CPStatus.SATISFIED and values == {"weight": 2}


def test_json_strings_can_contain_comments_and_status_marker_text():
    value = "% comment =====UNKNOWN===== ----------"
    status, values = _parse_output('{"text":"' + value + '"}\n----------\n==========\n')
    assert status is CPStatus.SATISFIED and values == {"text": value}
