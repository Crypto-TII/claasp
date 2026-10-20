import copy
import os

import pytest

from claasp.cipher_modules.models.sat import solvers
from claasp.cipher_modules.models.sat.utils.utils import cnf_or, cnf_xor_seq, run_mallob


def _fake_mallob_specs(shell_script):
    # "sh -c <script>" ignores the "-mono=<file>" argument appended by run_mallob
    specs = copy.deepcopy(
        next(spec for spec in solvers.SAT_SOLVERS_EXTERNAL if spec["solver_name"] == solvers.MALLOB_EXT)
    )
    specs["keywords"]["command"]["executable"] = "sh"
    specs["keywords"]["command"]["options"] = ["-c", shell_script]
    return specs


def test_cnf_or():
    assert cnf_or("r", ["a", "b", "c"]) == ["r -a", "r -b", "r -c", "-r a b c"]


def test_cnf_xor_seq():
    xor_seq = cnf_xor_seq(["i_0", "i_1", "r_7"], ["a_7", "b_7", "c_7", "d_7"])

    assert xor_seq[0] == "-i_0 a_7 b_7"
    assert xor_seq[1] == "i_0 -a_7 b_7"
    assert xor_seq[2] == "i_0 a_7 -b_7"
    assert xor_seq[-3] == "r_7 -i_1 d_7"
    assert xor_seq[-2] == "r_7 i_1 -d_7"
    assert xor_seq[-1] == "-r_7 -i_1 -d_7"


def test_run_mallob(tmp_path):
    specs = _fake_mallob_specs(
        "printf 'c 0.034 0 RESPONSE_TIME #1 0.031958 rev. 0\\ns SATISFIABLE\\nv 1 -2\\nv 3 0\\n'"
    )
    input_file = str(tmp_path / "input.cnf")
    status, solver_time, solver_memory, values = run_mallob(specs, [], "p cnf 3 0\n", input_file)

    assert status == "SATISFIABLE"
    assert solver_time == 0.031958
    assert solver_memory == 0
    assert values == ["1", "-2", "3"]
    assert not os.path.exists(input_file)


def test_run_mallob_without_status_line(tmp_path):
    specs = _fake_mallob_specs("exit 134")
    input_file = str(tmp_path / "input.cnf")
    with pytest.raises(RuntimeError, match="mallob produced no status line"):
        run_mallob(specs, [], "p cnf 3 0\n", input_file)

    assert not os.path.exists(input_file)


def test_parse_parkissat_output_keeps_only_the_model_after_the_status_line():
    from claasp.cipher_modules.models.sat.utils.utils import parse_parkissat_output

    output = ["c thread 3 model fragment", "v -1 2", "s SATISFIABLE", "v 1 -2 3", "c thread 1", "v -4 0", "v 5 0"]
    status, values = parse_parkissat_output(output)
    assert status == "SATISFIABLE"
    assert values == ["1", "-2", "3", "-4"]


def test_parse_parkissat_output_orders_literals_by_variable_and_tolerates_duplicates():
    from claasp.cipher_modules.models.sat.utils.utils import parse_parkissat_output

    output = ["s SATISFIABLE", "v 3 -1", "v 2 3 -1 0"]
    assert parse_parkissat_output(output) == ("SATISFIABLE", ["-1", "2", "3"])


def test_parse_parkissat_output_rejects_mixed_models():
    import pytest
    from claasp.cipher_modules.models.sat.utils.utils import parse_parkissat_output

    with pytest.raises(RuntimeError):
        parse_parkissat_output(["s SATISFIABLE", "v 1 -2", "v -1 2 0"])


def test_parse_parkissat_output_unsat():
    from claasp.cipher_modules.models.sat.utils.utils import parse_parkissat_output

    assert parse_parkissat_output(["c x", "s UNSATISFIABLE"]) == ("UNSATISFIABLE", "")
