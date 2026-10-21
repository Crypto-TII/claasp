import pytest

from claasp.analysis.avalanche import avalanche_probabilities
from claasp.primitives import Speck


def test_one_round_speck_avalanche_fixture_is_reproducible():
    primitive = Speck(number_of_rounds=1)
    result = avalanche_probabilities(primitive, "plaintext", 4, seed=9, fixed_inputs={"key": 0})

    assert result.input_bit_count == 32
    assert result.output_bit_count == 32
    assert result.probabilities[0] == (
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.5,
        1.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.5,
        1.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
    )
    assert result.complete is False
    assert result.method == "empirical_paired_evaluation"


def test_avalanche_summary_and_input_validation():
    primitive = Speck(number_of_rounds=1)
    result = avalanche_probabilities(primitive, "plaintext", 2, seed=0)

    assert result.mean_changed_output_bits[0] == sum(result.probabilities[0])
    assert 0 <= result.maximum_sac_bias <= 0.5
    with pytest.raises(KeyError, match="nonce"):
        avalanche_probabilities(primitive, "nonce", 1)


def test_primitive_analysis_facade_exposes_avalanche():
    result = Speck(number_of_rounds=1).analysis.avalanche(
        "plaintext", 2, seed=9, fixed_inputs={"key": 0}
    )
    assert result.sample_count == 2
    assert result.input_name == "plaintext"


def test_terminal_report_uses_current_stdout_or_explicit_stream(capsys):
    from io import StringIO

    from claasp.analysis.avalanche import AvalancheResult
    from claasp.presentation import avalanche_section, render_section

    result = AvalancheResult("fixture", "plaintext", 2, 9, ((0.0, 0.5), (1.0, 0.5)))
    expected = render_section(avalanche_section(result), format="terminal")
    result.to_terminal()
    assert capsys.readouterr().out == expected
    output = StringIO()
    result.to_terminal(file=output)
    assert output.getvalue() == expected
    assert capsys.readouterr().out == ""


def test_result_terminal_output_does_not_import_optional_dependencies():
    import os
    import subprocess
    import sys

    environment = {**os.environ, "PYTHONPATH": "src"}
    subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; from io import StringIO; "
            "from claasp.analysis.avalanche import AvalancheResult; "
            "AvalancheResult('example', 'plaintext', 2, 9, ((0.5,),)).to_terminal(file=StringIO()); "
            "assert not any(name in sys.modules for name in "
            "('matplotlib', 'numpy', 'pandas', 'tensorflow'))",
        ],
        env=environment,
        check=True,
    )
