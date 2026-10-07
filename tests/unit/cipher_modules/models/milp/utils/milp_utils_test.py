from claasp.cipher_modules.models.milp.utils.utils import _get_variables_value


def test_get_variables_value_reads_numbers_written_with_numerical_errors():
    # the keys map to the variables x_0, x_1, ... of Sage, written as x_1, x_2, ... in the solution files
    internal_variables = {f"variable_{index}": f"x_{index}" for index in range(7)}
    solution = "x_1 1\nx_2 1e-13\nx_3 -2e-13\nx_4 0.9999999\nx_5 2.0000001e+00\nx_6 500.00000000001\n"

    assert _get_variables_value(internal_variables, solution) == {
        "variable_0": 1.0,
        "variable_1": 0.0,
        "variable_2": 0.0,
        "variable_3": 1.0,
        "variable_4": 2.0,
        "variable_5": 500.0,
        "variable_6": 0.0,  # missing from the solution file
    }


def test_get_variables_value_reads_the_solution_files_of_the_external_solvers():
    internal_variables = {"a": "x_0", "b": "x_1"}
    # GLPK (glpsol --output) writes a table, in which "*" marks the basic variables
    glpk_solution = (
        "     1 x_1          *              1             0             1\n"
        "     2 x_2                         0             0             1\n"
    )
    assert _get_variables_value(internal_variables, glpk_solution) == {"a": 1.0, "b": 0.0}
    # CPLEX writes "display solution variables -"
    cplex_solution = "Variable Name           Solution Value\nx_1                           1.000000\n"
    assert _get_variables_value(internal_variables, cplex_solution) == {"a": 1.0, "b": 0.0}


def test_get_variables_value_keeps_the_first_value_of_each_variable():
    # e.g. HiGHS writes the primal values, then the dual values, of the same variables
    solution = "# Primal solution values\nx_1 1\ny_2 0\n# Dual solution values\nx_1 0\ny_2 1\n"
    assert _get_variables_value({"a": "x_0", "b": "x_1"}, solution) == {"a": 1.0, "b": 0.0}
