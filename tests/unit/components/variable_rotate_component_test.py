from claasp.components.variable_rotate_component import VariableRotate


def make_variable_rotate_component(direction=1):
    return VariableRotate(0, 0, ["plaintext", "key"], [list(range(8)), list(range(3))], 8, direction)


def test_constructor_sets_variable_rotate_identity():
    variable_rotate_component = make_variable_rotate_component(direction=1)

    assert variable_rotate_component.id == "var_rot_0_0"
    assert variable_rotate_component.type == "word_operation"
    assert variable_rotate_component.input_bit_size == 11
    assert variable_rotate_component.output_bit_size == 8
    assert variable_rotate_component.description == ["ROTATE_BY_VARIABLE_AMOUNT", 1]


def test_get_word_based_c_code_direction():
    variable_rotate_component = make_variable_rotate_component(direction=1)
    code_lines = variable_rotate_component.get_word_based_c_code(False, 8, [])

    assert code_lines[0] == "\tinput -> list = (Word[]) {plaintext -> list[0], key -> list[0]};"
    assert code_lines[1] == "\tinput -> string_size = 2;"
    assert code_lines[2] == "\tWordString *var_rot_0_0 = RIGHT_ROTATE_BY_VARIABLE_AMOUNT(input);"


def test_get_word_operation_sign_updates_solution():
    variable_rotate_component = make_variable_rotate_component(direction=-1)
    solution = {
        "components_values": {
            "var_rot_0_0_i": {"value": "00"},
            "var_rot_0_0_o": {"value": "ff"},
        }
    }
    sign = variable_rotate_component.get_word_operation_sign(-1, solution)

    assert sign == -1
    assert "var_rot_0_0_i" not in solution["components_values"]
    assert "var_rot_0_0_o" not in solution["components_values"]
    assert solution["components_values"]["var_rot_0_0"]["value"] == "ff"
    assert solution["components_values"]["var_rot_0_0"]["sign"] == 1


def test_cp_variable_rotation_exhaustive_values():
    """All words and amounts, both directions, including non-power-of-two width."""
    from minizinc import Instance, Model, Solver
    for width in (4,5):
        for direction in (-1,1):
            component=VariableRotate(0,0,['word','amount'],[list(range(width)),[0,1,2]],width,direction)
            declarations,equations=component.cp_constraints()
            model=Model()
            model.add_string('\n'.join([
                f'array[0..{width-1}] of var 0..1: word;',
                'array[0..2] of var 0..1: amount;',
                f'array[0..{width-1}] of var 0..1: var_rot_0_0;',
                *declarations,*equations,'solve satisfy;']))
            result=Instance(Solver.lookup('gecode'),model).solve(all_solutions=True)
            assert len(result.solution)==(1<<width)*8
            for solution in result.solution:
                value=lambda bits:int(''.join(map(str,bits)),2)
                word,amount=value(solution.word),value(solution.amount)%width
                expected=((word>>amount)|(word<<(width-amount))) if direction==1 else ((word<<amount)|(word>>(width-amount)))
                assert value(solution.var_rot_0_0)==expected&((1<<width)-1)


def test_cp_variable_rotation_refuses_difference_as_value_fallback():
    import pytest
    with pytest.raises(NotImplementedError,match='differential weights'):
        make_variable_rotate_component().cp_xor_differential_propagation_constraints()
