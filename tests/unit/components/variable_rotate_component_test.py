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
        for direction in (-2,-1,0,1,2):
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
                def value(bits):
                    return int(''.join(map(str,bits)),2)
                word,amount=value(solution.word),value(solution.amount)%width
                amount=(direction*amount)%width
                expected=(word>>amount)|(word<<(width-amount))
                assert value(solution.var_rot_0_0)==expected&((1<<width)-1)


def test_cp_variable_rotation_refuses_difference_as_value_fallback():
    import pytest
    component = make_variable_rotate_component()
    with pytest.raises(NotImplementedError,match='differential weights'):
        component.cp_xor_differential_propagation_constraints()


def test_vectorized_variable_rotation_matches_full_integer_amounts():
    import numpy as np
    from claasp.cipher import Cipher
    from claasp.cipher_modules.generic_functions_vectorized_bit import bit_vector_rotate_by_variable_amount
    for width,amount_width in [(4,3),(5,3),(5,70)]:
        words=list(range(1<<width))
        amounts=list(range(8)) if amount_width==3 else [0,(1<<69)+3,(1<<64)+7]
        pairs=[(word,amount) for word in words for amount in amounts]
        matrices=[np.frombuffer(b''.join(value.to_bytes((bits+7)//8,'big') for value in values),dtype=np.uint8).reshape(-1,(bits+7)//8).T.copy()
                  for values,bits in [( [p[0] for p in pairs],width),([p[1] for p in pairs],amount_width)]]
        bit_inputs=[np.unpackbits(matrix,axis=0)[-bits:] for matrix,bits in zip(matrices,[width,amount_width])]
        for direction in (-2,-1,0,1,2):
            cipher=Cipher('variable_rotation_vectors','block_cipher',['plaintext','key'],[width,amount_width],width)
            cipher.add_round()
            rotated=cipher.add_variable_rotate_component(['plaintext','key'],[list(range(width)),list(range(amount_width))],width,direction)
            cipher.add_cipher_output_component([rotated.id],[list(range(width))],width)
            byte_output=cipher.evaluate_vectorized(matrices)[-1]
            bit_output=bit_vector_rotate_by_variable_amount(bit_inputs,width,direction)
            for i,(word,amount) in enumerate(pairs):
                shift=(direction*amount)%width
                expected=((word>>shift)|(word<<(width-shift)))&((1<<width)-1)
                assert int.from_bytes(byte_output[i].tobytes(),'big')==expected
                assert int(''.join(map(str,bit_output[:,i])),2)==expected


def test_rc5_vectorized_empty_wires_and_variable_rotations():
    import numpy as np
    from claasp.ciphers.block_ciphers.rc5_block_cipher import RC5BlockCipher
    cipher=RC5BlockCipher(number_of_rounds=4)
    points=[(0,0),(0x0123456789abcdef,0x12345678),(0xffffffffffffffff,0xffffffff)]
    arrays=[np.frombuffer(b''.join(p[i].to_bytes(size,'big') for p in points),dtype=np.uint8).reshape(-1,size).T.copy()
            for i,size in enumerate([8,4])]
    output=cipher.evaluate_vectorized(arrays)[-1]
    assert [int.from_bytes(row.tobytes(),'big') for row in output]==[cipher.evaluate(list(p)) for p in points]


def test_vectorized_variable_rotation_rejects_missing_amount():
    import numpy as np
    import pytest
    from claasp.cipher_modules.generic_functions_vectorized_bit import bit_vector_rotate_by_variable_amount
    from claasp.cipher_modules.generic_functions_vectorized_byte import byte_vector_rotate_by_variable_amount
    with pytest.raises(ValueError,match='data and amount'):
        bit_vector_rotate_by_variable_amount([np.zeros((4,1),dtype=np.uint8)],4,1)
    with pytest.raises(ValueError,match='positive amount'):
        byte_vector_rotate_by_variable_amount([np.zeros((1,1),dtype=np.uint8)],4,1,0)


def test_variable_rotation_broadcasts_constant_operand():
    import numpy as np
    from claasp.cipher_modules.generic_functions_vectorized_bit import bit_vector_rotate_by_variable_amount
    word=np.array([[1],[0],[0],[0]],dtype=np.uint8)
    amounts=np.array([[0,0,1,1],[0,1,0,1]],dtype=np.uint8)
    output=bit_vector_rotate_by_variable_amount([word,amounts],4,1)
    assert [int(''.join(map(str,output[:,i])),2) for i in range(4)]==[8,4,2,1]
