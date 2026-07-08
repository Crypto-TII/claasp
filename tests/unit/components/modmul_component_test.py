from claasp.components.modmul_component import ModMul


def test_modmul_component_creation():
    component = ModMul(
        current_round_number=1,
        current_round_number_of_components=0,
        input_id_links=["input1", "input2"],
        input_bit_positions=[[0, 1, 2, 3], [0, 1, 2, 3]],
        output_bit_size=4,
        modulus=16
    )
    
    assert component.id == "modmul_1_0"
    assert component.type == "word_operation"
    assert component.input_bit_size == 8
    assert component.output_bit_size == 4
    
    # Check evaluation string mapping based on the vector eval implementations
    bit_eval = component.get_bit_based_vectorized_python_code(["a", "b"], False)
    assert bit_eval == ["  modmul_1_0 = bit_vector_MODMUL([a,b ], 2, 4)"]
    
    byte_eval = component.get_byte_based_vectorized_python_code(["a", "b"])
    assert byte_eval == ["  modmul_1_0 = byte_vector_MODMUL(['a', 'b'])"]
