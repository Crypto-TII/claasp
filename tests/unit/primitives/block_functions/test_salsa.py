from claasp.primitives.block_functions.salsa import SalsaBlockFunction


def test_zero_key_nonce_and_counter_vector():
    block = SalsaBlockFunction()

    assert block.evaluate(key=0, nonce=0, counter=0) == int(
        "5bf6979a1b724c9b21670a96d4a8fc45"
        "f9672ee379a91e1126489ccee6ee6a80"
        "dac0e93d1ef9d72b9b63b2bc25c689f9"
        "38bf291bdc9b9ad34b5fc5e7392ac12a",
        16,
    )


def test_boundary_and_round_count_are_explicit():
    block = SalsaBlockFunction(number_of_rounds=2)

    assert tuple(block.graph.input_descriptors) == ("key", "nonce", "counter")
    assert block.kind.value == "block_function"
    assert len(block.graph.rounds) == 3
