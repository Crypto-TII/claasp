from claasp import InputVisibility, PrimitiveDetails, PrimitiveInputDetails
from claasp.primitives import AES, Speck


def test_aes_details_are_structured_and_readable():
    details = AES().details()

    assert isinstance(details, PrimitiveDetails)
    assert details.instance == "AES-128"
    assert details.number_of_rounds == 10
    assert details.realization == "lookup"
    assert details.output_bit_size == 128
    assert details.inputs == (
        PrimitiveInputDetails("plaintext", 128, "plaintext", InputVisibility.PUBLIC),
        PrimitiveInputDetails("key", 128, "key", InputVisibility.SECRET),
    )
    assert (
        str(details)
        == """Primitive details
  Type: block cipher
  Instance: AES-128
  Inputs:
    plaintext: 128 bits (public)
    key: 128 bits (secret)
  Output: 128 bits
  Rounds: 10
  Realization: lookup"""
    )


def test_details_identify_reduced_round_variant():
    details = Speck(64, 128, number_of_rounds=3).details()

    assert details.instance == "Speck64/128"
    assert details.number_of_rounds == 3
    assert tuple((item.name, item.bit_size) for item in details.inputs) == (
        ("plaintext", 64),
        ("key", 128),
    )
