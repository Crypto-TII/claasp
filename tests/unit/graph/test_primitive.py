from claasp import InputVisibility, PrimitiveDetails, PrimitiveInputDetails
from claasp.primitives import AES, AES128, CustomAES, Speck


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


def test_custom_aes_details_use_study_parameters():
    details = CustomAES(key_bit_size=256, number_of_rounds=5).details()

    assert details.instance == "CustomAES-256"
    assert details.number_of_rounds == 5
    assert tuple((item.name, item.bit_size) for item in details.inputs) == (
        ("plaintext", 128),
        ("key", 256),
    )


def test_instances_report_only_catalogue_approved_configurations():
    aes = AES(number_of_rounds=5)

    assert tuple(dict(item.values) for item in aes.instances) == (
        {"key_bit_size": 128, "number_of_rounds": 10},
        {"key_bit_size": 192, "number_of_rounds": 12},
        {"key_bit_size": 256, "number_of_rounds": 14},
    )
    assert "number_of_rounds=5" not in repr(aes.instances)
    assert "AES(key_bit_size=256, number_of_rounds=14)" in repr(aes.instances)
    assert AES128().instances == aes.instances


def test_parameters_reflect_the_public_constructor_signature():
    parameters = AES().parameters

    assert tuple(parameters) == ("key_bit_size", "number_of_rounds", "realization")
    assert parameters["key_bit_size"].default == 128
    assert parameters["number_of_rounds"].default is None
    assert "realization: str = 'lookup'" in repr(parameters)


def test_custom_parameters_abbreviate_large_defaults():
    assert "sbox_table: Iterable[int] = <tuple with 256 items>" in repr(CustomAES().parameters)
