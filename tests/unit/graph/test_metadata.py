import pytest

from claasp import (
    Bit,
    InputVisibility,
    Primitive,
    PrimitiveInput,
    PrimitiveKind,
    ValueType,
    public_input,
    secret_input,
)
from claasp.primitives import AES, Ascon
from claasp.primitives.block_ciphers.katan import Katan
from claasp.primitives.block_functions.siphash import SiphashMAC
from claasp.primitives.tweakable_block_ciphers.qarmav2 import QARMAv2


def test_input_descriptors_mark_keys_secret_without_changing_ports():
    aes = AES()
    assert aes.kind is PrimitiveKind.BLOCK_CIPHER
    assert aes.graph.secret_inputs == ("key",)
    assert aes.graph.input_descriptor("plaintext").visibility is InputVisibility.PUBLIC
    assert aes.graph.input_descriptor("key").role == "key"
    assert aes.graph.input_descriptor("key").value_type == aes.graph.input("key").value_type


def test_study_can_override_visibility_without_mutating_the_graph():
    aes = AES()
    public_key_study = aes.edit.with_input_visibility(key="public")
    assert aes.graph.input_descriptor("key").is_secret
    assert not public_key_study.graph.input_descriptor("key").is_secret
    assert public_key_study.graph.components == aes.graph.components
    assert public_key_study.graph.rounds == aes.graph.rounds
    with pytest.raises(KeyError, match="do not exist"):
        aes.edit.with_input_visibility(password="secret")


def test_explicit_descriptors_and_kinds_are_public_authoring_api():
    bit = ValueType(Bit(), (1,))
    primitive = Primitive(
        "keyed_bit_function",
        {"message": public_input(bit, role="message"), "mask": secret_input(bit, role="key")},
        kind=PrimitiveKind.BLOCK_FUNCTION,
    )
    assert primitive.graph.input_descriptors == {
        "message": PrimitiveInput(bit, "message", InputVisibility.PUBLIC),
        "mask": PrimitiveInput(bit, "key", InputVisibility.SECRET),
    }
    assert primitive.kind is PrimitiveKind.BLOCK_FUNCTION


def test_unkeyed_state_graphs_infer_permutation_kind():
    assert Ascon(number_of_rounds=1).kind is PrimitiveKind.PERMUTATION


def test_legacy_authored_graphs_map_to_semantic_v5_kinds():
    assert Katan(number_of_rounds=1).kind is PrimitiveKind.BLOCK_CIPHER
    assert (
        SiphashMAC(compression_rounds=1, finalization_rounds=1).kind is PrimitiveKind.BLOCK_FUNCTION
    )
    assert QARMAv2(number_of_rounds=1).kind is PrimitiveKind.TWEAKABLE_BLOCK_CIPHER
