"""Exhaustive function equivalence of generic addition normalization."""
import pytest
from claasp.cipher import Cipher
from claasp.cipher_modules.graph_normalization import binary_modadd_copy


@pytest.mark.parametrize('operands',[3,4])
def test_binary_addition_preserves_fragmented_repeated_wiring(operands):
    c=Cipher('normalize','permutation',['plaintext'],[4],2)
    c.add_round()
    inputs=[[3,0],[1,2],[0,3],[2,1]][:operands]
    addition=c.add_modadd_component(['plaintext']*operands,inputs,2)
    c.add_cipher_output_component([addition.id],[[0,1]],2)
    original=c.as_python_dictionary()
    normalized=binary_modadd_copy(c)
    assert c.as_python_dictionary()==original
    assert addition.id in normalized.all_components_ids()
    assert len(set(normalized.all_components_ids()))==len(normalized.all_components_ids())
    for x in range(16):
        assert c.evaluate([x])==normalized.evaluate([x])
    assert all(comp.description[1]==2 for comp in normalized.all_components()
               if comp.type=='word_operation' and comp.description[0]=='MODADD')


def test_normalization_rejects_nonword_modulus():
    c=Cipher('normalize','permutation',['plaintext'],[6],2);c.add_round()
    component=c.add_modadd_component(['plaintext'],[list(range(6))],2,3)
    c.add_cipher_output_component([component.id],[[0,1]],2)
    with pytest.raises(NotImplementedError,match='modulus'):
        binary_modadd_copy(c)
