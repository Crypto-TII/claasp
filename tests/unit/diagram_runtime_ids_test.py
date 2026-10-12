import copy
import pytest
from claasp.diagrams import to_cipher, evaluate_state_values


def graph(name='xor_0_0'):
    return {'schema':'claasp-diagrams/1','name':'anonymous_identity','cipher_type':'permutation','rounds':1,'output_bits':4,
            'inputs':[{'id':name,'bits':4,'role':'data'},{'id':'b','bits':4,'role':'key'}],
            'nodes':[{'id':'x','type':'word_operation','bits':4,'input_bits':8,'round':0,'description':['XOR',2],
                      'operands':[{'source':name,'positions':list(range(4))},{'source':'b','positions':list(range(4))}]},
                     {'id':'y','type':'word_operation','bits':4,'input_bits':8,'round':0,'description':['MODSUB',2,None],
                      'operands':[{'source':name,'positions':list(range(4))},{'source':'x','positions':list(range(4))}]},
                     {'id':'out','type':'cipher_output','bits':4,'input_bits':4,'round':0,'description':['cipher_output'],
                      'operands':[{'source':'y','positions':list(range(4))}]}]}


@pytest.mark.parametrize('name',['xor_0_0','modsub_0_1','cipher_output_0_2','not a Python identifier','class','λ','intermediate','cipher'])
def test_runtime_namespace_cannot_alias_a_valid_original_input(name):
    ir = graph(name);before = copy.deepcopy(ir);cipher = to_cipher(ir)
    assert ir == before
    assert len(set(cipher.diagram_source_ids.values())) == len(ir['inputs'])+len(ir['nodes'])
    assert all(component.round == 0 for component in cipher.all_components())
    assert cipher.diagram_input_roles[cipher.diagram_source_ids[name]] == 'data'
    for a in range(16):
        for b in range(16):
            assert cipher.evaluate([a,b]) == (a-(a^b))&15
    values = evaluate_state_values(cipher,[5,7])
    assert values[name] == 5 and values['x'] == 2 and values['y'] == 3 and values['out'] == 3


def test_collision_suffix_and_ordinary_input_names_are_preserved():
    ir = graph();ir['inputs'].append({'id':'xor__diagram0_0_0','bits':4,'role':'key'})
    cipher = to_cipher(ir)
    assert cipher.inputs == ['xor_0_0','b','xor__diagram0_0_0']
    assert cipher.diagram_source_ids['x'] == 'xor__diagram1_0_0'
    assert all(component.round == 0 for component in cipher.all_components())
    assert cipher.evaluate([5,7,15]) == 3


def test_collision_renaming_retains_rounds_used_by_inverse_placement():
    ir = {'schema':'claasp-diagrams/1','name':'anonymous_inverse_identity','cipher_type':'permutation','rounds':1,'output_bits':8,
          'inputs':[{'id':'rot_0_0','bits':8,'role':'data'}],
          'nodes':[{'id':'x','type':'word_operation','bits':8,'input_bits':8,'round':0,'description':['ROTATE',1],
                    'operands':[{'source':'rot_0_0','positions':list(range(8))}]},
                   {'id':'out','type':'cipher_output','bits':8,'input_bits':8,'round':0,'description':['cipher_output'],
                    'operands':[{'source':'x','positions':list(range(8))}]}]}
    rebuilt = to_cipher(ir)
    # Inverse round placement consumes Component.round; arbitrary input names
    # are outside the inverse module's admitted named-input vocabulary.
    for component in rebuilt.all_components():
        assert rebuilt.number_of_rounds-1-component.round == 0
    assert [component.round for component in rebuilt.all_components()] == [0,0]
