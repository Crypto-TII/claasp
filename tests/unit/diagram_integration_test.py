import pytest
from claasp.cipher import Cipher
from claasp.diagrams import from_cipher,to_ascii,from_ascii,to_cipher,to_tikz,synthesis_report


@pytest.mark.parametrize('operation',['constant','explicit_modulus'])
def test_bundle_parameters_and_runtime_collision_preserve_complete_semantics(operation):
    name = 'constant_0_0' if operation=='constant' else 'modadd_0_0'
    width = 64 if operation=='constant' else 32
    c = Cipher('anonymous_combined_options','permutation',['safe_input','b'],[width,width],width)
    c.add_round()
    if operation=='constant':
        k = c.add_constant_component(width,0x8000000000000001)
        value = c.add_xor_component(['safe_input',k.id],[list(range(width))]*2,width)
    else:
        value = c.add_modadd_component(['safe_input','b'],[list(range(width))]*2,width,17)
    c.add_cipher_output_component([value.id],[list(range(width))],width)
    ir = from_cipher(c)
    mapping = {'safe_input':name, **{node['id']:f'original_node_{index}' for index,node in enumerate(ir['nodes'])}}
    ir['inputs'][0]['id'] = name
    for node in ir['nodes']:
        node['id'] = mapping[node['id']]
        for edge in node['operands']:
            edge['source'] = mapping.get(edge['source'],edge['source'])
    options = dict(annotations=True,native_bundles=True,parameter_refs=True)
    text = to_ascii(ir,**options)
    for _ in range(3):
        assert from_ascii(text)==ir
        assert to_ascii(from_ascii(text),**options)==text
    rebuilt = to_cipher(from_ascii(text))
    assert all(component.round==0 for component in rebuilt.all_components())
    assert len(set(rebuilt.diagram_source_ids.values()))==len(ir['inputs'])+len(ir['nodes'])
    for a,b in [(0,0),(16,1),(31,19),((1<<width)-1,1)]:
        expected = a^0x8000000000000001 if operation=='constant' else (a+b)%17
        assert rebuilt.evaluate([a,b])==expected
    assert synthesis_report(ir,native_bundles=True,parameter_refs=True)['packing_policy']=='native-bundles'
    assert r'\begin{tikzpicture}' in to_tikz(ir,layoutSource='human',native_bundles=True,parameter_refs=True)
    with pytest.raises(ValueError,match='human TikZ'):
        to_tikz(ir,layoutSource='audit',parameter_refs=True)
