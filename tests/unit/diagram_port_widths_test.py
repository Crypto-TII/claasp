import json
import pytest
from claasp.cipher import Cipher
from claasp.diagrams import from_cipher,to_ascii,from_ascii,to_cipher
from claasp.cipher_modules.diagram.manual_blocks import MARKER


def circuit(operation='modsub'):
    c=Cipher('visible_logical_ports','permutation',['a'],[8],4)
    c.add_round();x=getattr(c,'add_'+operation+'_component')(['a'],[list(range(8))],4)
    c.add_cipher_output_component([x.id],[list(range(4))],4)
    return from_cipher(c)


@pytest.mark.parametrize('operation',['modsub','xor'])
def test_real_selected_port_widths_cannot_disagree_with_native_signature(operation):
    ir=circuit(operation);text=to_ascii(ir,annotations=True,native_bundles=True)
    body,encoded=text.split(MARKER);metadata=json.loads(encoded)
    definitions=[r['definition'] for r in metadata['records'] if r['definition']['kind']=='selection']
    left=next(d for d in definitions if d['positions']==[0,1,2,3]);right=next(d for d in definitions if d['positions']==[4,5,6,7])
    left['positions'].append(4);left['bits']=5
    right['positions'].pop(0);right['bits']=3
    # Original edge partition and flattened bit stream remain exactly unchanged.
    # Only actual typed connectivity is invalid:5+3 rather than declared4+4.
    with pytest.raises(ValueError,match='logical operand ports'):
        from_ascii(body+MARKER+json.dumps(metadata))


def test_original_edge_can_cross_logical_ports_without_changing_typed_widths():
    ir=circuit();text=to_ascii(ir,annotations=True,native_bundles=True)
    assert from_ascii(text)==ir
    rebuilt=to_cipher(from_ascii(text))
    for value in range(256):assert rebuilt.evaluate([value])==((value>>4)-(value&15))&15
