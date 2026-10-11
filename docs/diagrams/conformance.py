import json, pathlib, copy
from claasp.diagrams import *
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
from claasp.ciphers.permutations.ascon_permutation import AsconPermutation
from claasp.ciphers.permutations.gimli_permutation import GimliPermutation
out=pathlib.Path('/tmp/claasp-diagrams-corpus');out.mkdir(exist_ok=True)
rows=[]
import importlib, inspect
extra=[]
for module in ['block_ciphers.tea_block_cipher','block_ciphers.lea_block_cipher','block_ciphers.simeck_block_cipher','block_ciphers.cham_block_cipher','permutations.alzette_permutation','permutations.sparkle_permutation','hash_functions.sha2_hash_function','hash_functions.blake2_hash_function']:
    try:
        m=importlib.import_module('claasp.ciphers.'+module)
        extra.append(next(c for _,c in inspect.getmembers(m,inspect.isclass) if c.__module__==m.__name__ and issubclass(c,Cipher)))
    except Exception as error: rows.append({'module':module,'status':'import-failed','error':str(error)})
for cls in [SpeckBlockCipher,AESBlockCipher,SimonBlockCipher,PresentBlockCipher,AsconPermutation,GimliPermutation]+extra:
    row={'class':cls.__name__}
    try:
        c=cls(**({'number_of_rounds':2} if 'number_of_rounds' in inspect.signature(cls).parameters else {})); ir=from_cipher(c)
        text=to_ascii(ir); assert from_ascii(text)==ir
        (out/(cls.__name__+'.asciiart')).write_text(text)
        (out/(cls.__name__+'.tex')).write_text(to_tikz(ir,maxPanels=10000))
        rebuilt=to_cipher(from_ascii(text))
        checks=0
        for val in [0,1,0x123456789abcdef]:
            inputs=[val&((1<<i['bits'])-1) for i in ir['inputs']]
            assert c.evaluate(inputs, intermediate_output=True)==rebuilt.evaluate(inputs,intermediate_output=True)
            checks+=1
        assert layout(ir)==layout(ir)
        renamed=copy.deepcopy(ir); mapping={i['id']:f'v{x}' for x,i in enumerate(ir['inputs']+ir['nodes'])}
        for i in renamed['inputs']+renamed['nodes']: i['id']=mapping[i['id']]
        for n in renamed['nodes']:
            for e in n['operands']:e['source']=mapping[e['source']]
        assert list(layout(ir).values())==list(layout(renamed).values())
        row.update(status='passed',nodes=len(ir['nodes']),checks=checks,states=len(state_view(ir)))
    except Exception as e:row.update(status='failed',error=str(e))
    rows.append(row)
print(json.dumps(rows,indent=2));(out/'conformance.json').write_text(json.dumps(rows,indent=2))
