from claasp.cipher import Cipher
from claasp.diagrams import *
import pathlib, copy
checks=0
for op in ['xor','and','or','modadd','modsub','modmul','not','reverse','rotate','shift']:
    for width in [1,4,8,17]:
        mask=(1<<width)-1
        for amount in ([0,1,width,width+1,-1,-width-1] if op in ['rotate','shift'] else [0]):
            c=Cipher('generic_contract','permutation',['a','b'],[width,width],width);c.add_round()
            unary=op in ['not','reverse','rotate','shift']
            ids=['a'] if unary else ['a','b'];positions=[list(range(width)) for _ in ids]
            args=[ids,positions,width]+([amount] if op in ['rotate','shift'] else [])
            n=getattr(c,f'add_{op}_component')(*args);c.add_cipher_output_component([n.id],[list(range(width))],width)
            rebuilt=to_cipher(from_ascii(to_ascii(from_cipher(c))))
            for a,b in [(0,0),(mask,1),(mask//3,mask//2),(1,mask)]:
                if op=='xor':expected=a^b
                elif op=='and':expected=a&b
                elif op=='or':expected=a|b
                elif op=='modadd':expected=(a+b)&mask
                elif op=='modsub':expected=(a-b)&mask
                elif op=='modmul':expected=(a*b)&mask
                elif op=='not':expected=(~a)&mask
                elif op=='reverse':expected=int(f'{a:0{width}b}'[::-1],2)
                elif op=='rotate':
                    k=amount%width;expected=((a>>k)|(a<<(width-k)))&mask
                elif op=='shift':expected=(a>>amount) if amount>=0 else (a<<(-amount))&mask
                assert rebuilt.evaluate([a,b])==expected,(op,width,amount,a,b)
                checks+=1
c=Cipher('mixed_selection','permutation',['named_data','named_key'],[8,4],8);c.add_round()
x=c.add_xor_component(['named_data','named_key'],[[0,2,5,7],[3,2,1,0]],4)
c.add_intermediate_output_component([x.id],[[0,1,2,3]],4,'explicit_state');c.add_round()
r=c.add_rotate_component([x.id],[[0,1,2,3]],4,-1)
c.add_cipher_output_component([r.id,x.id],[[0,1,2,3],[3,2,1,0]],8)
ir=from_cipher(c,roles={'named_data':'data','named_key':'key'});rebuilt=to_cipher(from_ascii(to_ascii(ir)))
def select(value,width,indices):
    result=0
    for i in indices:result=(result<<1)|((value>>(width-1-i))&1)
    return result
for a in range(256):
    for key in [0,1,7,15]:
        state=select(a,8,[0,2,5,7])^select(key,4,[3,2,1,0])
        expected=((((state<<1)|(state>>3))&15)<<4)|select(state,4,[3,2,1,0])
        assert rebuilt.evaluate([a,key])==expected
        assert rebuilt.evaluate([a,key],intermediate_output=True)==c.evaluate([a,key],intermediate_output=True)
        checks+=1
mutated=copy.deepcopy(ir);mutated['nodes'][0]['operands'][0]['positions']=[1,2,5,7]
assert to_cipher(mutated).evaluate([128,0])!=rebuilt.evaluate([128,0])
assert state_view(ir)[0]['geometry']=='ambiguous-flat-fallback'
try:state_view(ir,shape=[3,3]);raise AssertionError('invalid shape accepted')
except ValueError:pass
pathlib.Path('/tmp/claasp-diagrams-corpus/mixed_selection.asciiart').write_text(to_ascii(ir))
print(f'{checks} independent operations/width-boundary/mixed-selection checks passed; bit mutation changes computation')
# Known-answer vector transcribed from pinned develop's Speck unit test.
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
kat=to_cipher(from_ascii(to_ascii(from_cipher(SpeckBlockCipher()))))
assert kat.evaluate([0x6574694c,0x1918111009080100])==0xa86842f2
print('Full-round Speck32/64 pinned-repository known-answer vector passed')
