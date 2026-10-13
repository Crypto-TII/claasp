"""Reproduce persistent vectors and explicit generic word-bank state views.
Usage: Sage-enabled python render_word_states.py OUTPUT_DIRECTORY
Requires pdflatex and pdftoppm on PATH. Inputs below are evaluation controls.
"""
import json
import pathlib
import re
import subprocess
import sys
from claasp.cipher import Cipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation
from claasp.diagrams import from_cipher, to_tikz, state_tikz, state_snapshots, evaluate_state_values

root = pathlib.Path(sys.argv[1]); root.mkdir(parents=True, exist_ok=True)
results = []

def render(name, fragment, width=29.7, height=21):
    (root/(name+'.tikz')).write_text(fragment)
    document = (r'\documentclass{article}\usepackage[T1]{fontenc}'
                +f'\\usepackage[paperwidth={width}cm,paperheight={height}cm,margin=1cm]{{geometry}}'
                +r'\usepackage{tikz}\pagestyle{empty}\begin{document}'
                +fragment+r'\end{document}')
    (root/(name+'.tex')).write_text(document)
    subprocess.run(['pdflatex','-no-shell-escape','-interaction=nonstopmode','-halt-on-error',name+'.tex'], cwd=root, check=True, stdout=subprocess.DEVNULL, timeout=60)
    subprocess.run(['pdftoppm','-scale-to','1400','-png',str(root/(name+'.pdf')),str(root/name)], check=True, timeout=60)
    log=(root/(name+'.log')).read_text()
    assert 'Overfull' not in log, name
    results.append({'case':name, 'rendered':True, 'overfull':0, 'panels':fragment.count('begin{tikzpicture}')})

for rounds in (1,2):
    cipher=SpeckBlockCipher(number_of_rounds=rounds);ir=from_cipher(cipher)
    values=evaluate_state_values(cipher,[0x6574694c,0x1918111009080100])
    for granularity in ('round','operation'):
        frames=state_snapshots(ir,mode='word',word_bits=None,values=values,granularity=granularity)
        (root/f'speck{rounds}-{granularity}.json').write_text(json.dumps(frames,indent=2))
        # Every operation fits with readable text across pages; round summary fits one page.
        fragment=state_tikz(ir,mode='word',word_bits=None,values=values,granularity=granularity,cell_width=1.8,page_breaks=False)
        render(f'speck{rounds}-{granularity}',fragment)
    for side in ('right','left'):
        render(f'speck{rounds}-{side}',to_tikz(ir,key_side=side,fitToPage=(25,18)))
cipher=ChachaPermutation(number_of_rounds=1);ir=from_cipher(cipher)
inputs=[int(''.join(f'{i:08x}' for i in range(16)),16)]
values=evaluate_state_values(cipher,inputs)
frames=state_snapshots(ir,mode='word',word_bits=None,columns=4,values=values)
(root/'chacha1-round.json').write_text(json.dumps(frames,indent=2))
render('chacha1-round',state_tikz(ir,mode='word',word_bits=None,columns=4,values=values,cell_width=1.8,page_breaks=False))
render('chacha1-overview',to_tikz(ir,fitToPage=(25,18)))
render('chacha1-panels',to_tikz(ir,pageBreaks=True),29.7,24)
for reverse in (False,True):
    cipher=Cipher('generic_order','block_cipher',['plaintext','key'],[8,8],8);cipher.add_round()
    operation=cipher.add_modsub_component(['key','plaintext'] if reverse else ['plaintext','key'],[list(range(8))]*2,8)
    cipher.add_cipher_output_component([operation.id],[list(range(8))],8)
    render('subtraction-'+str(int(reverse)),to_tikz(from_cipher(cipher)))
(root/'render-results.json').write_text(json.dumps(results,indent=2))
print(json.dumps(results,indent=2))
