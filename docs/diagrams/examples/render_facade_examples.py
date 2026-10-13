"""Reproduce the public facade examples and a source/result review PDF.
Sage-enabled python render_facade_examples.py OUTPUT_DIRECTORY
Requires pdflatex, pdftoppm and pdfunite on PATH. No renderer code names a cipher.
"""
import json
from pathlib import Path
import subprocess
import sys
from quarter_round import quarter_round
from claasp.diagrams import Diagrams, from_ascii
from claasp.cipher_modules.diagram.word_visual import build
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation
from claasp.ciphers.single_component_ciphers.rotate_cipher import RotateCipher
from claasp.ciphers.single_component_ciphers.shift_cipher import ShiftCipher
from claasp.ciphers.single_component_ciphers.not_cipher import NotCipher

root=Path(sys.argv[1]);root.mkdir(parents=True,exist_ok=True)
results=[]

def render(name, fragment, caption, width=29.7, height=42):
    (root/(name+'.tikz')).write_text(fragment)
    document=(r'\documentclass{article}\usepackage[T1]{fontenc}'
              f'\\usepackage[paperwidth={width}cm,paperheight={height}cm,margin=1cm]{{geometry}}'
              r'\usepackage{tikz}\pagestyle{empty}\begin{document}'
              +caption+r'\par\medskip'+fragment+r'\end{document}')
    (root/(name+'.tex')).write_text(document)
    subprocess.run(['pdflatex','-no-shell-escape','-interaction=nonstopmode','-halt-on-error',name+'.tex'],cwd=root,check=True,stdout=subprocess.DEVNULL,timeout=60)
    subprocess.run(['pdftoppm','-scale-to','1600','-png',str(root/(name+'.pdf')),str(root/name)],check=True,timeout=60)
    assert 'Overfull' not in (root/(name+'.log')).read_text(),name


def export(name, cipher, constructor, inputs, views=True):
    diagram=Diagrams(cipher)
    ir=diagram.ir
    model=build(ir,parallel_unary=4)
    text=diagram.to_ascii(parallel_unary=4,annotations=True)
    assert from_ascii(text)==ir
    (root/(name+'.asciiart')).write_text(text)
    (root/(name+'.json')).write_text(json.dumps(ir,indent=2))
    rotations=[record for record in model['records'] if record['definition']['description'][0]=='ROTATE']
    cohort_rows=sorted({record['row'] for record in rotations})
    result={'name':name,'constructor':constructor,'input_bits':[n['bits'] for n in ir['inputs']],
            'roles':[n['role'] for n in ir['inputs']], 'native_rounds':ir['rounds'],
            'compute_operations':len(model['records']),'rows':model['rows'],'columns':model['columns'],
            'rotation_cohorts':[{'row':row,'count':sum(r['row']==row for r in rotations)} for row in cohort_rows],
            'output':hex(diagram.to_cipher().evaluate(inputs)),'exact_fresh_native_ir':True}
    results.append(result)
    caption=(r'\textbf{'+name.replace('-',' ')+r'}\par\begin{verbatim}'
             +'\n'+constructor+'\nfrom claasp.diagrams import Diagrams\ndiagram = Diagrams(cipher)\n'
             +'diagram.to_tikz(parallel_unary=4, fitToPage=(25,30))\n'
             +r'\end{verbatim}'
             +f"Native stages: {ir['rounds']}; compute operations: {len(model['records'])}; "
             +f"word lanes: {model['columns']}. Original inputs and direct routes are retained; no presentation permutation nodes.")
    render(name+'-overview',diagram.to_tikz(parallel_unary=4,fitToPage=(25,30)),caption, height=21 if not views else 42)
    if views:
        render(name+'-detail',diagram.to_tikz(parallel_unary=4,pageBreaks=True),caption)
        values=diagram.evaluate_state_values(inputs)
        states=diagram.state_snapshots(mode='word',word_bits=None,values=values,columns=4)
        (root/(name+'-states.json')).write_text(json.dumps(states,indent=2))
        render(name+'-states',diagram.state_tikz(mode='word',word_bits=None,values=values,columns=4,columns_per_panel=4,cell_width=1.8,page_breaks=False),
               r'\textbf{All native half-round boundaries}\par Round summary; intra-round operations omitted. Four columns are an explicit display annotation; no matrix is inferred.',width=21,height=29.7)
    return diagram

quarter_inputs=[int('11111111010203049b8d6f4301234567',16)]
quarter=export('quarter-round',quarter_round(),'from quarter_round import quarter_round\ncipher = quarter_round() # four 32-bit words; rotations 16,12,8,7',quarter_inputs,False)
full=export('chacha-two-full-rounds',ChachaPermutation(number_of_rounds=2,round_mode='single'),
            "from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation\ncipher = ChachaPermutation(number_of_rounds=2, round_mode='single')",[int(''.join(f'{i:08x}' for i in range(16)),16)])
assert results[-1]['compute_operations']==96
assert [cohort['count'] for cohort in results[-1]['rotation_cohorts']]==[4]*8
assert len(full.state_snapshots(mode='word',word_bits=None))==5
# Small admitted primitives demonstrate facade reuse without claiming broad family coverage.
fragments=[]
for cipher,constructor in [(RotateCipher(bit_size=32,rotation_amount=7),'RotateCipher(bit_size=32,rotation_amount=7)'),
                           (ShiftCipher(bit_size=32,shift_amount=7),'ShiftCipher(bit_size=32,shift_amount=7)'),
                           (NotCipher(bit_size=32),'NotCipher(bit_size=32)')]:
    diagram=Diagrams(cipher)
    assert from_ascii(diagram.to_ascii(annotations=True))==diagram.ir
    fragments.append(r'\begin{verbatim}'+constructor+r'\end{verbatim}'+diagram.to_tikz()+r'\par\bigskip')
render('additional-primitives','\n'.join(fragments),r'\textbf{Admitted single-component primitives}\par Native Rotate, Shift and Not examples. These are primitive controls, not full-cipher coverage.',height=21)
(root/'results.json').write_text(json.dumps(results,indent=2))
subprocess.run(['pdfunite',*[str(root/(name+'.pdf')) for name in ('quarter-round-overview','chacha-two-full-rounds-overview','chacha-two-full-rounds-detail','chacha-two-full-rounds-states','additional-primitives')],str(root/'facade-review.pdf')],check=True,timeout=30)
print(json.dumps(results,indent=2))
