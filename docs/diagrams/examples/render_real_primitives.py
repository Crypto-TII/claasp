"""Render three genuine primitive instances, ASCII results and native states.
Run with Sage-enabled Python and pdflatex/pdftoppm/pdfunite on PATH:
    python render_real_primitives.py OUTPUT_DIRECTORY
"""
import json
from pathlib import Path
import subprocess
import sys
from claasp.diagrams import Diagrams, from_ascii
from claasp.cipher_modules.diagram.word_visual import build
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.block_ciphers.simeck_block_cipher import SimeckBlockCipher
from claasp.ciphers.permutations.chaskeypi_permutation import ChaskeyPiPermutation

root=Path(sys.argv[1]);root.mkdir(parents=True,exist_ok=True)
results=[];documents=[]

def render(name, body):
    (root/(name+'.tex')).write_text(r'\documentclass{article}\usepackage[T1]{fontenc}'
        r'\usepackage[paperwidth=29.7cm,paperheight=42cm,margin=1cm]{geometry}'
        r'\usepackage{tikz}\pagestyle{empty}\begin{document}'+body+r'\end{document}')
    subprocess.run(['pdflatex','-no-shell-escape','-interaction=nonstopmode','-halt-on-error',name+'.tex'],
                   cwd=root,check=True,stdout=subprocess.DEVNULL,timeout=60)
    subprocess.run(['pdftoppm','-scale-to','1600','-png',str(root/(name+'.pdf')),str(root/name)],check=True,timeout=60)
    assert 'Overfull' not in (root/(name+'.log')).read_text(),name
    documents.append(str(root/(name+'.pdf')))


def printed_script(source):
    return r'\begin{verbatim}'+source+r'\end{verbatim}'

controls=[('simon1',SimonBlockCipher(block_bit_size=32,key_bit_size=64,number_of_rounds=1),
           'from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher\n'
           'cipher = SimonBlockCipher(block_bit_size=32,key_bit_size=64,number_of_rounds=1)',True,'declared'),
          ('simeck1',SimeckBlockCipher(block_bit_size=32,key_bit_size=64,number_of_rounds=1),
           'from claasp.ciphers.block_ciphers.simeck_block_cipher import SimeckBlockCipher\n'
           'cipher = SimeckBlockCipher(block_bit_size=32,key_bit_size=64,number_of_rounds=1)',True,'declared'),
          ('chaskey1',ChaskeyPiPermutation(number_of_rounds=1),
           'from claasp.ciphers.permutations.chaskeypi_permutation import ChaskeyPiPermutation\n'
           'cipher = ChaskeyPiPermutation(number_of_rounds=1)',False,'word')]
for name,cipher,constructor,routed,mode in controls:
    diagram=Diagrams(cipher);ir=diagram.ir
    options={'routed_words':True} if routed else {}
    model=build(ir,**options)
    plain=diagram.to_ascii(**options)
    annotated=diagram.to_ascii(annotations=True,**options)
    assert from_ascii(annotated)==ir
    (root/(name+'.asciiart')).write_text(plain)
    (root/(name+'-native.asciiart')).write_text(annotated)
    (root/(name+'-ir.json')).write_text(json.dumps(ir,indent=2))
    source=constructor+'\nfrom claasp.diagrams import Diagrams\ndiagram = Diagrams(cipher)\n'
    ascii_call='print(diagram.to_ascii(routed_words=True))' if routed else 'print(diagram.to_ascii())'
    render(name+'-ascii',r'\textbf{'+name+' ASCII result}'+printed_script(source+ascii_call)
           +r'\scriptsize\begin{verbatim}'+plain+r'\end{verbatim}')
    tikz=diagram.to_tikz(fitToPage=(25,30),**options)
    (root/(name+'.tikz')).write_text(tikz)
    call='print(diagram.to_tikz(routed_words=True, fitToPage=(25,30)))' if routed else 'print(diagram.to_tikz(fitToPage=(25,30)))'
    note=(r'C0,C1,... label native cipher words in declared order; D terminals carry display values. '
          r'ASCII native packing uses local annotations. No permutation operation or helper computation is inserted.') if routed else 'Existing default admission; all native operations retained.'
    caption=(r'\textbf{'+name+' persistent vector}'+printed_script(source+call)
             +f"Native rounds: {ir['rounds']}; compute operations: {len(model['records'])}; "
             +f"word width: {model['bits']}; grid: {model['rows']} rows by {model['columns']} columns. "+note)
    render(name+'-vector',caption+r'\par\medskip'+tikz)
    if routed:
        input_source="values_by_name = {'plaintext':0x6574694c,'key':0x1918111009080100}\ninputs = [values_by_name[name] for name in cipher.inputs]"
        by_name={'plaintext':0x6574694c,'key':0x1918111009080100}
        inputs=[by_name[n['id']] for n in ir['inputs']]
    else:
        input_source="inputs = [int(''.join(f'{i:08x}' for i in range(4)),16)]"
        inputs=[int(''.join(f'{i:08x}' for i in range(4)),16)]
    values=diagram.evaluate_state_values(inputs)
    frames=diagram.state_snapshots(mode=mode,word_bits=None,columns=2,values=values)
    (root/(name+'-states.json')).write_text(json.dumps(frames,indent=2))
    state_source=(source+input_source+'\nvalues = diagram.evaluate_state_values(inputs)\n'
                  +f"print(diagram.state_tikz(mode='{mode}', word_bits=None,\n"
                  +"    values=values, columns=2, columns_per_panel=2,\n"
                  +"    cell_width=1.8, page_breaks=False))")
    state=diagram.state_tikz(mode=mode,word_bits=None,values=values,columns=2,columns_per_panel=2,cell_width=1.8,page_breaks=False)
    (root/(name+'-states.tikz')).write_text(state)
    state_caption=r'\textbf{'+name+' evaluated native states}'+printed_script(state_source)
    if routed:
        frontier=diagram.state_tikz(mode='round',word_bits=None,values=values,columns=2,
                                    columns_per_panel=2,cell_width=1.8,page_breaks=False)
        frontier_source=state_source.replace("mode='declared'","mode='round'")
        frontier_note=(r'\textbf{Generic input/final dependency frontier}\par Full original inputs appear first; '
                       r'the final frame uses native cipher packing. This is a frontier, not an inferred matrix.')
        state_caption=frontier_note+printed_script(frontier_source)+frontier+r'\par\bigskip'+state_caption
    render(name+'-states',state_caption
           +(r'Original declared observation packing (including round-key observations where present). ' if routed else
             r'Initial state plus both native half-round boundaries; intra-round operations omitted. ')
           +r'Two columns are an explicit display arrangement, not an inferred matrix.\par\medskip'+state)
    counts={}
    for record in model['records']:
        op=record['definition']['description'][0];counts[op]=counts.get(op,0)+1
    results.append({'name':name,'constructor':constructor,'routed_words':routed,'state_mode':mode,
        'native_rounds':ir['rounds'],'native_nodes':len(ir['nodes']),'compute_operations':len(model['records']),
        'operations':counts,'input_bits':[n['bits'] for n in ir['inputs']],
        'output_bits':ir['output_bits'],'cipher_columns':model['cipher_columns'],
        'rows':model['rows'],'columns':model['columns'],'output':hex(diagram.to_cipher().evaluate(inputs)),
        'exact_fresh_ir':True,'state_frames':len(frames)})
(root/'results.json').write_text(json.dumps(results,indent=2))
subprocess.run(['pdfunite',*documents,str(root/'real-primitives-review.pdf')],check=True,timeout=30)
print(json.dumps(results,indent=2))
