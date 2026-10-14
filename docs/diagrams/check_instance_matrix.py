"""Bounded ordinary catalog-instance matrix; no admission changes or fallback.
Run with Sage-enabled Python:
    python docs/diagrams/check_instance_matrix.py OUTPUT_DIRECTORY
Each valid case gets a fresh process and a 30-second upper execution bound.
Small local samples are not performance-tail guarantees or all-catalog coverage.
"""
import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

CASES=[
 ('speck2','block_ciphers.speck_block_cipher','SpeckBlockCipher',{'block_bit_size':32,'key_bit_size':64,'number_of_rounds':2}),
 ('chacha2','permutations.chacha_permutation','ChachaPermutation',{'number_of_rounds':2,'round_mode':'single'}),
 ('chaskey1','permutations.chaskeypi_permutation','ChaskeyPiPermutation',{'number_of_rounds':1}),
 ('simon2','block_ciphers.simon_block_cipher','SimonBlockCipher',{'block_bit_size':32,'key_bit_size':64,'number_of_rounds':2}),
 ('simon5','block_ciphers.simon_block_cipher','SimonBlockCipher',{'block_bit_size':32,'key_bit_size':64,'number_of_rounds':5}),
 ('simeck2','block_ciphers.simeck_block_cipher','SimeckBlockCipher',{'block_bit_size':32,'key_bit_size':64,'number_of_rounds':2}),
 ('alzette','permutations.alzette_permutation','AlzettePermutation',{}),
 ('sbox4','single_component_ciphers.sbox_cipher','SboxCipher',{'bit_size':4,'lookup_table':[12,5,6,11,9,0,10,13,3,14,15,8,4,7,1,2]}),
 ('linear4','single_component_ciphers.linear_layer_cipher','LinearLayerCipher',{'bit_size':4,'description':[[1,1,0,0],[0,1,1,0],[0,0,1,1],[1,0,0,0]]}),
 ('permutation8','single_component_ciphers.permutation_cipher','PermutationCipher',{'bit_size':8,'permutation_description':[7,6,5,4,3,2,1,0],'word_size':1}),
 ('aes1','block_ciphers.aes_block_cipher','AESBlockCipher',{'key_bit_size':128,'number_of_rounds':1}),
 ('present1','block_ciphers.present_block_cipher','PresentBlockCipher',{'key_bit_size':80,'number_of_rounds':1}),
 ('ascon1','permutations.ascon_permutation','AsconPermutation',{'number_of_rounds':1}),
 ('gimli1','permutations.gimli_permutation','GimliPermutation',{'number_of_rounds':1}),
 ('sha1r1','hash_functions.sha1_hash_function','SHA1HashFunction',{'word_size':32,'number_of_rounds':1}),
 ('sha256r1','hash_functions.sha2_hash_function','SHA2HashFunction',{'output_bit_size':256,'number_of_rounds':1}),
]
BOUNDS={'max_calls':512,'max_cells':20000,'max_grid_area':100000,'max_text_bytes':1000000}


def measured(action):
    start=time.perf_counter()
    try:
        value=action()
        result={'status':'supported','elapsed_seconds':round(time.perf_counter()-start,6)}
        if isinstance(value,str):result.update(bytes=len(value.encode()),sha256=hashlib.sha256(value.encode()).hexdigest())
        return result,value
    except (ValueError,TypeError,NotImplementedError) as error:
        message=str(error)
        status='budget_rejected' if any(word in message.lower() for word in ('bound','exceeds max','exceed max','exceed work')) else 'unsupported'
        return {'status':status,'reason':message,'exception':type(error).__name__,
                'elapsed_seconds':round(time.perf_counter()-start,6)},None
    except Exception as error:
        return {'status':'failed','reason':str(error),'exception':type(error).__name__,
                'elapsed_seconds':round(time.perf_counter()-start,6)},None


def one_case(case,output):
    from claasp.diagrams import Diagrams,from_ascii,to_cipher
    name,module,class_name,kwargs=case
    start=time.perf_counter();factory=getattr(importlib.import_module('claasp.ciphers.'+module),class_name)
    cipher=factory(**kwargs);diagram=Diagrams(cipher);ir=diagram.ir
    row={'case':name,'module':'claasp.ciphers.'+module,'class':class_name,'kwargs':kwargs,
         'native_rounds':ir['rounds'],'native_nodes':len(ir['nodes']),
         'input_bits':[n['bits'] for n in ir['inputs']],'output_bits':ir['output_bits'],
         'constructor_and_extraction_seconds':round(time.perf_counter()-start,6),'bounds':BOUNDS}
    inputs=[[0 for n in ir['inputs']],[(1<<n['bits'])-1 for n in ir['inputs']],
            [int('35'*((n['bits']+7)//8),16)&((1<<n['bits'])-1) for n in ir['inputs']]]
    native_result,outputs=measured(lambda:[cipher.evaluate(values) for values in inputs])
    row['native_evaluation']=native_result
    if outputs is None:return row
    row['native_outputs']=[hex(value) for value in outputs]
    reconstruction,restored=measured(lambda:diagram.to_cipher())
    if restored is not None:
        comparison,_=measured(lambda:check_outputs(restored,inputs,outputs))
        reconstruction['value_comparison']=comparison
    row['native_reconstruction']=reconstruction
    profiles={}
    for profile,routed in [('default',False),('routed',True)]:
        options=dict(BOUNDS,routed_words=routed)
        ascii_result,ascii_text=measured(lambda:diagram.to_ascii(**options))
        if ascii_text is not None:
            annotated_result,annotated=measured(lambda:diagram.to_ascii(annotations=True,**options))
            ascii_result['annotated_export']=annotated_result
            if annotated is not None:
                parsed_result,parsed=measured(lambda:from_ascii(annotated,max_text_bytes=BOUNDS['max_text_bytes'],max_grid_area=BOUNDS['max_grid_area']))
                if parsed is not None:
                    assert parsed==ir
                    parsed_result['exact_native_ir']=True
                    comparison,_=measured(lambda:check_outputs(to_cipher(parsed),inputs,outputs))
                    parsed_result['value_comparison']=comparison
                ascii_result['fresh_parse']=parsed_result
                (output/(name+'-'+profile+'.asciiart')).write_text(annotated)
            deterministic,_=measured(lambda:check_same(diagram.to_ascii(**options),ascii_text))
            ascii_result['same_process_determinism']=deterministic
        tikz_result,tikz=measured(lambda:diagram.to_tikz(**options,maxPanels=32))
        if tikz is not None:
            tikz_result['pictures']=tikz.count('begin{tikzpicture}')
            (output/(name+'-'+profile+'.tikz')).write_text(tikz)
        profiles[profile]={'ascii':ascii_result,'tikz':tikz_result}
    row['profiles']=profiles
    values_result,values=measured(lambda:diagram.evaluate_state_values(inputs[2]))
    row['state_value_evaluation']=values_result;states={}
    if values is not None:
        for mode in ('declared','round','word'):
            options={'mode':mode,'word_bits':None,'columns':4,'values':values}
            frames_result,frames=measured(lambda:diagram.state_snapshots(**options))
            if frames is not None:
                frames_result.update(frames=len(frames),words=sum(len(frame['words']) for frame in frames))
                final_words=frames[-1]['words']
                if mode=='word':final_words=[word for word in final_words if word.get('role')=='data']
                packed=0
                for word in final_words:packed=(packed<<frames[-1]['word_bits'])|word['value']
                assert len(final_words)*frames[-1]['word_bits']==ir['output_bits']
                assert packed==outputs[2]
                frames_result['final_native_output_agreement']=True
                if len(frames)>64 or sum(len(frame['words']) for frame in frames)>4096:
                    frames_result.update(status='budget_rejected',reason='Matrix state budget:64frames/4096words')
                    states[mode]={'snapshots':frames_result};continue
            ascii_result,ascii_state=measured(lambda:diagram.state_ascii(**options))
            tikz_result,tikz_state=measured(lambda:diagram.state_tikz(**options,max_panels=64))
            if tikz_state is not None and len(tikz_state.encode())>1000000:
                tikz_result.update(status='budget_rejected',reason='Matrix state byte budget 1MB')
            states[mode]={'snapshots':frames_result,'ascii':ascii_result,'tikz':tikz_result}
    row['states']=states
    return row


def check_outputs(cipher,inputs,expected):
    assert [cipher.evaluate(values) for values in inputs]==expected
    return True


def check_same(actual,expected):
    assert actual==expected
    return True


def main():
    parser=argparse.ArgumentParser();parser.add_argument('output',type=Path);parser.add_argument('--case')
    arguments=parser.parse_args();arguments.output.mkdir(parents=True,exist_ok=True)
    if arguments.case:
        case=next(case for case in CASES if case[0]==arguments.case)
        row=one_case(case,arguments.output)
        (arguments.output/(arguments.case+'.json')).write_text(json.dumps(row,indent=2))
        return
    rows=[]
    for case in CASES:
        start=time.perf_counter()
        try:
            result=subprocess.run([sys.executable,str(Path(__file__).resolve()),str(arguments.output),'--case',case[0]],
                capture_output=True,text=True,timeout=30,env=dict(os.environ))
            if result.returncode:
                row={'case':case[0],'status':'worker_failed','reason':result.stderr[-3000:]}
            else:row=json.loads((arguments.output/(case[0]+'.json')).read_text())
        except subprocess.TimeoutExpired:
            row={'case':case[0],'status':'time_budget_rejected','reason':'Normal case worker exceeded 30 seconds'}
        row['worker_elapsed_seconds']=round(time.perf_counter()-start,6);rows.append(row)
        print(case[0],row.get('status','completed'),flush=True)
    matrix={'scope':'16specified small valid catalog instances; no all-primitive claim, audit/legacy fallback or admission change',
            'bounds':BOUNDS,'worker_seconds':30,'vectors_per_case':3,'state_limits':{'frames':64,'words':4096,'bytes':1000000},
            'timing_scope':'One local sample per action including Python/native caching effects; not timing tails','cases':rows}
    (arguments.output/'matrix.json').write_text(json.dumps(matrix,indent=2))


if __name__=='__main__':main()
