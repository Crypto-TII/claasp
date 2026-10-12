import inspect,importlib,json,pathlib,random,time,argparse
from claasp.cipher import Cipher
from claasp.diagrams import from_cipher,to_audit_ascii,from_ascii,to_cipher,state_snapshots
parser=argparse.ArgumentParser();parser.add_argument('--output',type=pathlib.Path,required=True);out=parser.parse_args().output;out.mkdir(parents=True,exist_ok=True);rows=[];rng=random.Random(8102026)
mods=['permutations.chacha_permutation','permutations.keccak_permutation','permutations.xoodoo_sbox_permutation','block_ciphers.xtea_block_cipher','block_ciphers.skinny_block_cipher','block_ciphers.prince_block_cipher','block_ciphers.gift_block_cipher','hash_functions.sha1_hash_function','hash_functions.md5_hash_function','stream_ciphers.trivium_stream_cipher','permutations.tinyjambu_fsr_32bits_word_permutation']
for mod in mods:
 row={'module':mod};start=time.perf_counter()
 try:
  m=importlib.import_module('claasp.ciphers.'+mod);cls=next(c for _,c in inspect.getmembers(m,inspect.isclass) if c.__module__==m.__name__ and issubclass(c,Cipher));c=cls(**({'number_of_rounds':1} if 'number_of_rounds' in inspect.signature(cls).parameters else {}));row.update(name=cls.__name__,rounds=c.number_of_rounds,components=sum(len(r.components) for r in c.rounds_as_list));ir=from_cipher(c);text=to_audit_ascii(ir);back=from_ascii(text);assert back==ir;rebuilt=to_cipher(back)
  for _ in range(3):
   values=[rng.getrandbits(i['bits']) for i in ir['inputs']];assert c.evaluate(values,intermediate_output=True)==rebuilt.evaluate(values,intermediate_output=True)
  (out/(cls.__name__+'.asciiart')).write_text(text);row.update(status='passed',checks=3,bytes=len(text.encode()),state_frames=len(state_snapshots(ir)))
 except Exception as e:row.update(status='unsupported' if 'unsupported native' in str(e) else 'failed',error=str(e)[-1800:])
 row['seconds']=time.perf_counter()-start;rows.append(row);print(json.dumps(row),flush=True);(out/'report.json').write_text(json.dumps(rows,indent=2))
