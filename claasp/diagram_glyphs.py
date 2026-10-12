"""Native Python circuit glyphs: local definitions, visible dependencies.

The 5-by-11 cell grammar is shared with the web editor. Placement never uses
primitive names. This module has no external process or JavaScript dependency.
"""
import copy
import json
import re
from collections import Counter

MARKER = '\n# CLAASP-TYPED-GLYPH 1\n'
SIDES = ('left', 'top', 'right', 'bottom')
DELTA = {'left': (0,-1), 'right': (0,1), 'top': (-1,0), 'bottom': (1,0)}
OPPOSITE = {'left':'right','right':'left','top':'bottom','bottom':'top'}


def _center(text):
    if len(text)>7: raise ValueError('Glyph label exceeds seven characters')
    left=(7-len(text))//2
    return ' '*left+text+' '*(7-len(text)-left)


def _art(cell):
    kind, ports = cell['kind'], cell['ports']
    pipe=lambda active: '     |     ' if active else ' '*11
    border=lambda active: '  ___v___  ' if active else '  _______  '
    if kind in ('input','output','tap'):
        label=_center('I'+str(cell['index']+1)) if kind=='input' and not cell.get('unindexed') else '_______'
        return [pipe('top' in ports),border('top' in ports),
                ' '+('S' if cell.get('secret') else '|')+label+'| ',
                pipe('bottom' in ports),pipe('bottom' in ports)]
    if kind=='box':
        binding=_center('@21') if cell.get('reverse') else ' '*7
        label=_center(cell['tag'])
        return [border('top' in ports),' |'+binding+'| ',
                ('>' if ports.get('left')=='in' else ' ')+ '('+label+')'+('<' if ports.get('right')=='in' else ' '),
                ' |_______| ',pipe('bottom' in ports)]
    if cell.get('invisible'):
        middle=list(' '*11)
        vertical='top' in ports or 'bottom' in ports
        horizontal='left' in ports or 'right' in ports
        if horizontal and not vertical:middle=list('-'*11)
        elif vertical and not horizontal:middle[5]='|'
        else:
            if 'left' in ports:middle[:5]=list('-'*5)
            if 'right' in ports:middle[6:]=list('-'*5)
            middle[5]='o' if kind=='fork' else '+'
        return [pipe('top' in ports),pipe('top' in ports),''.join(middle),pipe('bottom' in ports),pipe('bottom' in ports)]
    # Visible wiring arrows make every route direction explicit.
    vertical='top' in ports or 'bottom' in ports
    horizontal='left' in ports or 'right' in ports
    middle=list(' |       | ')
    if vertical and not horizontal:middle[5]='|'
    elif horizontal and not vertical:
        for i in range(2,9):middle[i]='-'
    else:
        if 'left' in ports:
            for i in range(2,5):middle[i]='-'
        if 'right' in ports:
            for i in range(6,9):middle[i]='-'
        middle[5]='o' if kind=='fork' else '+'
    for side,index in [('left',0),('right',10)]:
        if side in ports:middle[index]=('>' if side=='left' else '<') if ports[side]=='in' else '-'
    bottom=list(' |_______| ')
    if 'bottom' in ports:bottom[5]='|'
    return [border('top' in ports), ' |'+('   |   ' if 'top' in ports else ' '*7)+'| ',
            ''.join(middle),''.join(bottom),pipe('bottom' in ports)]


def _graph(ir, *, port_selections=False, parallel=False):
    calls=[]; values={}; source_offsets={}; inputs=[]; serial=0
    def call(prefix,args,definition):
        nonlocal serial
        alphabet='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';n=serial; digits=''
        for _ in range(3):digits=alphabet[n%36]+digits;n//=36
        if n:raise ValueError('Typed glyph alias capacity exceeded')
        serial+=1;tag=prefix+digits
        index=len(calls);calls.append({'args':args,'definition':dict(copy.deepcopy(definition),tag=tag),'tag':tag,'bits':definition['bits']})
        return ('call',index)
    def width(value):return ir['inputs'][value[1]]['bits'] if value[0]=='input' else calls[value[1]]['bits']
    joined={}
    def join(parts):
        if len(parts)==1:return parts[0]
        middle=(len(parts)+1)//2;left=join(parts[:middle]);right=join(parts[middle:])
        key=(left,right)
        if port_selections and key in joined:return joined[key]
        result=call('JN',[left,right],{'kind':'join','bits':width(left)+width(right)})
        if port_selections:joined[key]=result
        return result
    for index,item in enumerate(ir['inputs']):
        v=('input',index);inputs.append(v);values[item['id']]=v
    selections={}; targets=[];cursor=0
    def signature(node):
        if node['type'] in ('constant','intermediate_output','cipher_output') or any(edge['source'] not in values for edge in node['operands']):return None
        return (node['type'],node['bits'],node['input_bits'],node['round'],json.dumps(node['description']),tuple(dict.fromkeys(values[e['source']] for e in node['operands'])))
    while cursor<len(ir['nodes']):
        node=ir['nodes'][cursor];members=[(cursor,node)];key=signature(node) if parallel else None;cursor+=1
        if key is not None:
            while cursor<len(ir['nodes']) and signature(ir['nodes'][cursor])==key:
                members.append((cursor,ir['nodes'][cursor]));cursor+=1
        args=[];offsets={};offset=0;definitions=[]
        for ordinal,node in members:
            local_positions=[]
            for edge in node['operands']:
                value=values[edge['source']]
                if port_selections:
                    if value not in offsets:
                        offsets[value]=offset;offset+=width(value);args.append(value)
                    local_positions.append([offsets[value]+source_offsets.get(edge['source'],0)+p for p in edge['positions']])
                else:
                    positions=edge['positions']
                    if positions!=list(range(width(value))):
                        key=(value,tuple(positions))
                        if key not in selections:selections[key]=call('BS',[value],{'kind':'selection','bits':len(positions),'positions':positions})
                        value=selections[key]
                    args.append(value)
            definition={k:copy.deepcopy(v) for k,v in node.items() if k!='operands'}
            definition['ordinal']=ordinal
            if port_selections and local_positions:definition['operand_positions']=local_positions
            definitions.append(definition)
        if len(args)>2:
            middle=(len(args)+1)//2;args=[join(args[:middle]),join(args[middle:])]
        prefix=re.sub('[^A-Za-z]','',node['description'][0] if node['type']=='word_operation' else node['type'])[:2].upper().ljust(2,'N')
        if len(definitions)>1:
            value=call('G'+prefix[0],args,{'kind':'parallel','bits':sum(d['bits'] for d in definitions),'members':definitions})
        else:value=call(prefix,args,dict(definitions[0],kind='native'))
        output_offset=0
        for _,node in members:
            values[node['id']]=value;source_offsets[node['id']]=output_offset;output_offset+=node['bits']
            if node['type'] in ('intermediate_output','cipher_output'):targets.append(value)
    # All native components and declared inputs stay observable, including
    # otherwise unreachable values. No original graph is embedded in metadata.
    consumed={v for c in calls for v in c['args']}
    for value in inputs+[('call',i) for i in range(len(calls))]:
        if value not in consumed and value not in targets:targets.append(value)
    return inputs,calls,targets


def _build_grid(ir, *, strategy='semantic-legacy', max_cells=1000000, max_calls=20000):
    if strategy not in ('semantic-legacy','direct-bus','semantic-ports','semantic-parallel','semantic-round'):raise ValueError('Unknown native layout strategy')
    if type(max_cells) is not int or max_cells<=0 or type(max_calls) is not int or max_calls<=0:raise ValueError('Invalid native work bounds')
    if len(ir['nodes'])>max_calls:raise ValueError('Native component count exceeds max_calls')
    if sum(i['bits'] for i in ir['inputs'])+sum(n['bits']+sum(len(e['positions']) for e in n['operands']) for n in ir['nodes'])>2000000:raise ValueError('Native explicit bit expansion exceeds bound')
    inputs,calls,targets=_graph(ir,port_selections=strategy in ('semantic-ports','semantic-parallel','semantic-round'),parallel=strategy in ('semantic-parallel','semantic-round'))
    if len(calls)>max_calls:raise ValueError('Native operation expansion exceeds max_calls')
    consumers={}
    for index,operation in enumerate(calls):
        for value in set(operation['args']):consumers.setdefault(value,[]).append(index)
    scheduling_rounds={}
    for index in reversed(range(len(calls))):
        definition=calls[index]['definition']
        if definition['kind']=='native':rank=definition['round']
        elif definition['kind']=='parallel':rank=min(member['round'] for member in definition['members'])
        else:rank=min((scheduling_rounds[j] for j in consumers.get(('call',index),[])),default=ir['rounds'])
        scheduling_rounds[index]=rank
    uses=Counter(v for c in calls for v in c['args']);uses.update(targets)
    slots={v:i for i,v in enumerate(inputs)};active=set(slots.values());cells={};row=0;maximum=len(inputs)-1
    def place(col,kind,ports,**data):
        key=(row,col)
        if len(cells)>=max_cells:raise ValueError('Native routing exceeds max_cells')
        if key in cells:raise ValueError('Native routing collision')
        cells[key]=dict(kind=kind,ports=ports,**data)
    def fill(occupied):
        for col in sorted(active-occupied):place(col,'wire',{'top':'in','bottom':'out'})
    def free(near=0):
        nonlocal maximum
        candidates=[c for c in range(maximum+2) if c not in active]
        col=min(candidates,key=lambda c:(abs(c-near),c)) if strategy!='direct-bus' else maximum+1
        maximum=max(maximum,col);return col
    def horizontal(source,target,keep):
        side='right' if source<target else 'left'
        ports={'top':'in',side:'out'}
        if keep:ports['bottom']='out'
        place(source,'fork' if keep else 'wire',ports)
        for col in range(min(source,target)+1,max(source,target)):
            ports={'left':'in','right':'out'} if side=='right' else {'right':'in','left':'out'}
            if col in active:ports.update(top='in',bottom='out')
            place(col,'cross' if col in active else 'wire',ports)
        return 'left' if side=='right' else 'right'
    for value in inputs:
        item=ir['inputs'][value[1]];place(slots[value],'input',{'bottom':'out'},index=value[1],secret=item['role']=='key',definition=dict(item,kind='input',index=value[1]))
    row+=1
    pending=set(range(len(calls)));observers=set(targets)
    while pending:
        ready=[i for i in sorted(pending) if all(v in slots for v in calls[i]['args'])]
        # Delay constants until another operand of a consumer is available.
        usable=[i for i in ready if calls[i]['args'] or ('call',i) in observers or any(j in pending and all(v==('call',i) or v in slots for v in calls[j]['args']) for j in consumers.get(('call',i),[]))]
        if not usable:
            # Two ready constants may each await the other's consumer input.
            # Break only that scheduling stall with the first ready source.
            if ready:usable=[ready[0]]
            else:raise ValueError('No progress in native live-register scheduling')
        i=min(usable,key=lambda index:((scheduling_rounds[index] if strategy=='semantic-round' else 0),calls[index]['definition']['kind']!='join',index)) if strategy in ('semantic-ports','semantic-parallel','semantic-round') else usable[0];call=calls[i];args=call['args'];old=[slots[v] for v in args]
        replacement=0;copied=False
        if not args:target=free()
        elif strategy!='direct-bus' and uses[args[0]]==1:target=old[0]
        elif len(args)==2 and strategy!='direct-bus' and uses[args[1]]==1 and args[0]!=args[1]:replacement=1;target=old[1]
        else:
            target=free(old[0]);copied=True
            keep_first=uses[args[0]]>1
            side=horizontal(old[0],target,keep_first)
            place(target,'wire',{side:'in','bottom':'out'});fill(set(range(min(old[0],target),max(old[0],target)+1)))
            row+=1
            if not keep_first:active.discard(old[0])
            active.add(target)
        if len(args)==2:
            source=old[1-replacement]
            keep=uses[args[1-replacement]]>args.count(args[1-replacement])
            # A copied first operand remains live across this routing row.
            side=horizontal(source,target,keep)
            logical_physical=[1-replacement,replacement] if side=='left' else [replacement,1-replacement]
            ports={'top':'in',side:'in','bottom':'out'}
            place(target,'box',ports,tag=call['tag'],definition=call['definition'],reverse=logical_physical!=[0,1])
            fill(set(range(min(source,target),max(source,target)+1)))
        else:
            place(target,'box',dict({'top':'in'} if args else {},bottom='out'),tag=call['tag'],definition=call['definition'])
            fill({target})
        row+=1;pending.remove(i)
        for value in args:
            uses[value]-=1
            if not uses[value]:active.discard(slots.pop(value))
        value=('call',i);slots[value]=target;active.add(target)
        if value in observers:
            uses[value]-=1;keep=uses[value]>0
            place(target,'tap' if keep else 'output',dict(top='in',**({'bottom':'out'} if keep else {})))
            fill({target});row+=1
            if not keep:active.discard(target);slots.pop(value)
    # Unused input observations are sinks, preserving every declared input.
    for value in inputs:
        if value in observers and value in slots:
            target=slots.pop(value);place(target,'output',{'top':'in'});fill({target});row+=1;active.discard(target)
    if active:raise ValueError('Uncaptured native values remain live')
    if strategy!='direct-bus':cells=compact_tracks(cells,max_cells=max_cells)
    return cells,{'rows':max(r for r,c in cells)+1,'cols':max(c for r,c in cells)+1,'blocks':len(cells),'pattern':'live-register-program','strategy':strategy}


def build_grid(ir, *, strategy='semantic-auto', max_cells=1000000, max_calls=20000):
    if strategy!='semantic-auto':return _build_grid(ir,strategy=strategy,max_cells=max_cells,max_calls=max_calls)
    candidates=[];errors=[]
    for variant in ('semantic-legacy','semantic-ports','semantic-parallel','semantic-round'):
        try:
            cells,report=_build_grid(ir,strategy=variant,max_cells=max_cells,max_calls=max_calls)
            cost=(report['rows']*report['cols']+report['blocks'],report['rows']*report['cols'],report['blocks'])
            candidates.append((cost,len(candidates),cells,report))
        except ValueError as error:errors.append(str(error))
    if not candidates:raise ValueError('; '.join(errors))
    _,_,cells,report=min(candidates,key=lambda item:item[:2]);report=dict(report,selectedVariant=report['strategy'],strategy='semantic-auto')
    return cells,report


def compact_tracks(cells, *, max_cells=1000000):
    """Preserve rigid horizontal segments and per-column boundary order."""
    rows={}
    for (r,c),cell in sorted(cells.items()):
        if cell['kind']=='wire' and cell['ports']=={'top':'in','bottom':'out'}:continue
        rows.setdefault(r,[]).append((c,cell))
    out={};last={}
    for items in rows.values():
        groups=[]
        for c,cell in items:
            previous=groups[-1][-1] if groups else None
            if previous and previous[0]+1==c and ('right' in previous[1]['ports'] or 'left' in cell['ports']):groups[-1].append((c,cell))
            else:groups.append([(c,cell)])
        for group in groups:
            target=max((last.get(c,(-1,None))[0]+1 for c,cell in group),default=0)
            for c,cell in group:
                prior=last.get(c)
                if prior and prior[1]['ports'].get('bottom')=='out' and cell['ports'].get('top')=='in':
                    for r in range(prior[0]+1,target):out[(r,c)]={'kind':'wire','ports':{'top':'in','bottom':'out'}}
                out[(target,c)]=copy.deepcopy(cell);last[c]=(target,cell)
                if len(out)>max_cells:raise ValueError('Compacted routing exceeds max_cells')
    return out


def render_grid(cells,dimensions):
    records=[];lines=[]
    for r in range(dimensions['rows']):
        art=[_art(cells[(r,c)]) if (r,c) in cells else [' '*11]*5 for c in range(dimensions['cols'])]
        lines.extend(''.join(a[y] for a in art) for y in range(5))
    for (r,c),cell in sorted(cells.items()):
        if 'definition' in cell:records.append({'row':r,'col':c,'definition':copy.deepcopy(cell['definition'])})
    return '\n'.join(lines),records


def encode(ir, *, strategy='semantic-auto', max_cells=1000000,
           max_calls=20000, max_grid_area=2000000, max_text_bytes=64000000):
    if any(type(v) is not int or v<=0 for v in (max_grid_area,max_text_bytes)):
        raise ValueError('Invalid native output bounds')
    cells,dimensions=build_grid(ir,strategy=strategy,max_cells=max_cells,max_calls=max_calls)
    area=dimensions['rows']*dimensions['cols']
    if area>max_grid_area:raise ValueError('Native rectangular grid exceeds max_grid_area')
    records=[{'row':r,'col':c,'definition':copy.deepcopy(cell['definition'])}
             for (r,c),cell in sorted(cells.items()) if 'definition' in cell]
    primitive={k:copy.deepcopy(v) for k,v in ir.items() if k not in ('inputs','nodes')}
    footer=json.dumps({'primitive':primitive,'records':records},separators=(',',':'))
    # The full rectangle includes blank cells, not just occupied glyphs.
    estimated_bytes=area*55+dimensions['rows']*5-1+len(MARKER)+len(footer.encode('utf8'))+1
    if estimated_bytes>max_text_bytes:raise ValueError('Native glyph export exceeds max_text_bytes')
    text,_=render_grid(cells,dimensions)
    return text+MARKER+footer+'\n'


def _wire_templates():
    result={}
    routes=[{'top':'in','bottom':'out'},{'left':'in','right':'out'},{'right':'in','left':'out'}]
    for side in ('left','right'):
        routes.extend([{'top':'in',side:'out'},{side:'in','bottom':'out'},{'top':'in',side:'out','bottom':'out'}])
    for side in ('left','right'):routes.append({'top':'in','bottom':'out',side:'in',OPPOSITE[side]:'out'})
    for ports in routes:
        kind='cross' if len(ports)==4 else 'fork' if len(ports)==3 else 'wire'
        for invisible in (False,True):
            cell={'kind':kind,'ports':ports,'invisible':invisible};result.setdefault(tuple(_art(cell)),[]).append(cell)
    return result


def decode(text, *, max_text_bytes=64000000, max_grid_area=2000000):
    if len(text.encode('utf8'))>max_text_bytes:raise ValueError('Glyph text exceeds max_text_bytes')
    if text.count(MARKER)!=1:raise ValueError('Invalid typed glyph framing')
    drawing,footer=text.split(MARKER);manifest=json.loads(footer);records={}
    if set(manifest)!={'primitive','records'}:raise ValueError('Unexpected glyph metadata')
    if len(manifest['records'])>20000:raise ValueError('Glyph definitions exceed work bound')
    native_count=0;bit_expansion=0
    for record in manifest['records']:
        definition=record['definition'];kind=definition.get('kind')
        members=definition.get('members') if kind=='parallel' else [definition] if kind=='native' else []
        if not isinstance(members,list) or kind=='parallel' and not members:raise ValueError('Invalid parallel members')
        native_count+=len(members)
        if native_count>20000:raise ValueError('Aggregate native component count exceeds work bound')
        if kind=='input':bit_expansion+=definition.get('bits',2000001)
        for member in members:
            if not isinstance(member,dict) or any(type(member.get(field)) is not int or member[field]<0 for field in ('bits','input_bits')):raise ValueError('Invalid native bit expansion')
            bit_expansion+=member['bits']+member['input_bits']
        if bit_expansion>2000000:raise ValueError('Aggregate native explicit bit expansion exceeds bound')
    for record in manifest['records']:
        key=(record['row'],record['col']);d=record['definition']
        if any(type(x) is not int or x<0 for x in key):raise ValueError('Invalid glyph anchor')
        if type(d.get('bits')) is not int or not 0<d['bits']<=2000000:raise ValueError('Local bit width exceeds work bound')
        fields={'input':{'kind','index','id','bits','role'},'native':{'kind','ordinal','id','type','bits','input_bits','round','description','tag','operand_positions'},'parallel':{'kind','bits','tag','members'},'selection':{'kind','bits','positions','tag'},'join':{'kind','bits','tag'}}
        if key in records or set(d)-fields.get(d.get('kind'),set()):raise ValueError('Duplicate or hidden dependency record')
        records[key]=d
    lines=drawing.split('\n');rows=(len(lines)+4)//5;cols=(max(map(len,lines),default=0)+10)//11;cells={};templates=_wire_templates();choices={}
    if len(lines)%5:raise ValueError('Glyph line count must be a multiple of five')
    if rows*cols>max_grid_area:raise ValueError('Glyph grid exceeds max_grid_area')
    for r in range(rows):
        for c in range(cols):
            art=tuple((lines[r*5+y] if r*5+y<len(lines) else '').ljust(cols*11)[c*11:(c+1)*11] for y in range(5))
            if all(not line.strip() for line in art):continue
            d=records.get((r,c))
            if d and d.get('kind')=='input':
                cell={'kind':'input','ports':{'bottom':'out'},'index':d['index'],'secret':d['role']=='key','definition':d,'unindexed':art[2][2:9]=='_______'}
            elif d:
                if d.get('kind') not in ('native','parallel','selection','join'):raise ValueError('Unknown local glyph definition')
                if art[2][2:9].strip()!=d.get('tag'):raise ValueError('Operation alias disagrees with visible box')
                ports={'bottom':'out'}
                if art[0][5]=='v':ports['top']='in'
                if art[2][0]=='>':ports['left']='in'
                if art[2][10]=='<':ports['right']='in'
                binding=art[1][2:9].strip()
                if binding not in ('','@21'):raise ValueError('Malformed operand binding')
                cell={'kind':'box','ports':ports,'tag':d['tag'],'reverse':binding=='@21','definition':d}
            elif art in templates:
                choices[(r,c)]=copy.deepcopy(templates[art]);cell=choices[(r,c)][0]
            else:
                cell=None
                for kind in ('output','tap'):
                    candidate={'kind':kind,'ports':dict(top='in',**({'bottom':'out'} if kind=='tap' else {}))}
                    if tuple(_art(candidate))==art:cell=candidate;break
                if cell is None:raise ValueError(f'Unknown or malformed glyph at {r}:{c}')
            if tuple(_art(cell))!=art:raise ValueError(f'Glyph definition contradicts visible text at {r}:{c}')
            cells[(r,c)]=cell
    if set(records)-set(cells):raise ValueError('Local definition lacks a visible box')
    # Borderless horizontal routes encode geometry but not arrow direction.
    # Resolve only directions forced by adjacent input/output ports; ambiguity
    # is exposed instead of choosing a convenient hidden dependency.
    alternatives={key:choices.get(key,[cell]) for key,cell in cells.items()}
    changed=True
    while changed:
        changed=False
        for key,variants in list(alternatives.items()):
            supported=[]
            for variant in variants:
                ok=True
                for side,direction in variant['ports'].items():
                    dr,dc=DELTA[side];neighbors=alternatives.get((key[0]+dr,key[1]+dc),[])
                    if not any(n['ports'].get(OPPOSITE[side])==('in' if direction=='out' else 'out') for n in neighbors):ok=False;break
                if ok:supported.append(variant)
            if not supported:raise ValueError(f'Disconnected or reversed port at {key}')
            if len(supported)!=len(variants):alternatives[key]=supported;changed=True
    for key,variants in alternatives.items():
        if len(variants)!=1:raise ValueError(f'Ambiguous wire direction at {key}')
        cells[key]=variants[0]
    # Every active port must meet the opposite directed port of its neighbor.
    for (r,c),cell in cells.items():
        for side,direction in cell['ports'].items():
            dr,dc=DELTA[side];other=cells.get((r+dr,c+dc))
            if not other or other['ports'].get(OPPOSITE[side])!=('in' if direction=='out' else 'out'):raise ValueError(f'Disconnected or reversed port at {r}:{c}:{side}')
    from collections import deque
    native={};memo={};dependencies={};followers={}
    def adjacent(key,side):
        dr,dc=DELTA[side];return ((key[0]+dr,key[1]+dc),OPPOSITE[side])
    for key,cell in cells.items():
        for side,direction in cell['ports'].items():
            if direction!='out':continue
            token=(key,side);kind=cell['kind']
            if kind=='input':ins=[]
            elif kind=='box':
                ins=[s for s in SIDES if cell['ports'].get(s)=='in']
                if cell.get('reverse'):
                    if len(ins)!=2:raise ValueError('Operand permutation requires two inputs')
                    ins.reverse()
            elif kind=='cross':ins=['top' if side=='bottom' else 'left' if side=='right' else 'right']
            else:
                ins=[s for s,direction in cell['ports'].items() if direction=='in']
                if len(ins)!=1:raise ValueError('Ambiguous wire source')
            dependencies[token]=[adjacent(key,side) for side in ins]
            for dep in set(dependencies[token]):followers.setdefault(dep,[]).append(token)
    remaining={token:len(set(deps)) for token,deps in dependencies.items()}
    ready=deque(token for token,count in remaining.items() if count==0)
    while ready:
        token=ready.popleft();key,side=token;cell=cells[key];kind=cell['kind'];d=cell.get('definition')
        args=[memo[dep] for dep in dependencies[token]]
        if kind=='input':stream=[{'source':d['id'],'positions':list(range(d['bits']))}]
        elif kind=='box':
            if d['kind']=='selection':
                flat=[(e['source'],b) for a in args for e in a for b in e['positions']]
                if len(args)!=1 or not flat or len({s for s,b in flat})!=1 or any(type(i) is not int or i<0 or i>=len(flat) for i in d['positions']):raise ValueError('Invalid visible selection width')
                if len(d['positions'])!=d['bits']:raise ValueError('Selection width mismatch')
                stream=[{'source':flat[0][0],'positions':[flat[i][1] for i in d['positions']]}]
            elif d['kind']=='join':
                if len(args)!=2:raise ValueError('Join needs two ordered inputs')
                stream=[e for a in args for e in a]
                if sum(len(e['positions']) for e in stream)!=d['bits']:raise ValueError('Join width mismatch')
            else:
                definitions=d['members'] if d['kind']=='parallel' else [d]
                if not isinstance(definitions,list) or not definitions or len(definitions)>20000:raise ValueError('Invalid parallel members')
                if any(not isinstance(item,dict) or type(item.get('bits')) is not int or not 0<item['bits']<=d['bits'] for item in definitions):raise ValueError('Invalid parallel member width')
                if sum(item['bits'] for item in definitions)!=d['bits']:raise ValueError('Parallel output width mismatch')
                flat=[(e['source'],bit) for incoming in args for e in incoming for bit in e['positions']]
                stream=[]
                for definition in definitions:
                    allowed={'id','type','bits','input_bits','round','description','ordinal','operand_positions'}
                    if d['kind']=='parallel' and set(definition)-allowed:raise ValueError('Hidden dependency in parallel operation')
                    node={k:copy.deepcopy(definition[k]) for k in ('id','type','bits','input_bits','round','description')};node['operands']=[e for a in args for e in a]
                    if 'operand_positions' in definition:
                        maps=definition['operand_positions']
                        if not isinstance(maps,list):raise ValueError('Invalid local operand positions')
                        operands=[]
                        for positions in maps:
                            if not isinstance(positions,list) or not positions or any(type(p) is not int or p<0 or p>=len(flat) for p in positions):raise ValueError('Invalid local operand positions')
                            selected=[flat[p] for p in positions]
                            if len({source for source,bit in selected})!=1:raise ValueError('One native operand must select a single visible value')
                            operands.append({'source':selected[0][0],'positions':[bit for source,bit in selected]})
                        if sum(len(e['positions']) for e in operands)!=definition['input_bits']:raise ValueError('Local operand positions disagree with input width')
                        node['operands']=operands
                    ordinal=definition.get('ordinal')
                    if type(ordinal) is not int or ordinal<0 or ordinal in native:raise ValueError('Invalid or duplicate native ordinal')
                    native[ordinal]=node;stream.append({'source':definition['id'],'positions':list(range(definition['bits']))})
                if sum(len(e['positions']) for e in stream)!=d['bits']:raise ValueError('Parallel output width mismatch')
        else:stream=args[0]
        memo[token]=stream
        for following in followers.get(token,[]):
            remaining[following]-=1
            if not remaining[following]:ready.append(following)
    if len(memo)!=len(dependencies):raise ValueError('Circular visible routing')
    for key,cell in cells.items():
        if cell['kind'] in ('output','tap') and adjacent(key,'top') not in memo:raise ValueError('Unresolved visible output')
    if any(not any((key,side) in memo for side in cell['ports'] if cell['ports'][side]=='out') for key,cell in cells.items() if key in records):raise ValueError('Unobserved annotated operation')
    inputs=[d for d in records.values() if d.get('kind')=='input'];inputs.sort(key=lambda d:d['index'])
    if [d['index'] for d in inputs]!=list(range(len(inputs))):raise ValueError('Invalid input ordering')
    if sorted(native)!=list(range(len(native))):raise ValueError('Missing native execution ordinal')
    return dict(manifest['primitive'],inputs=[{k:d[k] for k in ('id','bits','role')} for d in inputs],nodes=[native[i] for i in sorted(native)])


def tikz(ir, **options):
    from claasp.diagram_presentation import operation as readable_operation, parameter_registry, present
    view=options.get('view','overview-detail');legend_mode=options.get('legend','readable')
    if view not in ('overview','detail','overview-detail','wires') or legend_mode not in ('readable','audit','none'):raise ValueError('Invalid TikZ presentation mode')
    registry={key:value[0] for key,value in parameter_registry(ir).items()}
    cells,dimensions=build_grid(ir,strategy=options.get('strategy','semantic-auto'))
    xs=options.get('columnSpacing',3);ys=options.get('rowSpacing',1)
    if not isinstance(xs,(int,float)) or xs<=0 or not isinstance(ys,(int,float)) or ys<=0:raise ValueError('Invalid TikZ spacing')
    nr=options.get('rowsPerPanel',16);nc=options.get('columnsPerPanel',6);maximum=options.get('maxPanels',256)
    if any(type(x) is not int or x<=0 for x in (nr,nc,maximum)):raise ValueError('Invalid TikZ pagination')
    def crop(key,size):
        value=options.get(key,[0,size])
        if not isinstance(value,(list,tuple)) or len(value)!=2 or any(type(x) is not int for x in value) or not 0<=value[0]<value[1]<=size:raise ValueError('Invalid TikZ crop range')
        return value
    top,bottom=crop('rowRange',dimensions['rows']);left,right=crop('columnRange',dimensions['cols'])
    escape=lambda s:''.join({'_':r'\_','%':r'\%','&':r'\&','#':r'\#','{':r'\{','}':r'\}','\\':r'\textbackslash{}','$':r'\$','^':r'\textasciicircum{}','~':r'\textasciitilde{}'}.get(c,c) for c in str(s))
    def wrapped(value):
        text=json.dumps(value,separators=(',',':'))
        return r'\allowbreak{}'.join(escape(text[i:i+6]) for i in range(0,len(text),6))
    groups={}
    for (r,c),cell in sorted(cells.items()):
        if top<=r<bottom and left<=c<right:groups.setdefault(((r-top)//nr,(c-left)//nc),[]).append((r,c,cell))
    if view=='wires' and len(groups)>maximum:raise ValueError(f'TikZ needs {len(groups)} panels; crop or increase maxPanels')
    panels=[]
    for (pr,pc),items in sorted(groups.items()):
        rt=top+pr*nr;cl=left+pc*nc;lines=[r'\begin{tikzpicture}[>=stealth]'];legend=[];drawings=[]
        for r,c,cell in items:
            x=(c-cl)*xs;y=-(r-rt)*ys;key=f'D{r}:{c}';ports=cell['ports'];kind=cell['kind']
            if kind in ('input','box','output','tap'):
                definition=cell.get('definition',{})
                if kind=='input':label=('key' if cell.get('secret') else 'input')+'/'+str(definition.get('bits','?'))
                elif definition.get('kind')=='parallel':
                    first=definition['members'][0]
                    operation=first['description'][0] if first['type']=='word_operation' else first['type'].upper()
                    label=readable_operation(first,registry,short=True)+' x'+str(len(definition['members']))
                elif definition.get('kind')=='native':
                    description=definition.get('description',[])
                    operation=description[0] if definition.get('type')=='word_operation' else {'cipher_output':'OUT','intermediate_output':'OBSERVE','constant':'CONST'}.get(definition.get('type'),definition.get('type',''))
                    label=str(operation)+'/'+str(definition.get('bits','?'))
                    if definition.get('type') not in ('cipher_output','intermediate_output'):
                        label=readable_operation(definition,registry,short=True)
                elif definition.get('kind') in ('join','selection'):label={'join':'PACK','selection':'SELECT'}[definition['kind']]+'/'+str(definition['bits'])
                else:label=kind
                if cell.get('reverse'):label+=r'\\@21'
                if 'definition' in cell:label+=r'\\'+key;legend.append((key,cell['definition']))
                lines.append(fr'\node[draw,align=center,minimum width=12mm,minimum height=4mm,font=\scriptsize] (N{r}x{c}) at ({x},{y}) {{{escape(label).replace(escape(chr(92)*2),chr(92)*2)}}};')
            if kind=='box':
                ordered=[side for side in SIDES if ports.get(side)=='in']
                if cell.get('reverse'):ordered.reverse()
                for number,side in enumerate(ordered,1):
                    anchor={'left':'south east','right':'south west','top':'south east','bottom':'north west'}[side]
                    port={'left':'west','right':'east','top':'north','bottom':'south'}[side]
                    lines.append(fr'\node[font=\scriptsize,inner sep=2pt,anchor={anchor}] at (N{r}x{c}.{port}) {{{number}}};')
            # A crossing has distinct horizontal/vertical routes; no junction
            # dot is drawn. Arrow endpoints retain each port's direction.
            for side,direction in ports.items():
                if direction!='out':continue
                dr,dc=DELTA[side];nx=x+dc*xs;ny=y-dr*ys
                port={'left':'west','right':'east','top':'north','bottom':'south'}
                source=f'(N{r}x{c}.{port[side]})' if kind in ('input','box','output','tap') else f'({x},{y})'
                neighbor=cells.get((r+dr,c+dc),{})
                inside=rt<=r+dr<min(rt+nr,bottom) and cl<=c+dc<min(cl+nc,right)
                target=f'(N{r+dr}x{c+dc}.{port[OPPOSITE[side]]})' if inside and neighbor.get('kind') in ('input','box','output','tap') else f'({nx},{ny})'
                drawings.append(fr'\draw[->] {source} -- {target};')
        lines.extend(drawings)
        lines.append(r'\end{tikzpicture}')
        panels.append('\n'.join(lines))
    return present(ir,cells,dimensions,panels,options)
