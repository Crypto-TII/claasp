// Native-bit semantics in real editable glyph grids. The annotation footer
// contains per-box definitions and input identities, NEVER original edges.
// Every dependency is recovered by tracing the visible ports and wires.
import {Grid} from './grid.js';
import {defaultParams} from './blockCatalog.js';
import {renderGrid} from './render.js';
import {decodeGrid} from './decode.js';
import {gridToPseudocode,parseDeclarations,parseAssignments,buildGraph} from './pseudocode.js';
import {graphToGridDirectBus} from './layout/strategies/direct-bus.js';
import {graphToGridConservative} from './layout/strategies/conservative-bus.js';
import {validateTypedDiagram} from './typedDiagram.js';
import {checkConnectivity} from './connectivity.js';
export const TYPED_GLYPH_MARKER='\n# CLAASP-TYPED-GLYPH 1\n';
const clone=value=>JSON.parse(JSON.stringify(value));
// Editing secrecy changes the declared role in the same undoable transaction.
export function synchronizeTypedInputRole(params) {
  if(params.typed?.kind!=='input')return params;
  const role=params.secrecy==='secret'?'key':params.typed.role==='key'?'data':params.typed.role;
  return {...params,typed:{...params.typed,role}};
}
function assertVisibleInputRoles(grid) {
  for(const b of grid.allBlocks().filter(b=>b.type==='input'&&b.params.typed))
    if(Boolean(b.params.typed.role==='key')!==Boolean(b.params.secrecy==='secret'))
      throw new Error('Visible input secrecy disagrees with typed role; apply the input role edit before exporting');
}
export function typedIrToGrid(ir,{diagnostics={}}={}) {
  validateTypedDiagram(ir);
  const annotations=new Map(), values=new Map();let serial=0;
  const call=(prefix,args,definition)=> {
    if(serial>=36**3)throw new Error('Typed glyph alias capacity exceeded');
    const tag=prefix+String((serial++).toString(36).toUpperCase()).padStart(3,'0');
    const record={...clone(definition),tag};annotations.set(tag,record);
    return {kind:'call',typeName:'typedbox',params:{...defaultParams('typedbox'),text:tag,arity:args.length},args};
  };
  ir.inputs.forEach((i,index)=>values.set(i.id,{kind:'input',name:`input[${index+1}]`,secret:i.role==='key'}));
  const bitSize=value=>value.kind==='input'?ir.inputs[Number(/\[(\d+)\]/.exec(value.name)[1])-1].bits:annotations.get(value.params.text).bits;
  const targets=[];
  for(const [ordinal,n] of ir.nodes.entries()) {
    const fragments=n.operands.map(edge=> {
      const source=values.get(edge.source);if(!source)throw new Error('Unknown typed dependency');
      if(edge.positions.length===bitSize(source)&&edge.positions.every((p,i)=>p===i))return source;
      return call('BS',[source],{kind:'selection',bits:edge.positions.length,positions:edge.positions});
    });
    // Balanced ordered stream assembly limits helper depth. A native box
    // consumes up to two visible ordered fragments directly; larger streams
    // use binary joins without changing native operand/bit ordering.
    const join=parts=> {
      if(parts.length===1)return parts[0];
      const middle=Math.ceil(parts.length/2),left=join(parts.slice(0,middle)),right=join(parts.slice(middle));
      return call('JN',[left,right],{kind:'join',bits:bitSize(left)+bitSize(right)});
    };
    const nativeArgs=fragments.length<=2?fragments:[join(fragments.slice(0,Math.ceil(fragments.length/2))),join(fragments.slice(Math.ceil(fragments.length/2)))];
    const prefix=(n.type==='word_operation'?String(n.description[0]):n.type).replace(/[^A-Za-z]/g,'').slice(0,2).toUpperCase().padEnd(2,'N');
    const value=call(prefix,nativeArgs,{kind:'native',ordinal,id:n.id,type:n.type,bits:n.bits,input_bits:n.input_bits,round:n.round,description:n.description});
    values.set(n.id,value);
    if(['intermediate_output','cipher_output'].includes(n.type))targets.push({name:`output[${targets.length+1}]`,node:value,isOutput:true});
  }
  // Keep otherwise unreachable native operations and unused declared inputs
  // visible as observation taps, without adding executable native components.
  const reachable=new Set();const collect=n=>{if(reachable.has(n))return;reachable.add(n);if(n.args)n.args.forEach(collect);};
  targets.forEach(t=>collect(t.node));
  for(const value of values.values())if(!reachable.has(value)){targets.push({name:`output[${targets.length+1}]`,node:value,isOutput:true});collect(value);}
  let grid;
  try{grid=graphToGridDirectBus(targets,{diagnostics});}
  catch(error){diagnostics.directError=error.message;grid=graphToGridConservative(targets,{diagnostics});}
  if(!checkConnectivity(grid).wellConnected)throw new Error('Typed glyph routing failed connectivity');
  const inputs=grid.allBlocks().filter(b=>b.type==='input').sort((a,b)=>a.row-b.row||a.col-b.col);
  if(inputs.length!==ir.inputs.length)throw new Error('Unused or omitted declared inputs need explicit glyph support');
  inputs.forEach((b,index)=>b.params.typed={kind:'input',index,...clone(ir.inputs[index])});
  for(const b of grid.allBlocks().filter(b=>b.type==='typedbox')) {
    const definition=annotations.get(b.params.text);if(!definition)throw new Error('Unknown typed operation alias');
    b.params.typed=clone(definition);
  }
  const header={schema:ir.schema,name:ir.name,cipher_type:ir.cipher_type,output_bits:ir.output_bits,rounds:ir.rounds};
  const finalBox=grid.allBlocks().find(b=>b.params.typed?.type==='cipher_output');
  if(!finalBox)throw new Error('Missing native final output');finalBox.params.typedPrimitive=header;
  return grid;
}
export function renderTypedGlyph(grid) {
  assertVisibleInputRoles(grid);
  const headers=grid.allBlocks().map(b=>b.params.typedPrimitive).filter(Boolean);
  if(headers.length!==1)throw new Error('Typed export requires exactly one primitive; separate merged diagrams before exporting');
  const primitive=headers[0];
  if(!primitive)throw new Error('Missing typed primitive definition');
  const records=grid.allBlocks().filter(b=>b.params.typed).map(b=>({row:b.row,col:b.col,definition:{...clone(b.params.typed),...(b.type==='typedbox'?{tag:b.params.text}:{})}}));
  return renderGrid(grid)+TYPED_GLYPH_MARKER+JSON.stringify({primitive,records})+'\n';
}
export function parseTypedGlyph(text) {
  const parts=text.split(TYPED_GLYPH_MARKER);if(parts.length!==2)throw new Error('Invalid typed glyph framing');
  const grid=decodeGrid(parts[0]);const manifest=JSON.parse(parts[1]);
  const seen=new Set();
  for(const record of manifest.records) {
    const b=grid.getBlockAt(record.row,record.col);const key=`${record.row},${record.col}`;
    if(!b||b.row!==record.row||b.col!==record.col||seen.has(key))throw new Error('Typed annotation has no unique visible box');
    seen.add(key);const d=record.definition;
    if(d.kind==='input'&&b.type!=='input'||d.kind!=='input'&&(b.type!=='typedbox'||b.params.text!==d.tag))throw new Error('Typed annotation disagrees with visible box');
    if(d.kind==='input'&&Boolean(d.role==='key')!==Boolean(b.params.secrecy==='secret'))throw new Error('Visible input secrecy disagrees with typed role');
    if('operands' in d||'source' in d||'nodes' in d)throw new Error('Original edges are forbidden in typed annotations');
    b.params.typed=clone(d);
  }
  const typedBoxes=grid.allBlocks().filter(b=>['typedbox','input'].includes(b.type));
  if(typedBoxes.some(b=>!b.params.typed))throw new Error('Every typed input/operation requires a visible definition');
  const final=typedBoxes.find(b=>b.params.typed?.type==='cipher_output');if(!final)throw new Error('Missing typed cipher output');
  final.params.typedPrimitive=clone(manifest.primitive);
  typedGridToIr(grid);return grid;
}
export function typedGridToIr(grid) {
  assertVisibleInputRoles(grid);
  const boxes=grid.allBlocks();const headers=boxes.map(b=>b.params.typedPrimitive).filter(Boolean);
  if(headers.length!==1)throw new Error('Typed export requires exactly one primitive; separate merged diagrams before exporting');
  const primitive=headers[0];
  if(!primitive)throw new Error('No typed primitive metadata');
  const inputs=boxes.filter(b=>b.type==='input').sort((a,b)=>a.row-b.row||a.col-b.col).map(b=>b.params.typed);
  if(inputs.some(i=>!i))throw new Error('Missing explicit input widths/identities');
  const definitions=new Map(boxes.filter(b=>b.type==='typedbox').map(b=>[b.params.text,b.params.typed]));
  if(definitions.size!==boxes.filter(b=>b.type==='typedbox').length||[...definitions.values()].some(d=>!d))throw new Error('Duplicated alias or missing typed operation');
  const code=gridToPseudocode(grid),parsed=parseDeclarations(code),graph=buildGraph(parseAssignments(parsed.body),parsed.declarations);
  const native=new Map(), memo=new Map();
  const visit=raw=> {
    let n=raw;while(n.kind==='named')n=n.inner;
    if(n.kind==='index')throw new Error('Typed glyph boxes have one output; tuple projection is invalid');
    if(memo.has(n))return memo.get(n);
    let result;
    if(n.kind==='input') {
      const match=/^input(?:\[(\d+)\])?$/.exec(n.name);const index=Number(match?.[1]||1)-1;const input=inputs[index];
      if(!input)throw new Error('Unknown visible input slot');result=[{source:input.id,positions:Array.from({length:input.bits},(_,i)=>i)}];
    } else {
      const tag=n.params.text||n.typeName,d=definitions.get(tag);if(!d)throw new Error(`Untyped visible operation ${tag}`);
      const args=n.args.map(visit);
      if(d.kind==='selection') {
        if(args.length!==1||args[0].length!==1)throw new Error('Selection requires one whole native value');
        const source=args[0][0];if(d.positions.some(i=>!Number.isInteger(i)||i<0||i>=source.positions.length))throw new Error('Invalid visible selection width');
        result=[{source:source.source,positions:d.positions.map(i=>source.positions[i])}];
        if(result[0].positions.length!==d.bits)throw new Error('Selection width differs from annotation');
      } else if(d.kind==='join') {
        if(args.length!==2)throw new Error('Join requires two ordered ports');result=args.flat();
        if(result.reduce((s,e)=>s+e.positions.length,0)!==d.bits)throw new Error('Join width mismatch');
      } else if(d.kind==='native') {
        if(args.length>(d.input_bits?2:0))throw new Error('Native glyph consumes at most two ordered stream fragments');
        if(!Number.isInteger(d.ordinal)||d.ordinal<0)throw new Error('Missing explicit native execution order');
        const node={ordinal:d.ordinal,id:d.id,type:d.type,bits:d.bits,input_bits:d.input_bits,round:d.round,description:clone(d.description),operands:args.flat()};
        if(native.has(d.id)&&JSON.stringify(native.get(d.id))!==JSON.stringify(node))throw new Error('One alias has conflicting visible dependencies');
        native.set(d.id,node);result=[{source:d.id,positions:Array.from({length:d.bits},(_,i)=>i)}];
      } else throw new Error('Unknown typed box definition');
    }
    memo.set(n,result);return result;
  };
  for(const output of graph.targetOrder.filter(t=>t.isOutput))visit(output.node);
  const nodes=[...native.values()].sort((a,b)=>a.ordinal-b.ordinal).map(({ordinal,...node})=>node);
  return validateTypedDiagram({...clone(primitive),inputs:[...inputs].sort((a,b)=>a.index-b.index).map(i=>({id:i.id,bits:i.bits,role:i.role})),nodes});
}
