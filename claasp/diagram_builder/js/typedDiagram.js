// Typed, native-bit DAG exchange. Independent of legacy uniform-word glyphs.
// Semantic records are visible ASCII. Layout annotations never supply operands.
export function validateNativeComponent(n) {
  const d=n.description, integer=Number.isSafeInteger;
  const reject=()=>{throw new Error(`Invalid or unsupported native ${n.type} description/width: ${n.id}`);};
  if(n.type==='word_operation') {
    const op=d[0];
    if(['XOR','AND','OR','MODADD','MODSUB','MODMUL'].includes(op)) {
      const arithmetic=op.startsWith('MOD');
      if(d.length!==(arithmetic?3:2)||!integer(d[1])||d[1]<1||n.input_bits!==d[1]*n.bits)reject();
      if(arithmetic&&d[2]!==null&&(!integer(d[2])||d[2]<=0))reject();
    } else if(['ROTATE','SHIFT'].includes(op)) {
      if(d.length!==2||!integer(d[1])||n.input_bits!==n.bits)reject();
    } else if(['NOT','REVERSE'].includes(op)) {
      if(d.length!==2||d[1]!==0||n.input_bits!==n.bits)reject();
    } else reject();
  } else if(n.type==='constant') {
    if(n.input_bits!==0||d.length!==1||typeof d[0]!=='string'||!/^0x[0-9a-f]+$/i.test(d[0])||BigInt(d[0])>=(1n<<BigInt(n.bits)))reject();
  } else if(['intermediate_output','cipher_output'].includes(n.type)) {
    if(n.input_bits!==n.bits||d.length!==1||typeof d[0]!=='string')reject();
  } else if(n.type==='sbox') {
    if(n.input_bits>20||d.length!==2**n.input_bits||d.some(v=>!integer(v)||v<0||BigInt(v)>=(1n<<BigInt(n.bits))))reject();
  } else if(n.type==='permutation') {
    const [p,w]=d;
    if(d.length!==2||!integer(w)||w<1||n.input_bits!==n.bits||n.bits%w||!Array.isArray(p)||p.length!==n.bits/w||new Set(p).size!==p.length||p.some(v=>!integer(v)||v<0||v>=p.length))reject();
  } else if(n.type==='linear_layer') {
    if(d.length!==n.input_bits||d.some(row=>!Array.isArray(row)||row.length!==n.bits||row.some(v=>v!==0&&v!==1)))reject();
  } else if(n.type==='mix_column') {
    const [matrix,polynomial,w]=d;
    if(d.length!==3||!integer(w)||w<1||w>52||!integer(polynomial)||polynomial<=0||n.input_bits%w||n.bits%w||!Array.isArray(matrix)||matrix.length!==n.bits/w||matrix.some(row=>!Array.isArray(row)||row.length!==n.input_bits/w||row.some(v=>!integer(v)||v<0||v>=2**w)))reject();
  } else reject();
}
export function validateTypedDiagram(ir) {
  if (ir?.schema !== 'claasp-diagrams/1') throw new Error('Unsupported typed diagram schema');
  if (!Number.isInteger(ir.output_bits) || ir.output_bits <= 0) throw new Error('Missing or invalid output width');
  const known = new Map();
  for (const input of ir.inputs) {
    if (known.has(input.id) || !Number.isInteger(input.bits) || input.bits <= 0) throw new Error('Invalid typed input');
    known.set(input.id,input.bits);
  }
  let previousRound = -1;
  for (const n of ir.nodes) {
    if (known.has(n.id) || !Number.isInteger(n.bits) || n.bits <= 0 || !Number.isInteger(n.round) || n.round < 0 || n.round < previousRound || !Number.isInteger(n.input_bits) || n.input_bits < 0 || !Array.isArray(n.description)) throw new Error('Invalid node width, identity or round');
    previousRound = n.round;
    let total = 0;
    for (const edge of n.operands) {
      if (!known.has(edge.source) || !Array.isArray(edge.positions) || edge.positions.some(b => !Number.isInteger(b) || b < 0 || b >= known.get(edge.source))) throw new Error('Invalid ordered bit link');
      total += edge.positions.length;
    }
    if (total !== n.input_bits) throw new Error('Input bit width disagrees with links');
    validateNativeComponent(n);
    known.set(n.id,n.bits);
  }
  const outputs = ir.nodes.filter(n => n.type === 'cipher_output');
  if (outputs.length !== 1 || outputs[0].bits !== ir.output_bits || !Number.isInteger(ir.rounds) || previousRound >= ir.rounds) throw new Error('Invalid declared output or round range');
  return ir;
}
export function parseTypedAscii(text) {
  const lines = text.trimEnd().split(/\r?\n/);
  if (lines.shift() !== '+ CLAASP-DIAGRAMS 1 +' || lines.pop() !== '+ END +') throw new Error('Invalid typed ASCII framing');
  let ir; const inputs = [], nodes = [];
  for (const line of lines) {
    if (line.startsWith('| primitive ') && !ir) ir = JSON.parse(line.slice(12));
    else if (line.startsWith('| input ')) inputs.push(JSON.parse(line.slice(8)));
    else if (line.startsWith('+ node ')) nodes.push(JSON.parse(line.slice(7)));
    else throw new Error('Unknown or duplicate typed ASCII record');
  }
  if (!ir) throw new Error('Missing typed primitive');
  return validateTypedDiagram({...ir,inputs,nodes});
}
export function exportTypedClaaspClass(ir, className='TypedDiagramPrimitive') {
  validateTypedDiagram(ir);
  if (new Set('False None True and as assert async await break class continue def del elif else except finally for from global if import in is lambda nonlocal not or pass raise return try while with yield'.split(' ')).has(className) || !/^[A-Za-z_]\w*$/.test(className)) throw new Error('Invalid class name');
  // Python string literal containing JSON, without interpolating executable data.
  const literal = JSON.stringify(JSON.stringify(ir));
  return `import json\nfrom claasp.cipher import Cipher\nfrom claasp.diagrams import to_cipher\n\nclass ${className}(Cipher):\n    def __init__(self):\n        graph = json.loads(${literal})\n        self.__dict__.update(to_cipher(graph).__dict__)\n`;
}
