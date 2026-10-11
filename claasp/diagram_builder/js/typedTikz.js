// Vector rendering of the same glyph grid: no independent DAG placement.
import {BLOCK_TYPES,blockPorts} from './blockCatalog.js';
import {blockRoutes} from './render.js';
import {typedGridToIr} from './typedGlyph.js';
const escape=s=>String(s).replace(/[\\{}_%&#$^~]/g,c=>({'\\':'\\textbackslash{}','{':'\\{','}':'\\}','_':'\\_','%':'\\%','&':'\\&','#':'\\#','$':'\\$','^':'\\textasciicircum{}','~':'\\textasciitilde{}'}[c]));
export function typedGridToTikz(grid,{columnSpacing=2,rowSpacing=1,roundedCorners=0,labels='operation',wireStyle='orthogonal'}={}) {
  typedGridToIr(grid);
  if(![columnSpacing,rowSpacing].every(v=>Number.isFinite(v)&&v>0)||!Number.isFinite(roundedCorners)||roundedCorners<0||!['operation','alias'].includes(labels)||!['orthogonal','smooth'].includes(wireStyle))throw new Error('Invalid TikZ layout options');
  const lines=['\\begin{tikzpicture}[>=stealth,line width=.4pt,font=\\scriptsize]'];
  const point=(b,p)=>{const x=b.col+(p.side==='left'?0:p.side==='right'?b.words:p.wordOffset+.5),y=b.row+(p.side==='top'?0:p.side==='bottom'?b.rowSpan:b.rowSpan/2);return `(${(x*columnSpacing).toFixed(4)},${(-y*rowSpacing).toFixed(4)})`;};
  const center=b=>`(${((b.col+b.words/2)*columnSpacing).toFixed(4)},${(-(b.row+b.rowSpan/2)*rowSpacing).toFixed(4)})`;
  for(const b of grid.allBlocks()) {
    const family=BLOCK_TYPES[b.type].family,wiring=['wiring','double_wire','swap','multiblockpermutation'].includes(family);
    if(wiring) {
      const routes=blockRoutes(b.type,b.params).routes;
      for(const route of routes)for(const source of route.into)for(const dest of route.outs) {
        const a=point(b,source),z=point(b,dest),middle=center(b);
        const path=wireStyle==='smooth'?`${a} to[out=${{top:-90,bottom:90,left:0,right:180}[source.side]},in=${{top:-90,bottom:90,left:0,right:180}[dest.side]}] ${z}`:`${a} -- ${middle} -- ${z}`;
        lines.push(`\\draw[rounded corners=${roundedCorners}pt${routes.length>1?',preaction={draw=white,line width=2pt}':''}] ${path};`);
      }
      if(b.type==='split')lines.push(`\\fill ${center(b)} circle (.7pt);`);
    } else {
      const d=b.params.typed;let label=b.type;
      if(d?.kind==='input')label=`${d.id} (${d.bits} bits, ${d.role})`;
      else if(d?.kind==='native') {
        const description=d.description;
        label=`${d.type==='word_operation'?description[0]:d.type} (${d.bits} bits)`;
        if(d.type==='constant')label=`constant ${description[0]} (${d.bits} bits)`;
        if(d.type==='word_operation'&&['ROTATE','SHIFT'].includes(description[0]))label=`${description[0]}(${description[1]}) (${d.bits} bits)`;
        if(d.type==='word_operation'&&description[0].startsWith('MOD'))label+=` mod ${description[2]===null?`2^${d.bits}`:description[2]}`;
        if(d.type==='mix_column')label+=` poly ${description[1]}, word ${description[2]}`;
        lines.push(`% Native definition ${b.params.text}: ${JSON.stringify(d)}`);
      }
      else if(d?.kind==='selection')label=`select ${d.positions.join(',')}`;
      else if(d?.kind==='join')label=`join (${d.bits} bits)`;
      if(labels==='alias'&&b.type==='typedbox')label=b.params.text;
      const id=`b${b.row}_${b.col}`;
      lines.push(`\\node[draw,fill=white,align=center,font=\\tiny,inner sep=1pt,minimum width=${columnSpacing*.8}cm,minimum height=${rowSpacing*.55}cm,text width=${columnSpacing*.7}cm] (${id}) at ${center(b)} {${escape(label)}${b.params.operand_order?`\\\\order ${escape(b.params.operand_order)}`:''}};`);
      for(let w=0;w<b.words;w++)for(const [side,dir] of Object.entries(blockPorts(b.type,b.params,w,b.words)))if(dir==='in'||dir==='out') {
        const anchor={top:'north',bottom:'south',left:'west',right:'east'}[side],boundary=point(b,{side,wordOffset:w});
        lines.push(`\\draw${dir==='in'?'[->]':''} ${dir==='in'?`${boundary} -- (${id}.${anchor})`:`(${id}.${anchor}) -- ${boundary}`};`);
      }
    }
  }
  return lines.concat('\\end{tikzpicture}').join('\n');
}
