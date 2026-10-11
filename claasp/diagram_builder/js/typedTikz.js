// Vector rendering of the same glyph grid: no independent DAG placement.
import {BLOCK_TYPES,blockPorts} from './blockCatalog.js';
import {blockRoutes} from './render.js';
import {typedGridToIr} from './typedGlyph.js';
const escape=s=>String(s).replace(/[\\{}_%&#$^~]/g,c=>({'\\':'\\textbackslash{}','{':'\\{','}':'\\}','_':'\\_','%':'\\%','&':'\\&','#':'\\#','$':'\\$','^':'\\textasciicircum{}','~':'\\textasciitilde{}'}[c]));
export function typedGridToTikz(grid,options={}) {
  typedGridToIr(grid);
  const {rowsPerPanel=16,columnsPerPanel=6,rowRange,columnRange,pageBreaks=true,maxPanels=256}=options;
  const size=grid.dimensions();
  const range=(value,max)=>{const r=value||[0,max];if(!Array.isArray(r)||r.length!==2||!r.every(Number.isInteger)||r[0]<0||r[1]>max||r[0]>=r[1])throw new Error('Invalid TikZ crop range');return r;};
  const [top,bottom]=range(rowRange,size.rows),[left,right]=range(columnRange,size.cols);
  if(![rowsPerPanel,columnsPerPanel,maxPanels].every(n=>Number.isInteger(n)&&n>0)||typeof pageBreaks!=='boolean')throw new Error('Invalid TikZ pagination options');
  const panelColumns=Math.ceil((right-left)/columnsPerPanel),groups=new Map();
  for(const b of grid.allBlocks()){
    if(b.row>=bottom||b.row+b.rowSpan<=top||b.col>=right||b.col+b.words<=left)continue;
    if(b.row<top||b.row+b.rowSpan>bottom||b.col<left||b.col+b.words>right)throw new Error('TikZ crop/panel boundary intersects a block; choose aligned bounds');
    const key=Math.floor((b.row-top)/rowsPerPanel)*panelColumns+Math.floor((b.col-left)/columnsPerPanel);
    if(!groups.has(key))groups.set(key,[]);groups.get(key).push(b);
  }
  if(groups.size>maxPanels)throw new Error(`TikZ needs ${groups.size} nonempty panels; supply rowRange/columnRange or an explicit larger maxPanels`);
  const panels=[];
  for(let r=top;r<bottom;r+=rowsPerPanel)for(let c=left;c<right;c+=columnsPerPanel){
    const bounds={top:r,bottom:Math.min(bottom,r+rowsPerPanel),left:c,right:Math.min(right,c+columnsPerPanel)};
    const blocks=groups.get(Math.floor((r-top)/rowsPerPanel)*panelColumns+Math.floor((c-left)/columnsPerPanel));
    if(!blocks)continue;
    for(const b of blocks)if(b.row+b.rowSpan>bounds.bottom||b.col+b.words>bounds.right)throw new Error('TikZ crop/panel boundary intersects a block; choose aligned bounds');
    panels.push(renderPanel(grid,{...options,...bounds,size,blocks}));
  }
  return panels.join(pageBreaks?'\n\\clearpage\n':'\n\\par\\medskip\n');
}
function renderPanel(grid,{columnSpacing=2,rowSpacing=1,roundedCorners=0,labels='operation',wireStyle='orthogonal',top,bottom,left,right,size,blocks}) {
  if(![columnSpacing,rowSpacing].every(v=>Number.isFinite(v)&&v>0)||!Number.isFinite(roundedCorners)||roundedCorners<0||!['operation','alias'].includes(labels)||!['orthogonal','smooth'].includes(wireStyle))throw new Error('Invalid TikZ layout options');
  const lines=['\\begin{tikzpicture}[>=stealth,line width=.4pt,font=\\scriptsize]'],legend=[];
  const wrapped=value=>Array.from(String(value)).map((c,i)=>escape(c)+((i+1)%6===0?'\\allowbreak{}':'')).join('');
  lines.push(`% Physical grid crop rows [${top},${bottom}), columns [${left},${right}); matching edge labels denote continuation, not new terminals.`);
  lines.push(`\\node[anchor=south west,align=left,text width=${(right-left)*columnSpacing}cm] at (0,.45) {rows ${top}--${bottom-1}, columns ${left}--${right-1}; continuation edges labelled};`);
  const point=(b,p)=>{const x=b.col-left+(p.side==='left'?0:p.side==='right'?b.words:p.wordOffset+.5),y=b.row-top+(p.side==='top'?0:p.side==='bottom'?b.rowSpan:b.rowSpan/2);return `(${(x*columnSpacing).toFixed(4)},${(-y*rowSpacing).toFixed(4)})`;};
  const center=b=>`(${((b.col-left+b.words/2)*columnSpacing).toFixed(4)},${(-(b.row-top+b.rowSpan/2)*rowSpacing).toFixed(4)})`;
  for(const b of blocks) {
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
      if(label.length>12||label.split(/\s+/).some(word=>word.length>6)){
        const key=`D${b.row}:${b.col}`;legend.push({key,label});
        const kind=d?.kind==='join'?'join':d?.type==='word_operation'?d.description[0]:({intermediate_output:'tap',cipher_output:'final',linear_layer:'linear',mix_column:'mix',permutation:'perm',constant:'const'}[d?.type]||d?.type||'node');
        label=d?.kind==='selection'?`select ${key}`:d?.kind==='input'?`input ${key}`:`${kind} ${key}`;
      }
      lines.push(`\\node[draw,fill=white,align=center,font=\\scriptsize,inner sep=1pt,minimum width=${columnSpacing*.8}cm,minimum height=${rowSpacing*.55}cm,text width=${columnSpacing*.7}cm] (${id}) at ${center(b)} {${wrapped(label)}${b.params.operand_order?`\\\\order ${escape(b.params.operand_order)}`:''}};`);
      for(let w=0;w<b.words;w++)for(const [side,dir] of Object.entries(blockPorts(b.type,b.params,w,b.words)))if(dir==='in'||dir==='out') {
        const anchor={top:'north',bottom:'south',left:'west',right:'east'}[side],boundary=point(b,{side,wordOffset:w});
        lines.push(`\\draw${dir==='in'?'[->]':''} ${dir==='in'?`${boundary} -- (${id}.${anchor})`:`(${id}.${anchor}) -- ${boundary}`};`);
      }
    }
    for(let w=0;w<b.words;w++)for(const [side,dir] of Object.entries(blockPorts(b.type,b.params,w,b.words))){
      if(!['in','out'].includes(dir))continue;
      const key=side==='top'&&b.row===top&&top>0?`r${top}c${b.col+w}`:
        side==='bottom'&&b.row+b.rowSpan===bottom&&bottom<size.rows?`r${bottom}c${b.col+w}`:
        side==='left'&&b.col===left&&left>0?`c${left}r${b.row}`:
        side==='right'&&b.col+b.words===right&&right<size.cols?`c${right}r${b.row}`:null;
      if(key)lines.push(`\\node[font=\\tiny,anchor=${{top:'south',bottom:'north',left:'east',right:'west'}[side]}] at ${point(b,{side,wordOffset:w})} {${key}};`);
    }
  }
  lines.push('\\end{tikzpicture}');
  if(legend.length){lines.push('\\par\\smallskip');for(const {key,label} of legend)lines.push(`{\\raggedright\\scriptsize\\noindent\\textbf{${escape(key)}}: ${wrapped(label)}\\par}\\smallskip`);}
  return lines.join('\n');
}
