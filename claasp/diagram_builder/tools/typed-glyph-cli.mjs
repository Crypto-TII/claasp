import {readFileSync} from 'node:fs';
import {typedIrToGrid,renderTypedGlyph,parseTypedGlyph,typedGridToIr}from'../js/typedGlyph.js';
import {typedGridToTikz}from'../js/typedTikz.js';
const request=JSON.parse(readFileSync(0,'utf8'));
if(request.action==='parse')process.stdout.write(JSON.stringify(typedGridToIr(parseTypedGlyph(request.text))));
else {const grid=typedIrToGrid(request.ir);if(request.action==='ascii')process.stdout.write(renderTypedGlyph(grid));else if(request.action==='tikz')process.stdout.write(typedGridToTikz(grid,request.options));else throw new Error('Unknown glyph action');}
