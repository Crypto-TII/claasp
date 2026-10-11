import assert from 'node:assert/strict';
import {Grid} from '../js/grid.js';
import {defaultParams} from '../js/blockCatalog.js';
import {renderGrid} from '../js/render.js';
import {decodeGrid} from '../js/decode.js';
for(const [type,params] of [
 ['swap',{words:4,activeWords:'1,2'}],
 ['multiblockpermutation',{words:4,activeInputs:'1,2',activeOutputs:'1,2',permutation:'1,0',borders:'invisible'}]
]){
 const grid=new Grid();grid.placeBlock(0,0,type,{...defaultParams(type),...params});
 const text=renderGrid(grid),parsed=decodeGrid(text),block=parsed.allBlocks()[0];
 assert.equal(renderGrid(parsed),text);
 assert.equal(block.type,type);assert.equal(block.words,4);
 for(const name of type==='swap'?['activeWords']:['activeInputs','activeOutputs','permutation'])assert.equal(block.params[name],params[name]);
}
console.log('Leading inactive swap/permutation lanes recovered from glyphs');
