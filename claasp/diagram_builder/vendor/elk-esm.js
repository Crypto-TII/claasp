// elk.bundled.js is a Browserify UMD bundle with zero ES `export`
// statements -- Node's CJS interop synthesizes a default export from its
// `module.exports = f()` branch, but a real browser `<script
// type="module">` gets an *empty* module namespace from the same static
// import (confirmed directly: the UMD wrapper's browser branch only sets
// `globalThis.ELK` as a side effect, it never assigns anything an ESM
// static importer can see). This file isolates that asymmetry in one
// place so nothing else has to know about it.
let ELK;
if (typeof process !== 'undefined' && process.versions?.node) {
  ({ default: ELK } = await import('./elk.bundled.js'));
} else {
  await import('./elk.bundled.js');
  ELK = globalThis.ELK;
}
export default ELK;
