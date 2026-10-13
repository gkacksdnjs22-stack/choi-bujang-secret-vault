import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir,rm} from 'node:fs/promises';
import vm from 'node:vm';
import {runAttackChecks} from '../src/attack-check.mjs';
import {summarizeChecks} from '../src/check-summary.mjs';
const original=globalThis.fetch,calls=[];
let mode='success';
globalThis.fetch=async(url,options)=>{
  assert.equal(options.method,'GET');assert.equal(options.alephEvidence?.requestKey,'read');
  assert.ok(options.alephEvidence.caseId);calls.push(options.alephEvidence.caseId);
  if(mode==='network')throw Error('unavailable');
  const path=new URL(url).pathname;
  return new Response(JSON.stringify(path==='/api/checks'?{source:'fixed_virtual_fixture',ready:mode!=='failed'}:
    path==='/manifest.webmanifest'?{display:'standalone',icons:[{},{}]}:{error:'denied'}),
    {status:path==='/api/checks'||path==='/manifest.webmanifest'?200:path.startsWith('/api/restore/')?405:401});
};
let attempts;
try{
  attempts=await runAttackChecks({step:12,publicAppUrl:'https://vault.invalid/'});
  assert.equal(attempts.length,20);assert.equal(calls.length,15);assert.equal(new Set(calls).size,15);
  for(const a of attempts){assert.match(a.observed,/^(not_run|HTTP \d{3}(; jsonReady=(true|false))?)$/);
    assert.equal(calls.includes(a.attackId),a.result!=='not_run');}
  assert.equal(attempts.filter(a=>a.result==='blocked').length,15);
  mode='failed';assert.equal((await runAttackChecks({step:12,publicAppUrl:'https://vault.invalid/'})).filter(a=>a.result==='breached').length,9);
  mode='network';assert.ok((await runAttackChecks({step:12,publicAppUrl:'https://vault.invalid/'})).every(a=>a.result==='not_run'));
}finally{globalThis.fetch=original;}
const receipt={commit:'a'.repeat(40),checkedAt:new Date().toISOString(),attackAttempts:attempts};
const summary=summarizeChecks(receipt);
assert.deepEqual([summary.total,summary.blocked,summary.failed,summary.notRun],[20,15,0,5]);
assert.throws(()=>summarizeChecks({...receipt,attackAttempts:[{result:'blocked',observed:'not_run'}]}));
assert.throws(()=>summarizeChecks({...receipt,checkedAt:'invalid'}));
// Render exactly the API counts, including unexpected failures; no guessed totals.
const source=await readFile(new URL('../public/operations.mjs',import.meta.url),'utf8');
const elements=new Map();const el=id=>{if(!elements.has(id))elements.set(id,{append(){},textContent:'',disabled:false});return elements.get(id);};
const context=vm.createContext({document:{getElementById:el,createElement:()=>({})},
  createProtectedFetch:()=>()=>{},fetch:async()=>new Response(JSON.stringify({...summary,blocked:12,failed:3}),{status:200}),console});
await vm.runInContext(source.replace(/^import .*;\r?\n/,'' )+'\nloadReceipt();',context);
assert.match(el('receipt').textContent,/12/);assert.match(el('receipt').textContent,/3/);assert.match(el('receipt').textContent,/5/);
context.fetch=async()=>new Response('{}',{status:503});await vm.runInContext('loadReceipt()',context);
assert.equal(el('receipt').textContent.includes('20'),false);
console.log('step12: evidence IDs, GET-only, supported observations, failure/not_run accounting and API-to-screen counts passed');

const receiptPath=new URL('../artifacts/checks.json',import.meta.url);
let previous;try{previous=await readFile(receiptPath);}catch{}
await mkdir(new URL('../artifacts/',import.meta.url),{recursive:true});
const {default:checks}=await import('../api/checks.mjs');
async function call(query={},method='GET'){
 const res={headers:{},setHeader(k,v){this.headers[k]=v;},status(n){this.code=n;return this;},json(d){this.data=d;return this;}};
 await checks({method,query},res);return res;
}
try{
 await writeFile(receiptPath,JSON.stringify(receipt));
 assert.deepEqual((await call()).data,summary);
 assert.equal((await call({case:'s08-own'})).data.ready,true);
 assert.equal((await call({},'POST')).code,405);
 assert.equal((await call({owner:'other'})).code,400);
 await writeFile(receiptPath,'{}');assert.equal((await call()).code,503);
 console.log('step12: stored receipt API, invalid receipt, read-only and existing virtual-case boundaries passed');
}finally{if(previous)await writeFile(receiptPath,previous);else await rm(receiptPath,{force:true});}
