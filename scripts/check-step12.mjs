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
    path==='/data.json'?{notes:[]}:{error:'denied'}),
    {status:path==='/api/checks'||path==='/data.json'?200:path.startsWith('/api/restore/')?405:401});
};
let attempts;
try{
  attempts=await runAttackChecks({step:12,publicAppUrl:'https://vault.invalid/'});
  assert.equal(attempts.length,13);assert.equal(calls.length,13);assert.equal(new Set(calls).size,13);
  for(const a of attempts){assert.match(a.observed,/^(not_run|HTTP \d{3}(; jsonReady=(true|false))?)$/);
    assert.equal(calls.includes(a.attackId),a.result!=='not_run');}
  assert.ok(!attempts.some(a=>['s08-own','s11-manifest'].includes(a.attackId)));
  assert.equal(attempts.filter(a=>a.result==='blocked').length,13);
  mode='failed';assert.equal((await runAttackChecks({step:12,publicAppUrl:'https://vault.invalid/'})).filter(a=>a.result==='breached').length,6);
  mode='network';assert.ok((await runAttackChecks({step:12,publicAppUrl:'https://vault.invalid/'})).every(a=>a.result==='not_run'));
}finally{globalThis.fetch=original;}
assert.deepEqual(attempts.map(a=>a.attackId).sort(),['s02-static-copy','s03-unauth-list','s03-fake-token','s04-query-identity','s04-header-identity','s05-direct-table','s08-other-zone','s06-unregistered','s07-compound','s08-unknown-route','s08-all-notes','s08-write-notice','s09-burst-read'].sort());
const receipt={commit:'a'.repeat(40),checkedAt:new Date().toISOString(),attackAttempts:attempts};
const summary=summarizeChecks(receipt);
assert.deepEqual([summary.total,summary.blocked,summary.failed,summary.notRun],[13,13,0,0]);
assert.throws(()=>summarizeChecks({...receipt,attackAttempts:[{result:'blocked',observed:'not_run'}]}));
assert.throws(()=>summarizeChecks({...receipt,checkedAt:'invalid'}));
assert.throws(()=>summarizeChecks({...receipt,attackAttempts:[{attackId:'s11-manifest',result:'blocked',observed:'HTTP 200'}]}));
assert.throws(()=>summarizeChecks({...receipt,attackAttempts:[{attackId:'s08-own',result:'blocked',observed:'HTTP 200; jsonReady=true'}]}));
assert.deepEqual([summary.officialTests.total,summary.officialTests.executed,summary.officialTests.blocked,summary.officialTests.notRun],[41,0,0,41]);
// Render exactly the API counts, including unexpected failures; no guessed totals.
const source=await readFile(new URL('../public/operations.mjs',import.meta.url),'utf8');
const elements=new Map();const el=id=>{if(!elements.has(id))elements.set(id,{append(){},textContent:'',disabled:false});return elements.get(id);};
const context=vm.createContext({document:{getElementById:el,createElement:()=>({})},
  createProtectedFetch:()=>()=>{},fetch:async()=>new Response(JSON.stringify({...summary,blocked:10,failed:3}),{status:200}),console});
await vm.runInContext(source.replace(/^import .*;\r?\n/,'' )+'\nloadReceipt();',context);
assert.match(el('receipt').textContent,/10/);assert.match(el('receipt').textContent,/3/);assert.match(el('receipt').textContent,/0/);assert.match(el('official').textContent,/41/);
assert.match(el('official').textContent,/차단 0/);
context.fetch=async()=>new Response('{}',{status:503});await vm.runInContext('loadReceipt()',context);
assert.equal(el('receipt').textContent.includes('20'),false);
console.log('step12: evidence IDs, GET-only, supported observations, failure/not_run accounting and API-to-screen counts passed');

const receiptPath=new URL('../artifacts/submission.json',import.meta.url);
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
 const allUnrun={...receipt,attackAttempts:receipt.attackAttempts.map(a=>({...a,observed:'not_run',result:'not_run'}))};
 await writeFile(receiptPath,JSON.stringify(allUnrun));
 const reread=(await call()).data;
 assert.deepEqual([reread.total,reread.blocked,reread.failed,reread.notRun],[13,0,0,13]);
 await writeFile(receiptPath,JSON.stringify(receipt));
 assert.deepEqual((await call()).data,summary);
 assert.equal((await call({case:'s08-own'})).data.ready,true);
 assert.equal((await call({},'POST')).code,405);
 assert.equal((await call({owner:'other'})).code,400);
 await writeFile(receiptPath,'{}');assert.equal((await call()).code,503);
 console.log('step12: stored receipt API, invalid receipt, read-only and existing virtual-case boundaries passed');
}finally{if(previous)await writeFile(receiptPath,previous);else await rm(receiptPath,{force:true});}
